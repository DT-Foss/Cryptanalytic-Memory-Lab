#include <cadical.hpp>

#include <sys/resource.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace {

constexpr const char *kSchema = "o1-256-cadical-factor-search-result-v1";
constexpr const char *kRequiredVersion = "3.0.0";
constexpr int kKeyBits = 256;
constexpr int kMaximumVariables = 1000000;

struct Arguments {
  std::string cnf_path;
  std::string factors_path;
  int conflict_limit = -1;
  int seed = 0;
};

struct FactorEdge {
  int key_variable = 0;
  int factor_variable = 0;
  int weight = 0;
};

int parse_integer(std::string_view value, const char *field, int minimum,
                  int maximum) {
  if (value.empty())
    throw std::runtime_error(std::string(field) + " is empty");
  const std::string owned(value);
  char *end = nullptr;
  errno = 0;
  const long parsed = std::strtol(owned.c_str(), &end, 10);
  if (errno || !end || *end || parsed < minimum || parsed > maximum)
    throw std::runtime_error(std::string(field) + " is invalid");
  return static_cast<int>(parsed);
}

Arguments parse_arguments(int argc, char **argv) {
  Arguments result;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help") {
      std::cout << "usage: cadical_o1_factor_search --cnf PATH --factors PATH "
                   "--conflict-limit N [--seed N]\n";
      std::exit(0);
    }
    if (index + 1 >= argc)
      throw std::runtime_error("missing value for " + argument);
    const std::string value = argv[++index];
    if (argument == "--cnf")
      result.cnf_path = value;
    else if (argument == "--factors")
      result.factors_path = value;
    else if (argument == "--conflict-limit")
      result.conflict_limit =
          parse_integer(value, "conflict-limit", 1, 1000000000);
    else if (argument == "--seed")
      result.seed = parse_integer(value, "seed", 0, 2000000000);
    else
      throw std::runtime_error("unknown argument " + argument);
  }
  if (result.cnf_path.empty() || result.factors_path.empty() ||
      result.conflict_limit < 1)
    throw std::runtime_error("required arguments are missing");
  return result;
}

std::vector<FactorEdge> read_factors(const std::string &path,
                                     int variable_count) {
  std::ifstream input(path);
  if (!input)
    throw std::runtime_error("cannot open factors file");
  std::vector<FactorEdge> result;
  std::set<std::pair<int, int>> seen;
  int key_variable = 0;
  int factor_variable = 0;
  int weight = 0;
  while (input >> key_variable >> factor_variable >> weight) {
    if (key_variable < 1 || key_variable > kKeyBits || factor_variable < 1 ||
        factor_variable > variable_count || factor_variable == key_variable ||
        !weight || weight < std::numeric_limits<int16_t>::min() ||
        weight > std::numeric_limits<int16_t>::max() ||
        !seen.emplace(key_variable, factor_variable).second)
      throw std::runtime_error("factors contain an invalid row");
    result.push_back({key_variable, factor_variable, weight});
  }
  if (!input.eof() || result.empty() || result.size() > 65535)
    throw std::runtime_error("factors file is empty, malformed, or too large");
  if (!std::is_sorted(result.begin(), result.end(),
                      [](const FactorEdge &left, const FactorEdge &right) {
                        return std::tie(left.key_variable,
                                        left.factor_variable, left.weight) <
                               std::tie(right.key_variable,
                                        right.factor_variable, right.weight);
                      }))
    throw std::runtime_error("factor rows must be canonically sorted");
  return result;
}

class FactorDecisionPropagator final : public CaDiCaL::ExternalPropagator {
public:
  FactorDecisionPropagator(std::vector<FactorEdge> edges, int variable_count)
      : edges_(std::move(edges)), assigned_(variable_count + 1, 0),
        attempted_(variable_count + 1, false), support_(variable_count + 1, 0),
        touched_(variable_count + 1, false), levels_(1) {
    for (const FactorEdge &edge : edges_) {
      touched_[edge.key_variable] = true;
      touched_[edge.factor_variable] = true;
    }
    for (int variable = 1; variable <= variable_count; ++variable)
      if (touched_[variable])
        observed_.push_back(variable);
    observed_variables_ = observed_.size();
  }

  void notify_assignment(const std::vector<int> &literals) override {
    for (const int literal : literals) {
      const int variable = std::abs(literal);
      if (variable < 1 || variable >= static_cast<int>(assigned_.size()) ||
          !touched_[variable])
        throw std::runtime_error("unexpected assignment reached factor propagator");
      const int value = literal > 0 ? 1 : -1;
      if (!assigned_[variable]) {
        assigned_[variable] = value;
        levels_.at(current_level_).push_back(variable);
        ++assigned_count_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        ++assignment_notifications_;
      } else if (assigned_[variable] != value) {
        throw std::runtime_error("factor assignment changed without backtrack");
      }
    }
  }

  void notify_new_decision_level() override {
    current_level_ = levels_.size();
    levels_.emplace_back();
    maximum_level_ = std::max(maximum_level_, current_level_);
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level >= levels_.size())
      throw std::runtime_error("invalid factor backtrack level");
    for (size_t level = new_level + 1; level < levels_.size(); ++level) {
      for (const int variable : levels_[level]) {
        if (!assigned_[variable])
          throw std::runtime_error("factor backtrack found unassigned variable");
        assigned_[variable] = 0;
        --assigned_count_;
      }
    }
    levels_.resize(new_level + 1);
    current_level_ = new_level;
    ++backtracks_;
  }

  bool cb_check_found_model(const std::vector<int> &) override { return true; }

  int cb_decide() override {
    for (const int variable : observed_)
      support_[variable] = 0;
    for (const FactorEdge &edge : edges_) {
      const int left = edge.key_variable;
      const int right = edge.factor_variable;
      if (assigned_[left] && !assigned_[right] && !attempted_[right])
        support_[right] += edge.weight * assigned_[left];
      if (assigned_[right] && !assigned_[left] && !attempted_[left])
        support_[left] += edge.weight * assigned_[right];
    }
    int best_variable = 0;
    int64_t best_magnitude = 0;
    for (const int variable : observed_) {
      const int64_t magnitude = std::abs(support_[variable]);
      if (!assigned_[variable] && !attempted_[variable] &&
          magnitude > best_magnitude) {
        best_variable = variable;
        best_magnitude = magnitude;
      }
    }
    if (!best_variable)
      return 0;
    attempted_[best_variable] = true;
    ++factor_decisions_;
    maximum_support_ = std::max(maximum_support_, best_magnitude);
    return support_[best_variable] > 0 ? best_variable : -best_variable;
  }

  int cb_propagate() override { return 0; }
  int cb_add_reason_clause_lit(int) override { return 0; }

  bool cb_has_external_clause(bool &forgettable) override {
    forgettable = false;
    return false;
  }

  int cb_add_external_clause_lit() override { return 0; }

  int64_t factor_decisions() const { return factor_decisions_; }
  int64_t assignment_notifications() const { return assignment_notifications_; }
  int64_t backtracks() const { return backtracks_; }
  int64_t maximum_assigned() const { return maximum_assigned_; }
  size_t maximum_level() const { return maximum_level_; }
  int64_t maximum_support() const { return maximum_support_; }
  int64_t observed_variables() const { return observed_variables_; }

private:
  std::vector<FactorEdge> edges_;
  std::vector<int8_t> assigned_;
  std::vector<bool> attempted_;
  std::vector<int64_t> support_;
  std::vector<bool> touched_;
  std::vector<int> observed_;
  std::vector<std::vector<int>> levels_;
  size_t current_level_ = 0;
  int64_t assigned_count_ = 0;
  int64_t factor_decisions_ = 0;
  int64_t assignment_notifications_ = 0;
  int64_t backtracks_ = 0;
  int64_t maximum_assigned_ = 0;
  size_t maximum_level_ = 0;
  int64_t maximum_support_ = 0;
  int64_t observed_variables_ = 0;
};

int64_t statistic(CaDiCaL::Solver &solver, const char *name) {
  return solver.get_statistic_value(name);
}

int64_t peak_rss_bytes() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return -1;
#ifdef __APPLE__
  return static_cast<int64_t>(usage.ru_maxrss);
#else
  return static_cast<int64_t>(usage.ru_maxrss) * 1024;
#endif
}

int64_t cpu_microseconds() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return -1;
  return static_cast<int64_t>(usage.ru_utime.tv_sec) * 1000000 +
         usage.ru_utime.tv_usec +
         static_cast<int64_t>(usage.ru_stime.tv_sec) * 1000000 +
         usage.ru_stime.tv_usec;
}

std::string key_hex(CaDiCaL::Solver &solver) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (int byte_index = 0; byte_index < 32; ++byte_index) {
    unsigned value = 0;
    for (int bit = 0; bit < 8; ++bit) {
      const int variable = byte_index * 8 + bit + 1;
      if (solver.val(variable) > 0)
        value |= 1U << bit;
    }
    out << std::setw(2) << value;
  }
  return out.str();
}

} // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");

    CaDiCaL::Solver solver;
    if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
        !solver.set("quiet", 1) || !solver.set("factor", 0) ||
        !solver.set("lucky", 0) || !solver.set("walk", 0) ||
        !solver.set("rephase", 0) || !solver.set("forcephase", 1))
      throw std::runtime_error("CaDiCaL rejected deterministic search options");
    int variables = 0;
    if (const char *error =
            solver.read_dimacs(arguments.cnf_path.c_str(), variables, 2))
      throw std::runtime_error(std::string("DIMACS read failed: ") + error);
    if (variables < kKeyBits || variables > kMaximumVariables)
      throw std::runtime_error("DIMACS variable count differs");

    std::vector<FactorEdge> edges =
        read_factors(arguments.factors_path, variables);
    auto propagator =
        std::make_unique<FactorDecisionPropagator>(edges, variables);
    solver.connect_external_propagator(propagator.get());
    std::vector<bool> observed(variables + 1, false);
    for (const FactorEdge &edge : edges) {
      observed[edge.key_variable] = true;
      observed[edge.factor_variable] = true;
    }
    for (int variable = 1; variable <= variables; ++variable)
      if (observed[variable])
        solver.add_observed_var(variable);
    if (!solver.limit("conflicts", arguments.conflict_limit))
      throw std::runtime_error("CaDiCaL rejected conflict limit");

    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);

    std::cout << "{\"schema\":\"" << kSchema
              << "\",\"cadical_version\":\""
              << CaDiCaL::Solver::version() << "\",\"variables\":"
              << variables << ",\"conflict_limit\":"
              << arguments.conflict_limit << ",\"seed\":" << arguments.seed
              << ",\"status\":" << status << ",\"key_model_hex\":";
    if (status == 10)
      std::cout << '\"' << key_hex(solver) << '\"';
    else
      std::cout << "null";
    std::cout << ",\"stats\":{\"conflicts\":"
              << statistic(solver, "conflicts") << ",\"decisions\":"
              << statistic(solver, "decisions") << ",\"propagations\":"
              << statistic(solver, "propagations")
              << "},\"factor\":{\"edge_count\":" << edges.size()
              << ",\"observed_variables\":"
              << propagator->observed_variables()
              << ",\"requested_decisions\":"
              << propagator->factor_decisions()
              << ",\"assignment_notifications\":"
              << propagator->assignment_notifications()
              << ",\"backtracks\":" << propagator->backtracks()
              << ",\"maximum_assigned_variables\":"
              << propagator->maximum_assigned()
              << ",\"maximum_decision_level\":"
              << propagator->maximum_level()
              << ",\"maximum_abs_support\":"
              << propagator->maximum_support()
              << "},\"resources\":{\"wall_microseconds\":"
              << elapsed.count() << ",\"cpu_microseconds\":"
              << cpu_microseconds() << ",\"peak_rss_bytes\":"
              << peak_rss_bytes() << "}}\n";

    solver.disconnect_external_propagator();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_factor_search: " << error.what() << '\n';
    return 1;
  }
}
