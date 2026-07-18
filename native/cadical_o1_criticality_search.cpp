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
#include <vector>

namespace {

constexpr const char *kSchema = "o1-256-cadical-criticality-search-result-v1";
constexpr const char *kPotentialSchema = "O1CRIT-POT-V1";
constexpr const char *kRequiredVersion = "3.0.0";
constexpr int kKeyBits = 256;
constexpr int kMaximumVariables = 1000000;
constexpr int kMaximumFactorVariables = 8;

struct Arguments {
  std::string cnf_path;
  std::string potential_path;
  std::string decision_variables_path;
  int conflict_limit = -1;
  int seed = 0;
};

struct PotentialFactor {
  std::vector<int> variables;
  std::vector<double> energies;
};

struct PotentialField {
  double offset = 0.0;
  std::string source_sha256;
  std::vector<PotentialFactor> factors;
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
      std::cout << "usage: cadical_o1_criticality_search --cnf PATH "
                   "--potential PATH --conflict-limit N [--seed N] "
                   "[--decision-variables PATH]\n";
      std::exit(0);
    }
    if (index + 1 >= argc)
      throw std::runtime_error("missing value for " + argument);
    const std::string value = argv[++index];
    if (argument == "--cnf")
      result.cnf_path = value;
    else if (argument == "--potential")
      result.potential_path = value;
    else if (argument == "--decision-variables")
      result.decision_variables_path = value;
    else if (argument == "--conflict-limit")
      result.conflict_limit =
          parse_integer(value, "conflict-limit", 1, 1000000000);
    else if (argument == "--seed")
      result.seed = parse_integer(value, "seed", 0, 2000000000);
    else
      throw std::runtime_error("unknown argument " + argument);
  }
  if (result.cnf_path.empty() || result.potential_path.empty() ||
      result.conflict_limit < 1)
    throw std::runtime_error("required arguments are missing");
  return result;
}

std::vector<int> read_decision_variables(const std::string &path,
                                         int variable_count) {
  if (path.empty())
    return {};
  std::ifstream input(path);
  if (!input)
    throw std::runtime_error("cannot open decision-variable file");
  std::vector<int> result;
  int variable = 0;
  while (input >> variable) {
    if (variable < 1 || variable > kKeyBits || variable > variable_count ||
        (!result.empty() && variable <= result.back()))
      throw std::runtime_error("decision variables differ");
    result.push_back(variable);
  }
  if (!input.eof() || result.empty())
    throw std::runtime_error("decision variables are empty or malformed");
  return result;
}

PotentialField read_potential(const std::string &path, int variable_count) {
  std::ifstream input(path);
  if (!input)
    throw std::runtime_error("cannot open potential file");
  std::string schema;
  size_t factor_count = 0;
  PotentialField result;
  if (!(input >> schema >> factor_count >> result.offset >> result.source_sha256) ||
      schema != kPotentialSchema || !factor_count || factor_count > 65535 ||
      !std::isfinite(result.offset) || result.source_sha256.size() != 64)
    throw std::runtime_error("potential header differs");
  std::vector<int> previous;
  for (size_t index = 0; index < factor_count; ++index) {
    int width = 0;
    if (!(input >> width) || width < 1 || width > kMaximumFactorVariables)
      throw std::runtime_error("potential factor width differs");
    PotentialFactor factor;
    factor.variables.resize(width);
    for (int &variable : factor.variables)
      if (!(input >> variable) || variable < 1 || variable > variable_count)
        throw std::runtime_error("potential variable differs");
    if (!std::is_sorted(factor.variables.begin(), factor.variables.end()) ||
        std::adjacent_find(factor.variables.begin(), factor.variables.end()) !=
            factor.variables.end() ||
        (!previous.empty() && !(previous < factor.variables)))
      throw std::runtime_error("potential variable order differs");
    previous = factor.variables;
    factor.energies.resize(size_t{1} << width);
    for (double &energy : factor.energies)
      if (!(input >> energy) || !std::isfinite(energy))
        throw std::runtime_error("potential energy differs");
    result.factors.push_back(std::move(factor));
  }
  std::string trailing;
  if (input >> trailing)
    throw std::runtime_error("potential contains trailing fields");
  return result;
}

class CriticalityDecisionPropagator final
    : public CaDiCaL::ExternalPropagator {
public:
  CriticalityDecisionPropagator(PotentialField field, int variable_count,
                                const std::vector<int> &decision_variables)
      : field_(std::move(field)), assigned_(variable_count + 1, 0),
        support_(variable_count + 1, 0.0),
        decision_counts_(variable_count + 1, 0),
        touched_(variable_count + 1, false),
        eligible_(variable_count + 1, false), levels_(1),
        explicit_scope_(!decision_variables.empty()) {
    for (const PotentialFactor &factor : field_.factors)
      for (const int variable : factor.variables)
        touched_[variable] = true;
    for (int variable = 1; variable <= variable_count; ++variable)
      if (touched_[variable])
        observed_.push_back(variable);
    if (decision_variables.empty()) {
      for (const int variable : observed_) {
        eligible_[variable] = true;
        eligible_variables_.push_back(variable);
      }
    } else {
      for (const int variable : decision_variables) {
        if (!touched_[variable])
          throw std::runtime_error("decision variable is absent from potential");
        eligible_[variable] = true;
        eligible_variables_.push_back(variable);
      }
    }
  }

  void notify_assignment(const std::vector<int> &literals) override {
    for (const int literal : literals) {
      const int variable = std::abs(literal);
      if (variable < 1 || variable >= static_cast<int>(assigned_.size()) ||
          !touched_[variable])
        throw std::runtime_error("unexpected criticality assignment");
      const int value = literal > 0 ? 1 : -1;
      if (!assigned_[variable]) {
        assigned_[variable] = value;
        levels_.at(current_level_).push_back(variable);
        ++assigned_count_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        ++assignment_notifications_;
      } else if (assigned_[variable] != value) {
        throw std::runtime_error("criticality assignment changed without backtrack");
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
      throw std::runtime_error("invalid criticality backtrack level");
    for (size_t level = new_level + 1; level < levels_.size(); ++level)
      for (const int variable : levels_[level]) {
        if (!assigned_[variable])
          throw std::runtime_error("criticality backtrack found unassigned variable");
        assigned_[variable] = 0;
        --assigned_count_;
      }
    levels_.resize(new_level + 1);
    current_level_ = new_level;
    ++backtracks_;
  }

  bool cb_check_found_model(const std::vector<int> &) override { return true; }

  int cb_decide() override {
    for (const int variable : observed_)
      support_[variable] = 0.0;
    for (const PotentialFactor &factor : field_.factors) {
      for (size_t target = 0; target < factor.variables.size(); ++target) {
        const int target_variable = factor.variables[target];
        if (assigned_[target_variable] || !eligible_[target_variable])
          continue;
        long double negative_sum = 0.0;
        long double positive_sum = 0.0;
        int64_t negative_count = 0;
        int64_t positive_count = 0;
        for (size_t mask = 0; mask < factor.energies.size(); ++mask) {
          bool consistent = true;
          for (size_t local = 0; local < factor.variables.size(); ++local) {
            if (local == target)
              continue;
            const int spin = assigned_[factor.variables[local]];
            if (spin && ((mask >> local) & 1U) != static_cast<unsigned>(spin > 0)) {
              consistent = false;
              break;
            }
          }
          if (!consistent)
            continue;
          if ((mask >> target) & 1U) {
            positive_sum += factor.energies[mask];
            ++positive_count;
          } else {
            negative_sum += factor.energies[mask];
            ++negative_count;
          }
        }
        if (!negative_count || !positive_count)
          throw std::runtime_error("criticality conditional table is empty");
        support_[target_variable] +=
            static_cast<double>(positive_sum / positive_count -
                                negative_sum / negative_count);
        ++conditional_factor_evaluations_;
      }
    }
    int best_variable = 0;
    double best_magnitude = 0.0;
    for (const int variable : eligible_variables_) {
      const double magnitude = std::abs(support_[variable]);
      if (!assigned_[variable] && magnitude > best_magnitude) {
        best_variable = variable;
        best_magnitude = magnitude;
      }
    }
    if (!best_variable || !std::isfinite(best_magnitude) || best_magnitude == 0.0)
      return 0;
    if (decision_counts_[best_variable]++)
      ++repeated_decisions_;
    ++factor_decisions_;
    maximum_support_ = std::max(maximum_support_, best_magnitude);
    return support_[best_variable] > 0.0 ? best_variable : -best_variable;
  }

  int cb_propagate() override { return 0; }
  int cb_add_reason_clause_lit(int) override { return 0; }
  bool cb_has_external_clause(bool &forgettable) override {
    forgettable = false;
    return false;
  }
  int cb_add_external_clause_lit() override { return 0; }

  int64_t factor_decisions() const { return factor_decisions_; }
  int64_t repeated_decisions() const { return repeated_decisions_; }
  int64_t assignment_notifications() const { return assignment_notifications_; }
  int64_t backtracks() const { return backtracks_; }
  int64_t maximum_assigned() const { return maximum_assigned_; }
  size_t maximum_level() const { return maximum_level_; }
  double maximum_support() const { return maximum_support_; }
  int64_t conditional_factor_evaluations() const {
    return conditional_factor_evaluations_;
  }
  size_t observed_variables() const { return observed_.size(); }
  size_t eligible_decision_variables() const {
    return eligible_variables_.size();
  }
  const char *decision_scope() const {
    return explicit_scope_ ? "explicit" : "all_observed";
  }
  const std::vector<int> &observed() const { return observed_; }

private:
  PotentialField field_;
  std::vector<int8_t> assigned_;
  std::vector<double> support_;
  std::vector<int64_t> decision_counts_;
  std::vector<bool> touched_;
  std::vector<bool> eligible_;
  std::vector<int> observed_;
  std::vector<int> eligible_variables_;
  std::vector<std::vector<int>> levels_;
  size_t current_level_ = 0;
  int64_t assigned_count_ = 0;
  int64_t factor_decisions_ = 0;
  int64_t repeated_decisions_ = 0;
  int64_t assignment_notifications_ = 0;
  int64_t backtracks_ = 0;
  int64_t maximum_assigned_ = 0;
  size_t maximum_level_ = 0;
  double maximum_support_ = 0.0;
  int64_t conditional_factor_evaluations_ = 0;
  bool explicit_scope_ = false;
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
    PotentialField field = read_potential(arguments.potential_path, variables);
    const std::vector<int> decision_variables = read_decision_variables(
        arguments.decision_variables_path, variables);
    const size_t factor_count = field.factors.size();
    const std::string source_sha256 = field.source_sha256;
    const double offset = field.offset;
    auto propagator = std::make_unique<CriticalityDecisionPropagator>(
        std::move(field), variables, decision_variables);
    solver.connect_external_propagator(propagator.get());
    for (const int variable : propagator->observed())
      solver.add_observed_var(variable);
    if (!solver.limit("conflicts", arguments.conflict_limit))
      throw std::runtime_error("CaDiCaL rejected conflict limit");
    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);

    std::cout << std::setprecision(17)
              << "{\"schema\":\"" << kSchema
              << "\",\"cadical_version\":\"" << CaDiCaL::Solver::version()
              << "\",\"variables\":" << variables
              << ",\"conflict_limit\":" << arguments.conflict_limit
              << ",\"seed\":" << arguments.seed << ",\"status\":" << status
              << ",\"key_model_hex\":";
    if (status == 10)
      std::cout << '\"' << key_hex(solver) << '\"';
    else
      std::cout << "null";
    std::cout << ",\"stats\":{\"conflicts\":" << statistic(solver, "conflicts")
              << ",\"decisions\":" << statistic(solver, "decisions")
              << ",\"propagations\":" << statistic(solver, "propagations")
              << "},\"potential\":{\"factor_count\":" << factor_count
              << ",\"source_sha256\":\"" << source_sha256
              << "\",\"offset\":" << offset
              << ",\"observed_variables\":"
              << propagator->observed_variables()
              << ",\"decision_scope\":\"" << propagator->decision_scope()
              << "\",\"eligible_decision_variables\":"
              << propagator->eligible_decision_variables()
              << ",\"requested_decisions\":" << propagator->factor_decisions()
              << ",\"repeated_decisions\":" << propagator->repeated_decisions()
              << ",\"assignment_notifications\":"
              << propagator->assignment_notifications()
              << ",\"backtracks\":" << propagator->backtracks()
              << ",\"maximum_assigned_variables\":"
              << propagator->maximum_assigned()
              << ",\"maximum_decision_level\":" << propagator->maximum_level()
              << ",\"maximum_abs_support\":" << propagator->maximum_support()
              << ",\"conditional_factor_evaluations\":"
              << propagator->conditional_factor_evaluations()
              << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
              << ",\"cpu_microseconds\":" << cpu_microseconds()
              << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
    solver.disconnect_external_propagator();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_criticality_search: " << error.what() << '\n';
    return 1;
  }
}
