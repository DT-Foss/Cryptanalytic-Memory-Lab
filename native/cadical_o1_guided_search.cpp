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
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr const char *kSchema = "o1-256-cadical-guided-search-result-v1";
constexpr const char *kRequiredVersion = "3.0.0";
constexpr int kKeyBits = 256;

struct Arguments {
  std::string cnf_path;
  std::string hints_path;
  std::string mode;
  int conflict_limit = -1;
  int guided_bits = -1;
  int seed = 0;
};

struct Hint {
  int variable = 0;
  double score = 0.0;

  int literal() const { return score >= 0.0 ? variable : -variable; }
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
      std::cout
          << "usage: cadical_o1_guided_search --cnf PATH --mode "
             "internal|phase|guided --conflict-limit N [--hints PATH] "
             "[--guided-bits 0..256] [--seed N]\n";
      std::exit(0);
    }
    if (index + 1 >= argc)
      throw std::runtime_error("missing value for " + argument);
    const std::string value = argv[++index];
    if (argument == "--cnf")
      result.cnf_path = value;
    else if (argument == "--hints")
      result.hints_path = value;
    else if (argument == "--mode")
      result.mode = value;
    else if (argument == "--conflict-limit")
      result.conflict_limit =
          parse_integer(value, "conflict-limit", 1, 1000000000);
    else if (argument == "--guided-bits")
      result.guided_bits = parse_integer(value, "guided-bits", 0, kKeyBits);
    else if (argument == "--seed")
      result.seed = parse_integer(value, "seed", 0, 2000000000);
    else
      throw std::runtime_error("unknown argument " + argument);
  }
  if (result.cnf_path.empty() || result.conflict_limit < 1 ||
      (result.mode != "internal" && result.mode != "phase" &&
       result.mode != "guided"))
    throw std::runtime_error("required arguments are missing or inconsistent");
  if (result.mode != "internal" && result.hints_path.empty())
    throw std::runtime_error("phase and guided modes require hints");
  if (result.mode == "internal" && !result.hints_path.empty())
    throw std::runtime_error("internal mode does not accept hints");
  if (result.mode == "internal" && result.guided_bits != 0)
    throw std::runtime_error("internal mode requires zero guided bits");
  if (result.mode != "internal" && result.guided_bits < 0)
    throw std::runtime_error("phase and guided modes require guided bits");
  return result;
}

std::vector<Hint> read_hints(const std::string &path) {
  std::ifstream input(path);
  if (!input)
    throw std::runtime_error("cannot open hints file");
  std::vector<Hint> by_index(kKeyBits);
  std::vector<bool> seen(kKeyBits, false);
  int index = -1;
  double score = 0.0;
  int count = 0;
  while (input >> index >> score) {
    if (index < 0 || index >= kKeyBits || seen[index] || !std::isfinite(score))
      throw std::runtime_error("hints contain an invalid row");
    seen[index] = true;
    by_index[index] = {index + 1, score};
    ++count;
  }
  if (!input.eof() || count != kKeyBits)
    throw std::runtime_error("hints must contain exactly 256 rows");
  std::vector<Hint> ordered = by_index;
  std::sort(ordered.begin(), ordered.end(), [](const Hint &left,
                                               const Hint &right) {
    const double left_magnitude = std::abs(left.score);
    const double right_magnitude = std::abs(right.score);
    if (left_magnitude != right_magnitude)
      return left_magnitude > right_magnitude;
    return left.variable < right.variable;
  });
  return ordered;
}

class O1DecisionPropagator final : public CaDiCaL::ExternalPropagator {
public:
  explicit O1DecisionPropagator(std::vector<Hint> hints)
      : hints_(std::move(hints)), assigned_(kKeyBits + 1, 0),
        attempted_(kKeyBits + 1, false), levels_(1) {}

  void notify_assignment(const std::vector<int> &literals) override {
    for (const int literal : literals) {
      const int variable = std::abs(literal);
      if (variable < 1 || variable > kKeyBits)
        throw std::runtime_error("non-key assignment reached O1 propagator");
      const int value = literal > 0 ? 1 : -1;
      if (!assigned_[variable]) {
        assigned_[variable] = value;
        levels_.at(current_level_).push_back(variable);
        ++assigned_count_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        ++assignment_notifications_;
      } else if (assigned_[variable] != value) {
        throw std::runtime_error("key assignment changed without backtrack");
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
      throw std::runtime_error("invalid O1 propagator backtrack level");
    for (size_t level = new_level + 1; level < levels_.size(); ++level) {
      for (const int variable : levels_[level]) {
        if (!assigned_[variable])
          throw std::runtime_error("backtrack encountered unassigned key variable");
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
    for (const Hint &hint : hints_) {
      if (!assigned_[hint.variable] && !attempted_[hint.variable]) {
        attempted_[hint.variable] = true;
        ++guided_decisions_;
        return hint.literal();
      }
    }
    return 0;
  }

  int cb_propagate() override { return 0; }
  int cb_add_reason_clause_lit(int) override { return 0; }

  bool cb_has_external_clause(bool &forgettable) override {
    forgettable = false;
    return false;
  }

  int cb_add_external_clause_lit() override { return 0; }

  int64_t guided_decisions() const { return guided_decisions_; }
  int64_t assignment_notifications() const { return assignment_notifications_; }
  int64_t backtracks() const { return backtracks_; }
  int64_t maximum_assigned() const { return maximum_assigned_; }
  size_t maximum_level() const { return maximum_level_; }

private:
  std::vector<Hint> hints_;
  std::vector<int8_t> assigned_;
  std::vector<bool> attempted_;
  std::vector<std::vector<int>> levels_;
  size_t current_level_ = 0;
  int64_t assigned_count_ = 0;
  int64_t guided_decisions_ = 0;
  int64_t assignment_notifications_ = 0;
  int64_t backtracks_ = 0;
  int64_t maximum_assigned_ = 0;
  size_t maximum_level_ = 0;
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

std::string json_string(const std::string &value) {
  std::ostringstream out;
  out << '"';
  for (const char character : value) {
    if (character == '\\' || character == '"')
      out << '\\';
    if (character == '\n')
      out << "\\n";
    else if (character == '\r')
      out << "\\r";
    else if (character == '\t')
      out << "\\t";
    else
      out << character;
  }
  out << '"';
  return out.str();
}

} // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");
    const std::vector<Hint> hints = arguments.mode == "internal"
                                        ? std::vector<Hint>()
                                        : read_hints(arguments.hints_path);
    const std::vector<Hint> active_hints(
        hints.begin(), hints.begin() + arguments.guided_bits);

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
    if (variables < kKeyBits)
      throw std::runtime_error("DIMACS contains fewer than 256 key variables");

    if (arguments.mode == "phase") {
      for (const Hint &hint : active_hints)
        solver.phase(hint.literal());
    }

    std::unique_ptr<O1DecisionPropagator> propagator;
    if (arguments.mode == "guided") {
      propagator = std::make_unique<O1DecisionPropagator>(active_hints);
      solver.connect_external_propagator(propagator.get());
      for (const Hint &hint : active_hints)
        solver.add_observed_var(hint.variable);
    }

    if (!solver.limit("conflicts", arguments.conflict_limit))
      throw std::runtime_error("CaDiCaL rejected conflict limit");
    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);
    const std::string model_key = status == 10 ? key_hex(solver) : std::string();

    std::ostringstream out;
    out << "{\"schema\":\"" << kSchema << "\",\"mode\":"
        << json_string(arguments.mode) << ",\"cadical_version\":"
        << json_string(CaDiCaL::Solver::version())
        << ",\"variables\":" << variables
        << ",\"conflict_limit\":" << arguments.conflict_limit
        << ",\"guided_bits\":" << arguments.guided_bits
        << ",\"seed\":" << arguments.seed << ",\"status\":" << status
        << ",\"key_model_hex\":";
    if (status == 10)
      out << json_string(model_key);
    else
      out << "null";
    out << ",\"stats\":{\"conflicts\":" << statistic(solver, "conflicts")
        << ",\"decisions\":" << statistic(solver, "decisions")
        << ",\"propagations\":" << statistic(solver, "propagations") << "}"
        << ",\"guided\":{\"requested_decisions\":"
        << (propagator ? propagator->guided_decisions() : 0)
        << ",\"assignment_notifications\":"
        << (propagator ? propagator->assignment_notifications() : 0)
        << ",\"backtracks\":"
        << (propagator ? propagator->backtracks() : 0)
        << ",\"maximum_assigned_key_bits\":"
        << (propagator ? propagator->maximum_assigned() : 0)
        << ",\"maximum_decision_level\":"
        << (propagator ? propagator->maximum_level() : 0) << "}"
        << ",\"resources\":{\"wall_microseconds\":" << elapsed.count()
        << ",\"cpu_microseconds\":" << cpu_microseconds()
        << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
    std::cout << out.str();

    if (propagator)
      solver.disconnect_external_propagator();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_guided_search: " << error.what() << '\n';
    return 1;
  }
}
