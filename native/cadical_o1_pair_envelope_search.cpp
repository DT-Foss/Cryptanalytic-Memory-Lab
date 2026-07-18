#include <cadical.hpp>

#include <sys/resource.h>

#include <algorithm>
#include <array>
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

constexpr const char *kSchema =
    "o1-256-cadical-pair-envelope-search-result-v1";
constexpr const char *kPotentialSchema = "O1CRIT-POT-V1";
constexpr const char *kRequiredVersion = "3.0.0";
constexpr const char *kDecisionRule = "pairwise_factorwise_max_envelope";
constexpr const char *kDecisionScope = "explicit_ordered_key_pairs";
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

struct DecisionVariables {
  std::vector<int> variables;
  std::string source_sha256;
};

uint32_t rotate_right(uint32_t value, unsigned count) {
  return (value >> count) | (value << (32U - count));
}

std::string sha256(std::string_view input) {
  static constexpr std::array<uint32_t, 64> constants = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
      0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
      0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
      0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
      0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
      0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
      0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
      0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
      0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
      0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
      0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
  };
  std::vector<uint8_t> message(input.begin(), input.end());
  if (message.size() >
      (std::numeric_limits<uint64_t>::max() - 9U) / 8U)
    throw std::runtime_error("decision-variable file is too large");
  const uint64_t bit_length = static_cast<uint64_t>(message.size()) * 8U;
  message.push_back(0x80U);
  while (message.size() % 64U != 56U)
    message.push_back(0U);
  for (int shift = 56; shift >= 0; shift -= 8)
    message.push_back(static_cast<uint8_t>(bit_length >> shift));

  std::array<uint32_t, 8> state = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  for (size_t offset = 0; offset < message.size(); offset += 64U) {
    std::array<uint32_t, 64> words{};
    for (size_t index = 0; index < 16U; ++index) {
      const size_t position = offset + 4U * index;
      words[index] = static_cast<uint32_t>(message[position]) << 24U |
                     static_cast<uint32_t>(message[position + 1U]) << 16U |
                     static_cast<uint32_t>(message[position + 2U]) << 8U |
                     static_cast<uint32_t>(message[position + 3U]);
    }
    for (size_t index = 16U; index < words.size(); ++index) {
      const uint32_t x = words[index - 15U];
      const uint32_t y = words[index - 2U];
      const uint32_t sigma0 =
          rotate_right(x, 7U) ^ rotate_right(x, 18U) ^ (x >> 3U);
      const uint32_t sigma1 =
          rotate_right(y, 17U) ^ rotate_right(y, 19U) ^ (y >> 10U);
      words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
    }
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];
    for (size_t index = 0; index < words.size(); ++index) {
      const uint32_t sum1 =
          rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
      const uint32_t choose = (e & f) ^ (~e & g);
      const uint32_t temporary1 =
          h + sum1 + choose + constants[index] + words[index];
      const uint32_t sum0 =
          rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
      const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temporary2 = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temporary1;
      d = c;
      c = b;
      b = a;
      a = temporary1 + temporary2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  }
  std::ostringstream result;
  result << std::hex << std::setfill('0');
  for (const uint32_t word : state)
    result << std::setw(8) << word;
  return result.str();
}

bool is_sha256(const std::string &value) {
  return value.size() == 64U &&
         std::all_of(value.begin(), value.end(), [](const char character) {
           return (character >= '0' && character <= '9') ||
                  (character >= 'a' && character <= 'f');
         });
}

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
          << "usage: cadical_o1_pair_envelope_search --cnf PATH "
             "--potential PATH --decision-variables PATH "
             "--conflict-limit N [--seed N]\n";
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
      result.decision_variables_path.empty() || result.conflict_limit < 1)
    throw std::runtime_error("required arguments are missing");
  return result;
}

DecisionVariables read_decision_variables(const std::string &path,
                                           int variable_count) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("cannot open decision-variable file");
  std::ostringstream buffer;
  buffer << input.rdbuf();
  if (!input.eof() && input.fail())
    throw std::runtime_error("cannot read decision-variable file");
  const std::string payload = buffer.str();
  std::istringstream parser(payload);
  DecisionVariables result;
  result.source_sha256 = sha256(payload);
  std::array<bool, kKeyBits + 1> seen{};
  int variable = 0;
  while (parser >> variable) {
    if (variable < 1 || variable > kKeyBits || variable > variable_count ||
        seen[variable])
      throw std::runtime_error("decision variables differ");
    seen[variable] = true;
    result.variables.push_back(variable);
  }
  if (!parser.eof() || result.variables.empty() ||
      result.variables.size() % 2U != 0U)
    throw std::runtime_error(
        "decision variables must be a nonempty even unique ordered list");
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
      schema != kPotentialSchema || !factor_count || factor_count > 65535U ||
      !std::isfinite(result.offset) || !is_sha256(result.source_sha256))
    throw std::runtime_error("potential header differs");
  std::vector<int> previous;
  for (size_t index = 0; index < factor_count; ++index) {
    int width = 0;
    if (!(input >> width) || width < 1 || width > kMaximumFactorVariables)
      throw std::runtime_error("potential factor width differs");
    PotentialFactor factor;
    factor.variables.resize(static_cast<size_t>(width));
    for (int &variable : factor.variables)
      if (!(input >> variable) || variable < 1 || variable > variable_count)
        throw std::runtime_error("potential variable differs");
    if (!std::is_sorted(factor.variables.begin(), factor.variables.end()) ||
        std::adjacent_find(factor.variables.begin(), factor.variables.end()) !=
            factor.variables.end() ||
        (!previous.empty() && !(previous < factor.variables)))
      throw std::runtime_error("potential variable order differs");
    previous = factor.variables;
    factor.energies.resize(size_t{1} << static_cast<unsigned>(width));
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

struct PairGroup {
  int first = 0;
  int second = 0;
  std::vector<size_t> incident_factors;
};

struct QueuedLiteral {
  int literal = 0;
  bool requested = false;
};

class PairEnvelopeDecisionPropagator final
    : public CaDiCaL::ExternalPropagator {
public:
  PairEnvelopeDecisionPropagator(PotentialField field, int variable_count,
                                 const std::vector<int> &decision_variables)
      : field_(std::move(field)), assigned_(variable_count + 1, 0),
        decision_counts_(variable_count + 1, 0),
        touched_(variable_count + 1, false), levels_(1),
        eligible_count_(decision_variables.size()) {
    for (const PotentialFactor &factor : field_.factors)
      for (const int variable : factor.variables)
        touched_[variable] = true;
    for (int variable = 1; variable <= variable_count; ++variable)
      if (touched_[variable])
        observed_.push_back(variable);
    for (size_t index = 0; index < decision_variables.size(); index += 2U) {
      PairGroup group;
      group.first = decision_variables[index];
      group.second = decision_variables[index + 1U];
      for (size_t factor_index = 0; factor_index < field_.factors.size();
           ++factor_index) {
        const std::vector<int> &variables =
            field_.factors[factor_index].variables;
        if (std::binary_search(variables.begin(), variables.end(), group.first) ||
            std::binary_search(variables.begin(), variables.end(), group.second))
          group.incident_factors.push_back(factor_index);
      }
      groups_.push_back(std::move(group));
    }
  }

  void notify_assignment(const std::vector<int> &literals) override {
    for (const int literal : literals) {
      const int variable = std::abs(literal);
      if (variable < 1 || variable >= static_cast<int>(assigned_.size()) ||
          !touched_[variable])
        throw std::runtime_error("unexpected pair-envelope assignment");
      const int value = literal > 0 ? 1 : -1;
      if (!assigned_[variable]) {
        assigned_[variable] = static_cast<int8_t>(value);
        levels_.at(current_level_).push_back(variable);
        ++assigned_count_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        ++assignment_notifications_;
      } else if (assigned_[variable] != value) {
        throw std::runtime_error(
            "pair-envelope assignment changed without backtrack");
      }
      update_queue_for_assignment(literal);
    }
  }

  void notify_new_decision_level() override {
    current_level_ = levels_.size();
    levels_.emplace_back();
    maximum_level_ = std::max(maximum_level_, current_level_);
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level >= levels_.size())
      throw std::runtime_error("invalid pair-envelope backtrack level");
    for (size_t level = new_level + 1U; level < levels_.size(); ++level)
      for (const int variable : levels_[level]) {
        if (!assigned_[variable])
          throw std::runtime_error(
              "pair-envelope backtrack found unassigned variable");
        assigned_[variable] = 0;
        --assigned_count_;
      }
    levels_.resize(new_level + 1U);
    current_level_ = new_level;
    queue_.clear();
    ++backtracks_;
  }

  bool cb_check_found_model(const std::vector<int> &) override { return true; }

  int cb_decide() override {
    if (const int queued = request_queued_literal())
      return queued;

    std::vector<double> base_maxima(field_.factors.size());
    long double base_score = static_cast<long double>(field_.offset);
    for (size_t index = 0; index < field_.factors.size(); ++index) {
      base_maxima[index] = factor_envelope(index, nullptr, 0U);
      base_score += static_cast<long double>(base_maxima[index]);
    }
    if (!std::isfinite(base_score))
      throw std::runtime_error("global pair-envelope score is not finite");

    const PairGroup *selected_group = nullptr;
    unsigned selected_mask = 0U;
    long double selected_gap = 0.0L;
    for (const PairGroup &group : groups_) {
      if (assigned_[group.first] && assigned_[group.second])
        continue;
      long double nonincident_score = base_score;
      for (const size_t factor_index : group.incident_factors)
        nonincident_score -= static_cast<long double>(base_maxima[factor_index]);

      struct PatternScore {
        unsigned mask;
        long double score;
      };
      std::vector<PatternScore> patterns;
      for (unsigned mask = 0U; mask < 4U; ++mask) {
        const int first_spin = mask & 1U ? 1 : -1;
        const int second_spin = mask & 2U ? 1 : -1;
        if ((assigned_[group.first] &&
             assigned_[group.first] != first_spin) ||
            (assigned_[group.second] &&
             assigned_[group.second] != second_spin))
          continue;
        long double score = nonincident_score;
        for (const size_t factor_index : group.incident_factors)
          score += static_cast<long double>(
              factor_envelope(factor_index, &group, mask));
        if (!std::isfinite(score))
          throw std::runtime_error("pair-pattern envelope is not finite");
        patterns.push_back({mask, score});
      }
      if (patterns.size() < 2U)
        throw std::runtime_error("pair has fewer than two feasible patterns");
      std::sort(patterns.begin(), patterns.end(),
                [](const PatternScore &left, const PatternScore &right) {
                  if (left.score != right.score)
                    return left.score > right.score;
                  return left.mask < right.mask;
                });
      const long double gap = patterns[0].score - patterns[1].score;
      if (!std::isfinite(gap) || gap < 0.0L)
        throw std::runtime_error("pair-envelope score gap is invalid");
      if (gap > selected_gap) {
        selected_group = &group;
        selected_mask = patterns[0].mask;
        selected_gap = gap;
      }
    }
    if (!selected_group) {
      ++zero_gap_fallbacks_;
      return 0;
    }
    maximum_gap_ = std::max(maximum_gap_, selected_gap);
    enqueue_if_unassigned(selected_group->first,
                          selected_mask & 1U ? 1 : -1);
    enqueue_if_unassigned(selected_group->second,
                          selected_mask & 2U ? 1 : -1);
    if (queue_.empty())
      throw std::runtime_error("selected pair has no unassigned literal");
    return request_queued_literal();
  }

  int cb_propagate() override { return 0; }
  int cb_add_reason_clause_lit(int) override { return 0; }
  bool cb_has_external_clause(bool &forgettable) override {
    forgettable = false;
    return false;
  }
  int cb_add_external_clause_lit() override { return 0; }

  size_t factor_count() const { return field_.factors.size(); }
  size_t pair_count() const { return groups_.size(); }
  size_t observed_variables() const { return observed_.size(); }
  size_t eligible_variables() const { return eligible_count_; }
  const std::vector<int> &observed() const { return observed_; }
  int64_t requested_decisions() const { return requested_decisions_; }
  int64_t repeated_decisions() const { return repeated_decisions_; }
  int64_t queued_decisions() const { return queued_decisions_; }
  int64_t same_sign_queue_skips() const { return same_sign_queue_skips_; }
  int64_t opposite_sign_queue_invalidations() const {
    return opposite_sign_queue_invalidations_;
  }
  int64_t zero_gap_fallbacks() const { return zero_gap_fallbacks_; }
  int64_t assignment_notifications() const { return assignment_notifications_; }
  int64_t backtracks() const { return backtracks_; }
  int64_t maximum_assigned() const { return maximum_assigned_; }
  size_t maximum_level() const { return maximum_level_; }
  long double maximum_gap() const { return maximum_gap_; }
  int64_t envelope_evaluations() const { return envelope_evaluations_; }

private:
  double factor_envelope(size_t factor_index, const PairGroup *group,
                         unsigned pair_mask) {
    const PotentialFactor &factor = field_.factors.at(factor_index);
    double best = -std::numeric_limits<double>::infinity();
    for (size_t row = 0; row < factor.energies.size(); ++row) {
      bool consistent = true;
      for (size_t local = 0; local < factor.variables.size(); ++local) {
        const int variable = factor.variables[local];
        int spin = assigned_[variable];
        if (group && variable == group->first)
          spin = pair_mask & 1U ? 1 : -1;
        else if (group && variable == group->second)
          spin = pair_mask & 2U ? 1 : -1;
        if (spin && ((row >> local) & 1U) !=
                        static_cast<unsigned>(spin > 0)) {
          consistent = false;
          break;
        }
      }
      if (consistent)
        best = std::max(best, factor.energies[row]);
    }
    ++envelope_evaluations_;
    if (!std::isfinite(best))
      throw std::runtime_error("factor envelope has no consistent row");
    return best;
  }

  void enqueue_if_unassigned(int variable, int spin) {
    if (assigned_[variable])
      return;
    queue_.push_back({spin > 0 ? variable : -variable, false});
    ++queued_decisions_;
  }

  int request_queued_literal() {
    while (!queue_.empty()) {
      QueuedLiteral &entry = queue_.front();
      const int variable = std::abs(entry.literal);
      if (assigned_[variable]) {
        if (assigned_[variable] != (entry.literal > 0 ? 1 : -1)) {
          queue_.clear();
          ++opposite_sign_queue_invalidations_;
          return 0;
        }
        if (!entry.requested)
          ++same_sign_queue_skips_;
        queue_.erase(queue_.begin());
        continue;
      }
      if (entry.requested)
        return 0;
      entry.requested = true;
      if (decision_counts_[variable]++)
        ++repeated_decisions_;
      ++requested_decisions_;
      return entry.literal;
    }
    return 0;
  }

  void update_queue_for_assignment(int literal) {
    const int variable = std::abs(literal);
    for (size_t index = 0; index < queue_.size(); ++index) {
      if (std::abs(queue_[index].literal) != variable)
        continue;
      if (queue_[index].literal != literal) {
        queue_.clear();
        ++opposite_sign_queue_invalidations_;
        return;
      }
      if (!queue_[index].requested)
        ++same_sign_queue_skips_;
      queue_.erase(queue_.begin() + static_cast<std::ptrdiff_t>(index));
      return;
    }
  }

  PotentialField field_;
  std::vector<int8_t> assigned_;
  std::vector<int64_t> decision_counts_;
  std::vector<bool> touched_;
  std::vector<int> observed_;
  std::vector<PairGroup> groups_;
  std::vector<QueuedLiteral> queue_;
  std::vector<std::vector<int>> levels_;
  size_t current_level_ = 0;
  int64_t assigned_count_ = 0;
  int64_t requested_decisions_ = 0;
  int64_t repeated_decisions_ = 0;
  int64_t queued_decisions_ = 0;
  int64_t same_sign_queue_skips_ = 0;
  int64_t opposite_sign_queue_invalidations_ = 0;
  int64_t zero_gap_fallbacks_ = 0;
  int64_t assignment_notifications_ = 0;
  int64_t backtracks_ = 0;
  int64_t maximum_assigned_ = 0;
  size_t maximum_level_ = 0;
  long double maximum_gap_ = 0.0L;
  int64_t envelope_evaluations_ = 0;
  size_t eligible_count_ = 0;
};

int64_t statistic(CaDiCaL::Solver &solver, const char *name) {
  return solver.get_statistic_value(name);
}

int64_t peak_rss_bytes() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return 0;
#ifdef __APPLE__
  return static_cast<int64_t>(usage.ru_maxrss);
#else
  return static_cast<int64_t>(usage.ru_maxrss) * 1024;
#endif
}

int64_t cpu_microseconds() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return 0;
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
    DecisionVariables decisions = read_decision_variables(
        arguments.decision_variables_path, variables);
    const std::string source_sha256 = field.source_sha256;
    const std::string decision_sha256 = decisions.source_sha256;
    const double offset = field.offset;
    auto propagator = std::make_unique<PairEnvelopeDecisionPropagator>(
        std::move(field), variables, decisions.variables);
    solver.connect_external_propagator(propagator.get());
    for (const int variable : propagator->observed())
      solver.add_observed_var(variable);
    if (!solver.limit("conflicts", arguments.conflict_limit))
      throw std::runtime_error("CaDiCaL rejected conflict limit");
    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);

    std::cout << std::setprecision(std::numeric_limits<long double>::max_digits10)
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
              << "},\"envelope\":{\"factor_count\":"
              << propagator->factor_count() << ",\"pair_count\":"
              << propagator->pair_count() << ",\"group_width\":2"
              << ",\"decision_rule\":\"" << kDecisionRule
              << "\",\"decision_scope\":\"" << kDecisionScope
              << "\",\"source_sha256\":\""
              << source_sha256 << "\",\"decision_variables_sha256\":\""
              << decision_sha256 << "\",\"offset\":" << offset
              << ",\"observed_variables\":"
              << propagator->observed_variables()
              << ",\"eligible_decision_variables\":"
              << propagator->eligible_variables()
              << ",\"requested_decisions\":"
              << propagator->requested_decisions()
              << ",\"repeated_decisions\":"
              << propagator->repeated_decisions()
              << ",\"queued_decisions\":" << propagator->queued_decisions()
              << ",\"same_sign_queue_skips\":"
              << propagator->same_sign_queue_skips()
              << ",\"opposite_sign_queue_invalidations\":"
              << propagator->opposite_sign_queue_invalidations()
              << ",\"zero_gap_fallbacks\":"
              << propagator->zero_gap_fallbacks()
              << ",\"assignment_notifications\":"
              << propagator->assignment_notifications()
              << ",\"backtracks\":" << propagator->backtracks()
              << ",\"maximum_assigned_variables\":"
              << propagator->maximum_assigned()
              << ",\"maximum_decision_level\":"
              << propagator->maximum_level()
              << ",\"maximum_score_gap\":" << propagator->maximum_gap()
              << ",\"envelope_evaluations\":"
              << propagator->envelope_evaluations()
              << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
              << ",\"cpu_microseconds\":" << cpu_microseconds()
              << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
    solver.disconnect_external_propagator();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_pair_envelope_search: " << error.what() << '\n';
    return 1;
  }
}
