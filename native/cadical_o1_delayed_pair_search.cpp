#include <cadical.hpp>

#include <sys/resource.h>

#include <algorithm>
#include <array>
#include <cerrno>
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
    "o1-256-cadical-delayed-pair-credit-search-result-v1";
constexpr const char *kPotentialSchema = "O1CRIT-POT-V1";
constexpr const char *kRequiredVersion = "3.0.0";
constexpr const char *kDecisionRule =
    "delayed_trail_owner_pair_group_credit";
constexpr const char *kColdDecisionRule =
    "pairwise_factorwise_max_envelope";
constexpr const char *kDecisionScope = "explicit_ordered_key_pairs";
constexpr const char *kGroupStateEncoding =
    "i16le-credit,u16le-visits,u16le-conflict-hits,"
    "u16le-propagation-units,u16le-backtrack-hits";
constexpr const char *kOwnerStateEncoding =
    "u32le-first-owner-level,u32le-second-owner-level";
constexpr const char *kStateEncoding =
    "group-block:i16le-credit,u16le-visits,u16le-conflict-hits,"
    "u16le-propagation-units,u16le-backtrack-hits;"
    "owner-block:u32le-first-owner-level,u32le-second-owner-level";
constexpr const char *kCounterSemantics =
    "visits=closed-action-tickets;"
    "conflict-hits=conflict-bearing-owner-undos;"
    "propagation-units=reserved-zero;backtrack-hits=all-owner-undos";
constexpr const char *kUpdateFormula =
    "on-backtrack:c=I(conflicts>previous-backtrack-conflicts);"
    "for-owner-level>new-level:w=32>>min(current-level-owner-level,4);"
    "credit=sat_i16(credit-(1+c)*sum(w));clear-undone-owners";
constexpr const char *kSelectionFormula =
    "cold:max-gap-then-group-order;"
    "delayed:max-gap-plus-credit-over-1024-then-gap-then-group-order";
constexpr int kKeyBits = 256;
constexpr int kRequiredGroups = 63;
constexpr int kRequiredDecisionVariables = 2 * kRequiredGroups;
constexpr int kMaximumVariables = 1000000;
constexpr int kMaximumFactorVariables = 8;
constexpr int kCreditMinimum = -32768;
constexpr int kCreditMaximum = 32767;
constexpr uint32_t kCounterMaximum = 65535U;
constexpr int kGroupStateBytesPerGroup = 10;
constexpr int kOwnerStateBytesPerGroup = 8;
constexpr int kStateBytesPerGroup =
    kGroupStateBytesPerGroup + kOwnerStateBytesPerGroup;
constexpr int kBoundedGroupStateBytes =
    kRequiredGroups * kGroupStateBytesPerGroup;
constexpr int kBoundedOwnerStateBytes =
    kRequiredGroups * kOwnerStateBytesPerGroup;
constexpr int kBoundedStateBytes =
    kBoundedGroupStateBytes + kBoundedOwnerStateBytes;

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
    throw std::runtime_error("input is too large for SHA-256");
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

std::string read_binary_file(const std::string &path, const char *field) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error(std::string("cannot open ") + field);
  std::ostringstream buffer;
  buffer << input.rdbuf();
  if (!input.eof() && input.fail())
    throw std::runtime_error(std::string("cannot read ") + field);
  const std::string payload = buffer.str();
  if (payload.empty())
    throw std::runtime_error(std::string(field) + " is empty");
  return payload;
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
          << "usage: cadical_o1_delayed_pair_search --cnf PATH "
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

DecisionVariables parse_decision_variables(const std::string &payload,
                                            int variable_count) {
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
  if (!parser.eof() ||
      result.variables.size() != static_cast<size_t>(kRequiredDecisionVariables))
    throw std::runtime_error("exactly 63 ordered key pairs are required");
  return result;
}

PotentialField parse_potential(const std::string &payload,
                               int variable_count) {
  std::istringstream input(payload);
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
  size_t group_index = 0;
  unsigned member = 0;
  bool requested = false;
};

struct GroupState {
  int16_t credit = 0;
  uint16_t visits = 0;
  uint16_t conflict_hits = 0;
  uint16_t propagation_units = 0;
  uint16_t backtrack_hits = 0;
};

static_assert(sizeof(GroupState) == kGroupStateBytesPerGroup,
              "delayed pair group state must occupy exactly ten bytes");

struct OwnerState {
  std::array<uint32_t, 2> levels{};
};

static_assert(sizeof(OwnerState) == kOwnerStateBytesPerGroup,
              "delayed pair owner state must occupy exactly eight bytes");

struct SolverSnapshot {
  int64_t conflicts = 0;
  int64_t decisions = 0;
  int64_t propagations = 0;
};

struct ActionTicket {
  bool open = false;
  size_t group_index = 0;
  SolverSnapshot baseline;
  bool first_assigned = false;
  bool second_assigned = false;
};

struct PendingDecision {
  bool open = false;
  size_t group_index = 0;
  unsigned member = 0;
  int variable = 0;
};

enum class CloseReason { Advance, Backtrack, Invalidation, SolveEnd };

class DelayedPairCreditPropagator final : public CaDiCaL::ExternalPropagator {
public:
  DelayedPairCreditPropagator(CaDiCaL::Solver *solver, PotentialField field,
                             int variable_count,
                             const std::vector<int> &decision_variables)
      : solver_(solver), field_(std::move(field)),
        assigned_(variable_count + 1, 0),
        decision_counts_(variable_count + 1, 0),
        touched_(variable_count + 1, false),
        owner_group_(variable_count + 1, -1),
        owner_member_(variable_count + 1, -1), levels_(1),
        eligible_count_(decision_variables.size()) {
    if (!solver_ ||
        decision_variables.size() !=
            static_cast<size_t>(kRequiredDecisionVariables))
      throw std::runtime_error("delayed pair-credit constructor differs");
    for (const PotentialFactor &factor : field_.factors)
      for (const int variable : factor.variables)
        touched_[variable] = true;
    for (int variable = 1; variable <= variable_count; ++variable)
      if (touched_[variable])
        observed_.push_back(variable);
    for (const int variable : decision_variables)
      if (!touched_[variable])
        throw std::runtime_error(
            "decision variable is absent from delayed pair potential");
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
      states_.emplace_back();
      owners_.emplace_back();
      const size_t group_index = groups_.size() - 1U;
      owner_group_.at(static_cast<size_t>(decision_variables[index])) =
          static_cast<int>(group_index);
      owner_member_.at(static_cast<size_t>(decision_variables[index])) = 0;
      owner_group_.at(static_cast<size_t>(decision_variables[index + 1U])) =
          static_cast<int>(group_index);
      owner_member_.at(static_cast<size_t>(decision_variables[index + 1U])) = 1;
    }
    previous_backtrack_conflicts_ = snapshot().conflicts;
  }

  void notify_assignment(const std::vector<int> &literals) override {
    if (pending_.open)
      throw std::runtime_error(
          "delayed pair pending decision was not bound before assignment");
    for (const int literal : literals) {
      const int variable = std::abs(literal);
      if (variable < 1 || variable >= static_cast<int>(assigned_.size()) ||
          !touched_[variable])
        throw std::runtime_error("unexpected delayed pair assignment");
      const int value = literal > 0 ? 1 : -1;
      if (!assigned_[variable]) {
        const int group_index = owner_group_.at(static_cast<size_t>(variable));
        const int member = owner_member_.at(static_cast<size_t>(variable));
        if (group_index >= 0) {
          if (member < 0 || member > 1)
            throw std::runtime_error("delayed pair owner map differs");
          const uint32_t owner_level =
              owners_.at(static_cast<size_t>(group_index))
                  .levels.at(static_cast<size_t>(member));
          if (owner_level) {
            if (owner_level != current_level_)
              throw std::runtime_error(
                  "delayed pair owner assignment level differs");
            ++owner_assignment_hits_;
          }
        }
        assigned_[variable] = static_cast<int8_t>(value);
        levels_.at(current_level_).push_back(variable);
        ++assigned_count_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        ++assignment_notifications_;
      } else if (assigned_[variable] != value) {
        throw std::runtime_error(
            "delayed pair assignment changed without backtrack");
      }
      update_queue_for_assignment(literal);
      record_ticket_assignment(variable);
    }
  }

  void notify_new_decision_level() override {
    current_level_ = levels_.size();
    levels_.emplace_back();
    maximum_level_ = std::max(maximum_level_, current_level_);
    if (!pending_.open)
      return;
    if (current_level_ > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("delayed pair owner level exceeds u32");
    if (pending_.group_index >= owners_.size() || pending_.member > 1U ||
        pending_.variable < 1)
      throw std::runtime_error("delayed pair pending decision differs");
    OwnerState &owner = owners_.at(pending_.group_index);
    uint32_t &owner_level = owner.levels.at(pending_.member);
    if (owner_level)
      throw std::runtime_error("delayed pair owner rebound while live");
    const PairGroup &group = groups_.at(pending_.group_index);
    const int expected = pending_.member ? group.second : group.first;
    if (expected != pending_.variable || assigned_.at(pending_.variable))
      throw std::runtime_error("delayed pair pending owner target differs");
    owner_level = static_cast<uint32_t>(current_level_);
    ++pending_bound_;
    if (pending_.member)
      ++second_owner_bindings_;
    else
      ++first_owner_bindings_;
    ++live_owners_;
    maximum_live_owners_ = std::max(maximum_live_owners_, live_owners_);
    pending_ = PendingDecision{};
  }

  void notify_backtrack(size_t new_level) override {
    if (pending_.open)
      throw std::runtime_error(
          "delayed pair pending decision survived to backtrack");
    if (new_level >= levels_.size())
      throw std::runtime_error("invalid delayed pair backtrack level");
    if (current_level_ + 1U != levels_.size() || new_level > current_level_)
      throw std::runtime_error("delayed pair current level differs");
    close_ticket(CloseReason::Backtrack);
    apply_delayed_backtrack_credit(new_level);
    for (size_t level = new_level + 1U; level < levels_.size(); ++level)
      for (const int variable : levels_[level]) {
        if (!assigned_[variable])
          throw std::runtime_error(
              "delayed pair backtrack found unassigned variable");
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
    if (pending_.open)
      throw std::runtime_error(
          "delayed pair decision requested before pending level bind");
    if (const int queued = request_queued_literal())
      return queued;
    if (!queue_.empty())
      return 0;
    close_ticket(CloseReason::Advance);

    std::vector<double> base_maxima(field_.factors.size());
    long double base_score = static_cast<long double>(field_.offset);
    for (size_t index = 0; index < field_.factors.size(); ++index) {
      base_maxima[index] = factor_envelope(index, nullptr, 0U);
      base_score += static_cast<long double>(base_maxima[index]);
    }
    if (!std::isfinite(base_score))
      throw std::runtime_error("global delayed pair-envelope score is not finite");

    const bool cold = tickets_closed_ == 0;
    bool selected = false;
    size_t selected_index = 0;
    unsigned selected_mask = 0U;
    long double selected_gap = 0.0L;
    long double selected_priority = 0.0L;
    for (size_t group_index = 0; group_index < groups_.size(); ++group_index) {
      const PairGroup &group = groups_[group_index];
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
        if ((assigned_[group.first] && assigned_[group.first] != first_spin) ||
            (assigned_[group.second] && assigned_[group.second] != second_spin))
          continue;
        long double score = nonincident_score;
        for (const size_t factor_index : group.incident_factors)
          score += static_cast<long double>(
              factor_envelope(factor_index, &group, mask));
        if (!std::isfinite(score))
          throw std::runtime_error("delayed pair-pattern envelope is not finite");
        patterns.push_back({mask, score});
      }
      if (patterns.size() < 2U)
        throw std::runtime_error("delayed pair has fewer than two patterns");
      std::sort(patterns.begin(), patterns.end(),
                [](const PatternScore &left, const PatternScore &right) {
                  if (left.score != right.score)
                    return left.score > right.score;
                  return left.mask < right.mask;
                });
      const long double gap = patterns[0].score - patterns[1].score;
      if (!std::isfinite(gap) || gap < 0.0L)
        throw std::runtime_error("delayed pair score gap is invalid");
      if (gap == 0.0L)
        continue;
      const long double priority =
          cold ? gap
               : gap + static_cast<long double>(states_[group_index].credit) /
                           1024.0L;
      bool better = false;
      if (cold)
        better = gap > selected_gap;
      else
        better = !selected || priority > selected_priority ||
                 (priority == selected_priority && gap > selected_gap);
      if (better) {
        selected = true;
        selected_index = group_index;
        selected_mask = patterns[0].mask;
        selected_gap = gap;
        selected_priority = priority;
      }
    }
    if (!selected) {
      ++zero_gap_fallbacks_;
      return 0;
    }
    maximum_gap_ = std::max(maximum_gap_, selected_gap);
    if (!cold && (!has_modulated_priority_ ||
                  selected_priority > maximum_modulated_priority_)) {
      maximum_modulated_priority_ = selected_priority;
      has_modulated_priority_ = true;
    }
    if (cold)
      ++cold_group_selections_;
    else
      ++credit_modulated_group_selections_;
    if (tickets_opened_ == 0) {
      first_group_index_ = static_cast<int>(selected_index);
      first_pattern_mask_ = static_cast<int>(selected_mask);
    }
    selection_trace_ += std::to_string(selected_index) + " " +
                        std::to_string(selected_mask) + "\n";
    open_ticket(selected_index);
    const PairGroup &selected_group = groups_[selected_index];
    enqueue_if_unassigned(selected_group.first,
                          selected_mask & 1U ? 1 : -1, selected_index, 0U);
    enqueue_if_unassigned(selected_group.second,
                          selected_mask & 2U ? 1 : -1, selected_index, 1U);
    if (queue_.empty())
      throw std::runtime_error("selected delayed pair has no unassigned literal");
    return request_queued_literal();
  }

  int cb_propagate() override { return 0; }
  int cb_add_reason_clause_lit(int) override { return 0; }
  bool cb_has_external_clause(bool &forgettable) override {
    forgettable = false;
    return false;
  }
  int cb_add_external_clause_lit() override { return 0; }

  void finalize() {
    if (pending_.open)
      throw std::runtime_error(
          "delayed pair solve ended with unbound pending decision");
    close_ticket(CloseReason::SolveEnd);
    validate_ledger();
  }

  size_t factor_count() const { return field_.factors.size(); }
  size_t pair_count() const { return groups_.size(); }
  size_t observed_variables() const { return observed_.size(); }
  size_t eligible_variables() const { return eligible_count_; }
  const std::vector<int> &observed() const { return observed_; }

  std::string group_state_bytes() const {
    std::string result;
    result.reserve(states_.size() *
                   static_cast<size_t>(kGroupStateBytesPerGroup));
    for (const GroupState &state : states_) {
      append_u16(result, static_cast<uint16_t>(state.credit));
      append_u16(result, static_cast<uint16_t>(state.visits));
      append_u16(result, static_cast<uint16_t>(state.conflict_hits));
      append_u16(result, static_cast<uint16_t>(state.propagation_units));
      append_u16(result, static_cast<uint16_t>(state.backtrack_hits));
    }
    return result;
  }

  std::string owner_state_bytes() const {
    std::string result;
    result.reserve(owners_.size() *
                   static_cast<size_t>(kOwnerStateBytesPerGroup));
    for (const OwnerState &owner : owners_) {
      append_u32(result, owner.levels[0]);
      append_u32(result, owner.levels[1]);
    }
    return result;
  }

  void write_delayed_json(std::ostream &out) const {
    out << "\"queue\":{\"requested_decisions\":" << requested_decisions_
        << ",\"repeated_decisions\":" << repeated_decisions_
        << ",\"queued_decisions\":" << queued_decisions_
        << ",\"same_sign_queue_skips\":" << same_sign_queue_skips_
        << ",\"opposite_sign_queue_invalidations\":"
        << opposite_sign_queue_invalidations_
        << ",\"assignment_notifications\":" << assignment_notifications_
        << ",\"backtracks\":" << backtracks_
        << ",\"maximum_assigned_variables\":" << maximum_assigned_
        << ",\"maximum_decision_level\":" << maximum_level_ << "},";
    out << "\"selection\":{\"cold_group_selections\":"
        << cold_group_selections_
        << ",\"credit_modulated_group_selections\":"
        << credit_modulated_group_selections_
        << ",\"zero_gap_fallbacks\":" << zero_gap_fallbacks_
        << ",\"envelope_evaluations\":" << envelope_evaluations_
        << ",\"first_group_index\":";
    if (first_group_index_ < 0)
      out << "null";
    else
      out << first_group_index_;
    out << ",\"first_pattern_mask\":";
    if (first_pattern_mask_ < 0)
      out << "null";
    else
      out << first_pattern_mask_;
    out << ",\"maximum_score_gap\":" << maximum_gap_
        << ",\"maximum_modulated_priority\":"
        << (has_modulated_priority_ ? maximum_modulated_priority_ : 0.0L)
        << ",\"trace_sha256\":\"" << sha256(selection_trace_) << "\"},";
    out << "\"tickets\":{\"opened\":" << tickets_opened_
        << ",\"closed\":" << tickets_closed_
        << ",\"closed_on_advance\":" << tickets_closed_on_advance_
        << ",\"closed_on_backtrack\":" << tickets_closed_on_backtrack_
        << ",\"closed_on_invalidation\":"
        << tickets_closed_on_invalidation_
        << ",\"closed_on_solve_end\":" << tickets_closed_on_solve_end_
        << ",\"assignment_hits\":" << ticket_assignment_hits_
        << ",\"maximum_open\":" << maximum_open_tickets_
        << ",\"current_open\":" << (ticket_.open ? 1 : 0) << "},";
    out << "\"pending\":{\"marked\":" << pending_marked_
        << ",\"bound\":" << pending_bound_
        << ",\"first_owner_bindings\":" << first_owner_bindings_
        << ",\"second_owner_bindings\":" << second_owner_bindings_
        << ",\"owner_assignment_hits\":" << owner_assignment_hits_
        << ",\"maximum_open\":" << maximum_open_pending_
        << ",\"current_open\":" << (pending_.open ? 1 : 0) << "},";
    out << "\"backtrack_credit\":{\"callbacks\":"
        << delayed_backtrack_callbacks_
        << ",\"conflict_callbacks\":" << conflict_backtrack_callbacks_
        << ",\"nonconflict_callbacks\":"
        << nonconflict_backtrack_callbacks_
        << ",\"eligible_undo_groups\":" << eligible_undo_groups_
        << ",\"eligible_undo_members\":" << eligible_undo_members_
        << ",\"conflict_undo_members\":" << conflict_undo_members_
        << ",\"nonconflict_undo_members\":" << nonconflict_undo_members_
        << ",\"weighted_undo_units\":" << weighted_undo_units_
        << ",\"conflict_weighted_undo_units\":"
        << conflict_weighted_undo_units_
        << ",\"nonconflict_weighted_undo_units\":"
        << nonconflict_weighted_undo_units_
        << ",\"conflict_penalty_units\":" << conflict_penalty_units_
        << ",\"nonconflict_penalty_units\":"
        << nonconflict_penalty_units_
        << ",\"credit_updates\":" << delayed_credit_updates_
        << ",\"assignment_credit_units\":0,\"propagation_credit_units\":0},";
    out << "\"solver_counter_deltas\":{\"conflicts\":"
        << delta_conflicts_total_ << ",\"decisions\":"
        << delta_decisions_total_ << ",\"propagations\":"
        << delta_propagations_total_ << "},";
    const std::string group_encoded = group_state_bytes();
    const std::string owner_encoded = owner_state_bytes();
    const std::string encoded = group_encoded + owner_encoded;
    out << "\"state\":{\"encoding\":\"" << kStateEncoding
        << "\",\"group_encoding\":\"" << kGroupStateEncoding
        << "\",\"owner_encoding\":\"" << kOwnerStateEncoding
        << "\",\"bytes_per_group\":" << kStateBytesPerGroup
        << ",\"group_bytes_per_group\":" << kGroupStateBytesPerGroup
        << ",\"owner_bytes_per_group\":" << kOwnerStateBytesPerGroup
        << ",\"bounded_group_state_bytes\":" << group_encoded.size()
        << ",\"bounded_owner_state_bytes\":" << owner_encoded.size()
        << ",\"bounded_state_bytes\":" << encoded.size()
        << ",\"sha256\":\"" << sha256(encoded)
        << "\",\"group_sha256\":\"" << sha256(group_encoded)
        << "\",\"owner_sha256\":\"" << sha256(owner_encoded)
        << "\",\"credit_min\":" << kCreditMinimum
        << ",\"credit_max\":" << kCreditMaximum
        << ",\"counter_max\":" << kCounterMaximum
        << ",\"owner_level_max\":"
        << std::numeric_limits<uint32_t>::max()
        << ",\"counter_semantics\":\"" << kCounterSemantics
        << "\",\"live_owners\":" << live_owners_
        << ",\"maximum_live_owners\":" << maximum_live_owners_
        << ",\"saturated_credit_updates\":" << saturated_credit_updates_
        << ",\"saturated_counter_updates\":" << saturated_counter_updates_
        << ",\"groups\":[";
    for (size_t index = 0; index < states_.size(); ++index) {
      if (index)
        out << ',';
      const GroupState &state = states_[index];
      out << "{\"index\":" << index << ",\"first_variable\":"
          << groups_[index].first << ",\"second_variable\":"
          << groups_[index].second << ",\"credit\":" << state.credit
          << ",\"visits\":" << state.visits << ",\"conflict_hits\":"
          << state.conflict_hits << ",\"propagation_units\":"
          << state.propagation_units << ",\"backtrack_hits\":"
          << state.backtrack_hits << ",\"first_owner_level\":"
          << owners_[index].levels[0] << ",\"second_owner_level\":"
          << owners_[index].levels[1] << '}';
    }
    out << "]}";
  }

private:
  static void append_u16(std::string &output, uint16_t value) {
    output.push_back(static_cast<char>(value & 0xffU));
    output.push_back(static_cast<char>(value >> 8U));
  }

  static void append_u32(std::string &output, uint32_t value) {
    output.push_back(static_cast<char>(value & 0xffU));
    output.push_back(static_cast<char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<char>(value >> 24U));
  }

  void validate_ledger() const {
    if (groups_.size() != static_cast<size_t>(kRequiredGroups) ||
        states_.size() != groups_.size() || owners_.size() != groups_.size() ||
        pending_marked_ != pending_bound_ ||
        pending_bound_ != first_owner_bindings_ + second_owner_bindings_ ||
        owner_assignment_hits_ > pending_bound_ ||
        maximum_open_pending_ != static_cast<int64_t>(pending_marked_ > 0) ||
        pending_.open || delayed_backtrack_callbacks_ != backtracks_ ||
        delayed_backtrack_callbacks_ !=
            conflict_backtrack_callbacks_ + nonconflict_backtrack_callbacks_ ||
        eligible_undo_members_ !=
            conflict_undo_members_ + nonconflict_undo_members_ ||
        weighted_undo_units_ !=
            conflict_weighted_undo_units_ + nonconflict_weighted_undo_units_ ||
        conflict_penalty_units_ != 2 * conflict_weighted_undo_units_ ||
        nonconflict_penalty_units_ != nonconflict_weighted_undo_units_ ||
        delayed_credit_updates_ != eligible_undo_groups_ ||
        pending_bound_ != eligible_undo_members_ + live_owners_ ||
        group_state_bytes().size() !=
            static_cast<size_t>(kBoundedGroupStateBytes) ||
        owner_state_bytes().size() !=
            static_cast<size_t>(kBoundedOwnerStateBytes) ||
        group_state_bytes().size() + owner_state_bytes().size() !=
            static_cast<size_t>(kBoundedStateBytes))
      throw std::runtime_error("delayed pair final telemetry ledger differs");
    int64_t observed_live_owners = 0;
    for (size_t group_index = 0; group_index < owners_.size(); ++group_index) {
      const GroupState &state = states_[group_index];
      if (state.credit > 0 || state.propagation_units ||
          state.conflict_hits > state.backtrack_hits)
        throw std::runtime_error("delayed pair group-state invariant differs");
      const PairGroup &group = groups_[group_index];
      for (unsigned member = 0; member < 2U; ++member) {
        const uint32_t owner_level = owners_[group_index].levels[member];
        if (!owner_level)
          continue;
        const int variable = member ? group.second : group.first;
        const bool assignment_reported =
            assigned_.at(static_cast<size_t>(variable));
        if (owner_level > current_level_ || owner_level >= levels_.size() ||
            (assignment_reported &&
             std::find(levels_.at(owner_level).begin(),
                       levels_.at(owner_level).end(),
                       variable) == levels_.at(owner_level).end()))
          throw std::runtime_error("delayed pair live-owner invariant differs");
        ++observed_live_owners;
      }
    }
    if (observed_live_owners != live_owners_ ||
        maximum_live_owners_ < live_owners_)
      throw std::runtime_error("delayed pair owner-count invariant differs");
  }

  SolverSnapshot snapshot() const {
    SolverSnapshot result;
    result.conflicts = solver_->get_statistic_value("conflicts");
    result.decisions = solver_->get_statistic_value("decisions");
    result.propagations = solver_->get_statistic_value("propagations");
    if (result.conflicts < 0 || result.decisions < 0 ||
        result.propagations < 0)
      throw std::runtime_error("delayed pair solver counter differs");
    return result;
  }

  static int64_t checked_delta(int64_t current, int64_t baseline) {
    if (current < baseline)
      throw std::runtime_error("delayed pair solver counter moved backwards");
    return current - baseline;
  }

  static void checked_accumulate(int64_t &target, int64_t value) {
    if (value < 0 || target > std::numeric_limits<int64_t>::max() - value)
      throw std::runtime_error("delayed pair counter total overflow");
    target += value;
  }

  uint16_t saturating_counter_add(uint16_t current, int64_t delta) {
    if (delta < 0)
      throw std::runtime_error("delayed pair negative counter delta");
    if (delta > static_cast<int64_t>(kCounterMaximum - current)) {
      ++saturated_counter_updates_;
      return static_cast<uint16_t>(kCounterMaximum);
    }
    return static_cast<uint16_t>(current + static_cast<uint16_t>(delta));
  }

  int16_t saturating_credit_add(int16_t current, int64_t delta) {
    const int64_t value = static_cast<int64_t>(current) + delta;
    if (value > kCreditMaximum) {
      ++saturated_credit_updates_;
      return static_cast<int16_t>(kCreditMaximum);
    }
    if (value < kCreditMinimum) {
      ++saturated_credit_updates_;
      return static_cast<int16_t>(kCreditMinimum);
    }
    return static_cast<int16_t>(value);
  }

  void open_ticket(size_t group_index) {
    if (ticket_.open || group_index >= groups_.size())
      throw std::runtime_error("delayed pair action-ticket invariant differs");
    ticket_.open = true;
    ticket_.group_index = group_index;
    ticket_.baseline = snapshot();
    ticket_.first_assigned = false;
    ticket_.second_assigned = false;
    ++tickets_opened_;
    maximum_open_tickets_ = std::max<int64_t>(maximum_open_tickets_, 1);
  }

  void close_ticket(CloseReason reason) {
    if (!ticket_.open)
      return;
    const SolverSnapshot current = snapshot();
    const int64_t delta_conflicts =
        checked_delta(current.conflicts, ticket_.baseline.conflicts);
    const int64_t delta_decisions =
        checked_delta(current.decisions, ticket_.baseline.decisions);
    const int64_t delta_propagations =
        checked_delta(current.propagations, ticket_.baseline.propagations);
    checked_accumulate(delta_conflicts_total_, delta_conflicts);
    checked_accumulate(delta_decisions_total_, delta_decisions);
    checked_accumulate(delta_propagations_total_, delta_propagations);
    const int assignments = static_cast<int>(ticket_.first_assigned) +
                            static_cast<int>(ticket_.second_assigned);
    checked_accumulate(ticket_assignment_hits_, assignments);
    GroupState &state = states_.at(ticket_.group_index);
    state.visits = saturating_counter_add(state.visits, 1);
    ++tickets_closed_;
    if (reason == CloseReason::Advance)
      ++tickets_closed_on_advance_;
    else if (reason == CloseReason::Backtrack)
      ++tickets_closed_on_backtrack_;
    else if (reason == CloseReason::Invalidation)
      ++tickets_closed_on_invalidation_;
    else
      ++tickets_closed_on_solve_end_;
    ticket_ = ActionTicket{};
  }

  static int delayed_owner_weight(size_t current_level, uint32_t owner_level) {
    if (!owner_level || owner_level > current_level)
      throw std::runtime_error("delayed pair owner depth differs");
    const size_t depth = current_level - static_cast<size_t>(owner_level);
    const unsigned shift = static_cast<unsigned>(std::min<size_t>(depth, 4U));
    return 32 >> shift;
  }

  void apply_delayed_backtrack_credit(size_t new_level) {
    const int64_t current_conflicts = snapshot().conflicts;
    if (current_conflicts < previous_backtrack_conflicts_)
      throw std::runtime_error(
          "delayed pair conflict baseline moved backwards");
    const bool conflict = current_conflicts > previous_backtrack_conflicts_;
    previous_backtrack_conflicts_ = current_conflicts;
    checked_accumulate(delayed_backtrack_callbacks_, 1);
    if (conflict)
      checked_accumulate(conflict_backtrack_callbacks_, 1);
    else
      checked_accumulate(nonconflict_backtrack_callbacks_, 1);

    int64_t callback_undo_members = 0;
    for (size_t group_index = 0; group_index < owners_.size(); ++group_index) {
      OwnerState &owner = owners_[group_index];
      int64_t group_undo_members = 0;
      int64_t group_weight = 0;
      for (unsigned member = 0; member < 2U; ++member) {
        uint32_t &owner_level = owner.levels[member];
        if (!owner_level || owner_level <= new_level)
          continue;
        if (owner_level > current_level_ || owner_level >= levels_.size())
          throw std::runtime_error("delayed pair undone owner level differs");
        group_weight += delayed_owner_weight(current_level_, owner_level);
        ++group_undo_members;
        owner_level = 0;
      }
      if (!group_undo_members)
        continue;
      checked_accumulate(callback_undo_members, group_undo_members);
      checked_accumulate(eligible_undo_groups_, 1);
      checked_accumulate(eligible_undo_members_, group_undo_members);
      checked_accumulate(weighted_undo_units_, group_weight);
      const int64_t penalty = (conflict ? 2 : 1) * group_weight;
      if (conflict) {
        checked_accumulate(conflict_undo_members_, group_undo_members);
        checked_accumulate(conflict_weighted_undo_units_, group_weight);
        checked_accumulate(conflict_penalty_units_, penalty);
      } else {
        checked_accumulate(nonconflict_undo_members_, group_undo_members);
        checked_accumulate(nonconflict_weighted_undo_units_, group_weight);
        checked_accumulate(nonconflict_penalty_units_, penalty);
      }
      GroupState &state = states_.at(group_index);
      state.credit = saturating_credit_add(state.credit, -penalty);
      state.backtrack_hits =
          saturating_counter_add(state.backtrack_hits, group_undo_members);
      if (conflict)
        state.conflict_hits =
            saturating_counter_add(state.conflict_hits, group_undo_members);
      ++delayed_credit_updates_;
    }
    if (callback_undo_members > live_owners_)
      throw std::runtime_error("delayed pair live-owner ledger underflow");
    live_owners_ -= callback_undo_members;
  }

  void record_ticket_assignment(int variable) {
    if (!ticket_.open)
      return;
    const PairGroup &group = groups_.at(ticket_.group_index);
    if (variable == group.first)
      ticket_.first_assigned = true;
    if (variable == group.second)
      ticket_.second_assigned = true;
  }

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
      throw std::runtime_error("delayed pair factor envelope is empty");
    return best;
  }

  void enqueue_if_unassigned(int variable, int spin, size_t group_index,
                             unsigned member) {
    if (assigned_[variable])
      return;
    if (group_index >= groups_.size() || member > 1U)
      throw std::runtime_error("delayed pair queue owner differs");
    queue_.push_back(
        {spin > 0 ? variable : -variable, group_index, member, false});
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
          close_ticket(CloseReason::Invalidation);
          return 0;
        }
        if (!entry.requested)
          ++same_sign_queue_skips_;
        queue_.erase(queue_.begin());
        continue;
      }
      if (entry.requested)
        return 0;
      mark_pending(entry);
      entry.requested = true;
      if (decision_counts_[variable]++)
        ++repeated_decisions_;
      ++requested_decisions_;
      return entry.literal;
    }
    return 0;
  }

  void mark_pending(const QueuedLiteral &entry) {
    if (pending_.open || entry.group_index >= groups_.size() ||
        entry.member > 1U)
      throw std::runtime_error("delayed pair pending ledger differs");
    const PairGroup &group = groups_.at(entry.group_index);
    const int variable = entry.member ? group.second : group.first;
    if (variable != std::abs(entry.literal) || assigned_.at(variable) ||
        owners_.at(entry.group_index).levels.at(entry.member))
      throw std::runtime_error("delayed pair pending target differs");
    pending_.open = true;
    pending_.group_index = entry.group_index;
    pending_.member = entry.member;
    pending_.variable = variable;
    ++pending_marked_;
    maximum_open_pending_ = std::max<int64_t>(maximum_open_pending_, 1);
  }

  void update_queue_for_assignment(int literal) {
    const int variable = std::abs(literal);
    for (size_t index = 0; index < queue_.size(); ++index) {
      if (std::abs(queue_[index].literal) != variable)
        continue;
      if (queue_[index].literal != literal) {
        queue_.clear();
        ++opposite_sign_queue_invalidations_;
        close_ticket(CloseReason::Invalidation);
        return;
      }
      if (!queue_[index].requested)
        ++same_sign_queue_skips_;
      queue_.erase(queue_.begin() + static_cast<std::ptrdiff_t>(index));
      return;
    }
  }

  CaDiCaL::Solver *solver_ = nullptr;
  PotentialField field_;
  std::vector<int8_t> assigned_;
  std::vector<int64_t> decision_counts_;
  std::vector<bool> touched_;
  std::vector<int> owner_group_;
  std::vector<int8_t> owner_member_;
  std::vector<int> observed_;
  std::vector<PairGroup> groups_;
  std::vector<GroupState> states_;
  std::vector<OwnerState> owners_;
  std::vector<QueuedLiteral> queue_;
  std::vector<std::vector<int>> levels_;
  ActionTicket ticket_;
  PendingDecision pending_;
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
  int64_t envelope_evaluations_ = 0;
  long double maximum_gap_ = 0.0L;
  long double maximum_modulated_priority_ = 0.0L;
  bool has_modulated_priority_ = false;
  int first_group_index_ = -1;
  int first_pattern_mask_ = -1;
  std::string selection_trace_;
  int64_t cold_group_selections_ = 0;
  int64_t credit_modulated_group_selections_ = 0;
  int64_t tickets_opened_ = 0;
  int64_t tickets_closed_ = 0;
  int64_t tickets_closed_on_advance_ = 0;
  int64_t tickets_closed_on_backtrack_ = 0;
  int64_t tickets_closed_on_invalidation_ = 0;
  int64_t tickets_closed_on_solve_end_ = 0;
  int64_t ticket_assignment_hits_ = 0;
  int64_t maximum_open_tickets_ = 0;
  int64_t pending_marked_ = 0;
  int64_t pending_bound_ = 0;
  int64_t first_owner_bindings_ = 0;
  int64_t second_owner_bindings_ = 0;
  int64_t owner_assignment_hits_ = 0;
  int64_t maximum_open_pending_ = 0;
  int64_t previous_backtrack_conflicts_ = 0;
  int64_t delayed_backtrack_callbacks_ = 0;
  int64_t conflict_backtrack_callbacks_ = 0;
  int64_t nonconflict_backtrack_callbacks_ = 0;
  int64_t eligible_undo_groups_ = 0;
  int64_t eligible_undo_members_ = 0;
  int64_t conflict_undo_members_ = 0;
  int64_t nonconflict_undo_members_ = 0;
  int64_t weighted_undo_units_ = 0;
  int64_t conflict_weighted_undo_units_ = 0;
  int64_t nonconflict_weighted_undo_units_ = 0;
  int64_t conflict_penalty_units_ = 0;
  int64_t nonconflict_penalty_units_ = 0;
  int64_t delayed_credit_updates_ = 0;
  int64_t live_owners_ = 0;
  int64_t maximum_live_owners_ = 0;
  int64_t delta_conflicts_total_ = 0;
  int64_t delta_decisions_total_ = 0;
  int64_t delta_propagations_total_ = 0;
  int64_t saturated_credit_updates_ = 0;
  int64_t saturated_counter_updates_ = 0;
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
    const std::string cnf_payload =
        read_binary_file(arguments.cnf_path, "CNF input");
    const std::string potential_payload =
        read_binary_file(arguments.potential_path, "potential input");
    const std::string decision_payload =
        read_binary_file(arguments.decision_variables_path, "decision input");
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
    PotentialField field = parse_potential(potential_payload, variables);
    DecisionVariables decisions =
        parse_decision_variables(decision_payload, variables);
    const std::string source_sha256 = field.source_sha256;
    const std::string decision_sha256 = decisions.source_sha256;
    const double offset = field.offset;
    auto propagator = std::make_unique<DelayedPairCreditPropagator>(
        &solver, std::move(field), variables, decisions.variables);
    solver.connect_external_propagator(propagator.get());
    for (const int variable : propagator->observed())
      solver.add_observed_var(variable);
    if (!solver.limit("conflicts", arguments.conflict_limit))
      throw std::runtime_error("CaDiCaL rejected conflict limit");
    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);
    propagator->finalize();

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
    std::cout << ",\"cnf_sha256\":\"" << sha256(cnf_payload)
              << "\",\"stats\":{\"conflicts\":"
              << statistic(solver, "conflicts") << ",\"decisions\":"
              << statistic(solver, "decisions") << ",\"propagations\":"
              << statistic(solver, "propagations") << "},\"delayed\":{"
              << "\"factor_count\":" << propagator->factor_count()
              << ",\"pair_count\":" << propagator->pair_count()
              << ",\"group_width\":2,\"decision_rule\":\"" << kDecisionRule
              << "\",\"cold_decision_rule\":\"" << kColdDecisionRule
              << "\",\"decision_scope\":\"" << kDecisionScope
              << "\",\"source_sha256\":\"" << source_sha256
              << "\",\"decision_variables_sha256\":\"" << decision_sha256
              << "\",\"offset\":" << offset
              << ",\"observed_variables\":"
              << propagator->observed_variables()
              << ",\"eligible_decision_variables\":"
              << propagator->eligible_variables()
              << ",\"external_implications\":0,\"hard_clauses_added\":0"
              << ",\"update_formula\":\"" << kUpdateFormula
              << "\",\"selection_formula\":\"" << kSelectionFormula
              << "\",";
    propagator->write_delayed_json(std::cout);
    std::cout << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
              << ",\"cpu_microseconds\":" << cpu_microseconds()
              << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
    solver.disconnect_external_propagator();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_delayed_pair_search: " << error.what() << '\n';
    return 1;
  }
}
