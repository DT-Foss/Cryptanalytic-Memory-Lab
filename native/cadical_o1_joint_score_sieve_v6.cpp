// Lifecycle-safe exact width-6 score-threshold no-good vault successor.
//
// The serialized public grouping fixes structure only. This implementation
// reconstructs every group table from the original potential with an exact
// binary64 superaccumulator, keeps complete-model scoring on original factors,
// and carries native-v5's pending-clause and teardown repairs forward. Only
// clauses whose terminating external-clause callback was reached are eligible
// for the bounded, identity-bound episodic vault.
#include <iterator>
#include <set>

#define main cadical_o1_joint_score_sieve_v1_embedded_main
#define JointScoreSieve FrozenIndependentJointScoreSieveV1
#include "cadical_o1_joint_score_sieve.cpp"
#undef JointScoreSieve
#undef main

namespace {

constexpr const char *kGroupedSchema =
    "o1-256-cadical-joint-score-sieve-result-v6";
constexpr const char *kImplementationParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v5";
constexpr const char *kGroupedStateSchema =
    "o1-256-cadical-joint-score-sieve-grouped-state-v2";
constexpr std::string_view kGroupingMagic("O1-COMPAT-GREEDY-V1\0", 20U);
constexpr const char *kGroupingRule =
    "ascending-factor-score-aware-overlap-greedy;maximum-exact-root-gain;"
    "ties-smaller-union-width,larger-group,smaller-minimum-factor-index;"
    "groups-ascending-minimum-factor-index";
constexpr const char *kGroupedBoundRule =
    "exact-binary64-lattice-factor-sum;round-once-positive-infinity;"
    "partial-group-maximum;exact-binary64-lattice-root-sum;"
    "round-once-positive-infinity";
constexpr const char *kGroupedStateEncoding =
    "observed-ascending-i8-sign;trail-u32le-level,u32le-count,"
    "u32le-local-index,u32le-level;pending-u32le-length,u32le-cursor,"
    "u8-ready,u8-blocking,i32le-literals;derived-group-cache-group-order-"
    "f64le-max";
constexpr const char *kTeardownRule =
    "connected-solver-destroyed-before-external-propagator;"
    "no-explicit-disconnect";
constexpr const char *kPendingBacktrackRule =
    "retain-valid-pending-no-good;unwind-trail-and-refresh-group-cache;"
    "defer-new-bound";
constexpr size_t kMaximumCompatibilityWidth = 20U;
constexpr size_t kRequiredCompatibilityWidth = 6U;
constexpr std::string_view kVaultMagic("O1-NOGOOD-VAULT-V1\0", 19U);
constexpr const char *kVaultTelemetrySchema =
    "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1";
constexpr const char *kVaultSemanticRule =
    "valid-for-identical-CNF-and-score-potential-at-threshold;not-CNF-entailed";
constexpr const char *kVaultIdentityRule =
    "cnf-sha256,potential-sha256,grouping-sha256,observed-variables-sha256,"
    "bound-rule-sha256,threshold-f64le-exact";
constexpr const char *kVaultClauseEncoding =
    "u32le-length;signed-i32le-dimacs-literals;strict-ascending-absolute-"
    "variable";
constexpr const char *kVaultWitnessEncoding =
    "u8-source(1=trail-upper-bound,2=complete-model-score);"
    "f64le-witness;canonical-clause";
constexpr size_t kMaximumVaultPayloadBytes = 8388608U;
constexpr size_t kMaximumVaultClauses = 512U;
constexpr size_t kMaximumVaultLiterals = 1600000U;
constexpr size_t kVaultDigestCount = 5U;
constexpr size_t kVaultIdentityPrefixBytes =
    kVaultMagic.size() + 32U * kVaultDigestCount + 8U;
constexpr size_t kVaultMinimumBytes = kVaultIdentityPrefixBytes + 4U;

[[maybe_unused]] const char *state_name(CaDiCaL::State state) {
  switch (state) {
  case CaDiCaL::INITIALIZING:
    return "INITIALIZING";
  case CaDiCaL::CONFIGURING:
    return "CONFIGURING";
  case CaDiCaL::STEADY:
    return "STEADY";
  case CaDiCaL::ADDING:
    return "ADDING";
  case CaDiCaL::SOLVING:
    return "SOLVING";
  case CaDiCaL::SATISFIED:
    return "SATISFIED";
  case CaDiCaL::UNSATISFIED:
    return "UNSATISFIED";
  case CaDiCaL::DELETING:
    return "DELETING";
  case CaDiCaL::INCONCLUSIVE:
    return "INCONCLUSIVE";
  default:
    return "UNKNOWN_STATE";
  }
}

struct GroupedArguments {
  Arguments base;
  std::string grouping_path;
  std::string vault_path;
};

[[maybe_unused]] GroupedArguments parse_grouped_arguments(int argc,
                                                          char **argv) {
  if (argc == 2 && std::string_view(argv[1]) == "--help") {
    std::cout << "usage: cadical_o1_joint_score_sieve_v6 --cnf PATH "
                 "--potential PATH --grouping PATH --vault-in PATH "
                 "--threshold FLOAT "
                 "--conflict-limit N [--seed N]\n";
    std::exit(0);
  }
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string grouping_path;
  std::string vault_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--grouping") {
      if (!grouping_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("grouping argument differs");
      grouping_path = argv[index + 1];
    } else if (std::string_view(argv[index]) == "--vault-in") {
      if (!vault_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("vault-in argument differs");
      vault_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (grouping_path.empty() || vault_path.empty())
    throw std::runtime_error("required grouping or vault-in argument is missing");
  return {parse_arguments(static_cast<int>(filtered.size()), filtered.data()),
          grouping_path, vault_path};
}

struct CompatibilityGroup {
  std::vector<size_t> factor_indices;
  std::vector<int> variables;
  std::vector<size_t> local_indices;
  std::vector<double> energies;
};

std::vector<int> union_scope(const std::vector<int> &left,
                             const std::vector<int> &right) {
  std::vector<int> result;
  result.reserve(left.size() + right.size());
  std::set_union(left.begin(), left.end(), right.begin(), right.end(),
                 std::back_inserter(result));
  return result;
}

size_t project_union_row(size_t union_row,
                         const std::vector<int> &union_variables,
                         const std::vector<int> &factor_variables) {
  size_t factor_row = 0;
  for (size_t local = 0; local < factor_variables.size(); ++local) {
    const auto found = std::lower_bound(union_variables.begin(),
                                        union_variables.end(),
                                        factor_variables[local]);
    if (found == union_variables.end() || *found != factor_variables[local])
      throw std::runtime_error("grouped factor projection differs");
    const size_t position = static_cast<size_t>(found - union_variables.begin());
    if ((union_row >> position) & 1U)
      factor_row |= size_t{1} << local;
  }
  return factor_row;
}

double upward_exact_sum(ExactDoubleSum exact, const char *field) {
  const double rounded = exact.rounded();
  exact.add(rounded, true);
  const double result =
      exact.compare_zero() > 0
          ? std::nextafter(rounded, std::numeric_limits<double>::infinity())
          : rounded;
  if (!std::isfinite(result))
    throw std::runtime_error(std::string(field) + " is not representable");
  return result;
}

std::string f64_le_hex(double value) {
  uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&bits, &value, sizeof(bits));
  std::string bytes;
  bytes.reserve(8U);
  append_u64_le(bytes, bits);
  return bytes_hex(bytes);
}

uint16_t read_u16_le(const std::string &payload, size_t &cursor,
                     const char *field) {
  if (cursor > payload.size() || payload.size() - cursor < 2U)
    throw std::runtime_error(std::string(field) + " is truncated");
  const auto *bytes =
      reinterpret_cast<const unsigned char *>(payload.data() + cursor);
  cursor += 2U;
  return static_cast<uint16_t>(bytes[0]) |
         static_cast<uint16_t>(bytes[1]) << 8U;
}

uint32_t read_u32_le(const std::string &payload, size_t &cursor,
                     const char *field) {
  if (cursor > payload.size() || payload.size() - cursor < 4U)
    throw std::runtime_error(std::string(field) + " is truncated");
  const auto *bytes =
      reinterpret_cast<const unsigned char *>(payload.data() + cursor);
  cursor += 4U;
  return static_cast<uint32_t>(bytes[0]) |
         static_cast<uint32_t>(bytes[1]) << 8U |
         static_cast<uint32_t>(bytes[2]) << 16U |
         static_cast<uint32_t>(bytes[3]) << 24U;
}

uint64_t read_u64_le(const std::string &payload, size_t &cursor,
                     const char *field) {
  if (cursor > payload.size() || payload.size() - cursor < 8U)
    throw std::runtime_error(std::string(field) + " is truncated");
  const auto *bytes =
      reinterpret_cast<const unsigned char *>(payload.data() + cursor);
  cursor += 8U;
  uint64_t result = 0;
  for (unsigned shift = 0; shift < 64U; shift += 8U)
    result |= static_cast<uint64_t>(bytes[shift / 8U]) << shift;
  return result;
}

int32_t read_i32_le(const std::string &payload, size_t &cursor,
                    const char *field) {
  const uint32_t raw = read_u32_le(payload, cursor, field);
  int32_t result = 0;
  static_assert(sizeof(result) == sizeof(raw));
  std::memcpy(&result, &raw, sizeof(result));
  return result;
}

uint64_t f64_bits(double value) {
  uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

std::string read_digest_hex(const std::string &payload, size_t &cursor,
                            const char *field) {
  if (cursor > payload.size() || payload.size() - cursor < 32U)
    throw std::runtime_error(std::string(field) + " is truncated");
  const std::string result = bytes_hex(payload.substr(cursor, 32U));
  cursor += 32U;
  return result;
}

[[maybe_unused]] std::string read_bounded_vault_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input)
    throw std::runtime_error("cannot open score-threshold vault");
  const std::streampos end = input.tellg();
  if (end < 0 || static_cast<uint64_t>(end) > kMaximumVaultPayloadBytes)
    throw std::runtime_error("score-threshold vault payload exceeds hard cap");
  const size_t size = static_cast<size_t>(end);
  std::string payload(size, '\0');
  input.seekg(0, std::ios::beg);
  if (size && !input.read(payload.data(), static_cast<std::streamsize>(size)))
    throw std::runtime_error("cannot read score-threshold vault");
  char trailing = 0;
  if (input.get(trailing))
    throw std::runtime_error("score-threshold vault grew while reading");
  if (!input.eof() && input.fail())
    throw std::runtime_error("cannot finish reading score-threshold vault");
  return payload;
}

std::string canonical_clause_bytes(const std::vector<int> &clause) {
  if (clause.size() > std::numeric_limits<uint32_t>::max())
    throw std::runtime_error("score-threshold vault clause length overflows");
  std::string result;
  result.reserve(4U + 4U * clause.size());
  append_u32_le(result, static_cast<uint32_t>(clause.size()));
  for (const int literal : clause) {
    const int32_t signed_literal = static_cast<int32_t>(literal);
    append_u32_le(result, static_cast<uint32_t>(signed_literal));
  }
  return result;
}

struct ScoreThresholdVault {
  std::string input_payload;
  std::string identity_prefix;
  std::string input_sha256;
  std::string cnf_sha256;
  std::string potential_sha256;
  std::string grouping_sha256;
  std::string observed_sha256;
  std::string bound_rule_sha256;
  uint64_t threshold_bits = 0;
  std::vector<std::vector<int>> clauses;
  std::set<std::string> clause_keys;
  size_t literal_count = 0;
  std::string clause_aggregate;
};

struct EmittedVaultClause {
  std::vector<int> literals;
  std::string canonical;
  std::string clause_sha256;
  std::string source;
  double witness_score = 0.0;
  std::string witness_sha256;
  std::string classification;
};

ScoreThresholdVault parse_score_threshold_vault(
    const std::string &payload, const std::string &expected_cnf_sha256,
    const std::string &expected_potential_sha256,
    const std::string &expected_grouping_sha256,
    const std::string &expected_observed_sha256, double expected_threshold,
    const std::vector<int> &observed) {
  if (payload.size() > kMaximumVaultPayloadBytes)
    throw std::runtime_error("score-threshold vault payload exceeds hard cap");
  if (payload.size() < kVaultMinimumBytes ||
      std::string_view(payload.data(), kVaultMagic.size()) != kVaultMagic)
    throw std::runtime_error("score-threshold vault header differs");

  ScoreThresholdVault result;
  result.input_payload = payload;
  result.identity_prefix = payload.substr(0, kVaultIdentityPrefixBytes);
  result.input_sha256 = sha256(payload);
  size_t cursor = kVaultMagic.size();
  result.cnf_sha256 = read_digest_hex(payload, cursor, "vault CNF digest");
  result.potential_sha256 =
      read_digest_hex(payload, cursor, "vault potential digest");
  result.grouping_sha256 =
      read_digest_hex(payload, cursor, "vault grouping digest");
  result.observed_sha256 =
      read_digest_hex(payload, cursor, "vault observed-variable digest");
  result.bound_rule_sha256 =
      read_digest_hex(payload, cursor, "vault bound-rule digest");
  result.threshold_bits = read_u64_le(payload, cursor, "vault threshold");
  const std::string expected_bound_rule_sha256 = sha256(kGroupedBoundRule);
  if (result.cnf_sha256 != expected_cnf_sha256 ||
      result.potential_sha256 != expected_potential_sha256 ||
      result.grouping_sha256 != expected_grouping_sha256 ||
      result.observed_sha256 != expected_observed_sha256 ||
      result.bound_rule_sha256 != expected_bound_rule_sha256 ||
      result.threshold_bits != f64_bits(expected_threshold))
    throw std::runtime_error("score-threshold vault identity differs");

  const uint32_t clause_count =
      read_u32_le(payload, cursor, "vault clause count");
  if (clause_count > kMaximumVaultClauses)
    throw std::runtime_error("score-threshold vault clause count exceeds hard cap");
  result.clauses.reserve(clause_count);
  for (uint32_t clause_index = 0; clause_index < clause_count; ++clause_index) {
    const uint32_t length =
        read_u32_le(payload, cursor, "vault clause length");
    if (!length)
      throw std::runtime_error("score-threshold vault empty clause differs");
    if (length > observed.size() ||
        length > kMaximumVaultLiterals - result.literal_count)
      throw std::runtime_error("score-threshold vault literal count exceeds hard cap");
    if (cursor > payload.size() ||
        static_cast<size_t>(length) > (payload.size() - cursor) / 4U)
      throw std::runtime_error("score-threshold vault clause is truncated");
    std::vector<int> clause;
    clause.reserve(length);
    int64_t previous_absolute = 0;
    for (uint32_t literal_index = 0; literal_index < length; ++literal_index) {
      const int32_t literal =
          read_i32_le(payload, cursor, "vault clause literal");
      if (!literal || literal == std::numeric_limits<int32_t>::min())
        throw std::runtime_error("score-threshold vault literal differs");
      const int64_t absolute =
          literal < 0 ? -static_cast<int64_t>(literal) : literal;
      if (absolute <= previous_absolute || absolute > kMaximumVariables ||
          !std::binary_search(observed.begin(), observed.end(),
                              static_cast<int>(absolute)))
        throw std::runtime_error(
            "score-threshold vault literal order or scope differs");
      previous_absolute = absolute;
      clause.push_back(static_cast<int>(literal));
    }
    const std::string canonical = canonical_clause_bytes(clause);
    if (!result.clause_keys.insert(canonical).second)
      throw std::runtime_error("score-threshold vault duplicate clause differs");
    result.clause_aggregate += canonical;
    result.literal_count += clause.size();
    result.clauses.push_back(std::move(clause));
  }
  if (cursor != payload.size())
    throw std::runtime_error("score-threshold vault trailing bytes differ");
  return result;
}

class GroupedJointScoreSieveV6 final : public CaDiCaL::ExternalPropagator,
                                       public CaDiCaL::Terminator {
public:
  GroupedJointScoreSieveV6(PotentialField field,
                          const std::string &grouping_payload,
                          const std::string &vault_payload,
                          const std::string &cnf_sha256,
                          const std::string &potential_sha256,
                          double threshold)
      : field_(std::move(field)), threshold_(threshold) {
    for (const PotentialFactor &factor : field_.factors)
      observed_.insert(observed_.end(), factor.variables.begin(),
                       factor.variables.end());
    std::sort(observed_.begin(), observed_.end());
    observed_.erase(std::unique(observed_.begin(), observed_.end()),
                    observed_.end());
    if (observed_.empty())
      throw std::runtime_error("grouped joint-score potential observes no variables");
    assigned_.assign(observed_.size(), 0);
    for (PotentialFactor &factor : field_.factors) {
      for (const int variable : factor.variables) {
        const size_t local = local_index(variable);
        if (local == observed_.size())
          throw std::runtime_error("grouped original-factor mapping differs");
        factor.local_indices.push_back(local);
      }
    }
    build_groups(grouping_payload, potential_sha256);
    incident_groups_.resize(observed_.size());
    group_maxima_.resize(groups_.size());
    for (size_t group_index = 0; group_index < groups_.size(); ++group_index) {
      CompatibilityGroup &group = groups_[group_index];
      group_table_rows_ += static_cast<int64_t>(group.energies.size());
      for (const int variable : group.variables) {
        const size_t local = local_index(variable);
        if (local == observed_.size())
          throw std::runtime_error("grouped local variable mapping differs");
        group.local_indices.push_back(local);
        incident_groups_[local].push_back(group_index);
        ++group_incident_edges_;
      }
      group_maxima_[group_index] = group_maximum(group, assigned_);
    }
    if (singleton_group_count_ + pair_group_count_ +
                higher_order_group_count_ !=
            groups_.size() ||
        !maximum_group_size_)
      throw std::runtime_error("grouped factor partition differs");
    std::string observed_bytes;
    observed_bytes.reserve(observed_.size() * 4U);
    for (const int variable : observed_)
      append_u32_le(observed_bytes, static_cast<uint32_t>(variable));
    observed_sha256_ = sha256(observed_bytes);
    input_vault_ = parse_score_threshold_vault(
        vault_payload, cnf_sha256, potential_sha256, grouping_sha256_,
        observed_sha256_, threshold_, observed_);
    certify_input_vault();
    root_upper_bound_ = upper_from_cached_maxima();
    minimum_upper_bound_ = root_upper_bound_;
    maximum_upper_bound_ = root_upper_bound_;
    ++bound_checks_;
    update_maximum_live_state();
    if (root_upper_bound_ < threshold_)
      queue_clause(assigned_, root_upper_bound_, false);
    else
      record_trace(root_upper_bound_, false, 0U);
  }

  void notify_assignment(const std::vector<int> &literals) override {
    ++assignment_callbacks_;
    std::vector<size_t> changed;
    for (const int literal : literals) {
      const size_t local = local_index(std::abs(literal));
      if (local == observed_.size())
        throw std::runtime_error("unexpected grouped joint-score assignment");
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assigned_.at(local);
      if (!slot) {
        slot = value;
        trail_.push_back(
            {static_cast<uint32_t>(local), static_cast<uint32_t>(current_level_)});
        changed.push_back(local);
        ++assigned_count_;
        ++assignment_literals_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        maximum_live_trail_entries_ =
            std::max(maximum_live_trail_entries_, trail_.size());
      } else if (slot != value) {
        throw std::runtime_error(
            "grouped joint-score assignment changed without backtrack");
      }
    }
    update_maximum_live_state();
    if (!changed.empty()) {
      if (pending_ready_ || blocking_active_ || capacity_crossed_)
        refresh_group_maxima(changed);
      else
        evaluate_current_bound(changed);
    }
  }

  void notify_new_decision_level() override {
    if (current_level_ >= 1000000U)
      throw std::runtime_error("grouped joint-score decision level exceeds bound");
    ++current_level_;
    ++new_decision_levels_;
    maximum_level_ = std::max(maximum_level_, current_level_);
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_)
      throw std::runtime_error("invalid grouped joint-score backtrack level");
    const bool clause_pending = pending_ready_ || blocking_active_;
    std::vector<size_t> changed;
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t local = trail_.back().local;
      int8_t &slot = assigned_.at(local);
      if (!slot)
        throw std::runtime_error(
            "grouped joint-score backtrack found unassigned variable");
      slot = 0;
      trail_.pop_back();
      changed.push_back(local);
      --assigned_count_;
      ++backtracked_assignments_;
    }
    current_level_ = new_level;
    ++backtracks_;
    if (!changed.empty()) {
      if (clause_pending || capacity_crossed_)
        refresh_group_maxima(changed);
      else
        evaluate_current_bound(changed);
    }
    if (capacity_crossed_)
      capacity_termination_armed_ = true;
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    ++model_checks_;
    std::vector<int8_t> values(observed_.size(), 0);
    for (const int literal : model) {
      const size_t local = local_index(std::abs(literal));
      if (local == observed_.size())
        continue;
      int8_t &slot = values.at(local);
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      if (slot && slot != value)
        throw std::runtime_error("grouped joint-score model duplicates disagree");
      slot = value;
    }
    if (std::find(values.begin(), values.end(), int8_t{0}) != values.end())
      throw std::runtime_error("grouped joint-score model omits observed variable");
    // Complete scores intentionally remain an exact sum of original factors.
    ExactDoubleSum exact = complete_score_sum(values);
    const double score = exact.rounded();
    exact.add(threshold_, true);
    const int threshold_comparison = exact.compare_zero();
    ++complete_model_score_checks_;
    if (!have_complete_score_) {
      minimum_complete_score_ = score;
      maximum_complete_score_ = score;
      have_complete_score_ = true;
    } else {
      minimum_complete_score_ = std::min(minimum_complete_score_, score);
      maximum_complete_score_ = std::max(maximum_complete_score_, score);
    }
    if (threshold_comparison < 0) {
      ++models_below_threshold_;
      if (capacity_crossed_)
        throw std::runtime_error(
            "score-threshold capacity termination lag reached a rejected model at "
            "level " +
            std::to_string(current_level_));
      if (blocking_active_ || pending_ready_)
        throw std::runtime_error(
            "grouped joint-score model rejection overlaps clause");
      queue_clause(values, score, true);
      return false;
    }
    ++models_at_or_above_threshold_;
    return true;
  }

  int cb_decide() override {
    ++cb_decide_calls_;
    return 0;
  }

  int cb_propagate() override {
    ++cb_propagate_calls_;
    return 0;
  }

  int cb_add_reason_clause_lit(int) override { return 0; }

  bool terminate() override {
    if (!capacity_crossed_)
      return false;
    if (capacity_termination_armed_)
      return true;
    if (!capacity_termination_grace_poll_seen_) {
      capacity_termination_grace_poll_seen_ = true;
      return false;
    }
    capacity_termination_armed_ = true;
    return true;
  }

  bool cb_has_external_clause(bool &forgettable) override {
    ++cb_has_external_clause_calls_;
    forgettable = false;
    return pending_ready_;
  }

  int cb_add_external_clause_lit() override {
    if (!pending_ready_)
      throw std::runtime_error(
          "grouped joint-score clause callback lacks pending clause");
    if (pending_cursor_ < pending_clause_.size())
      return pending_clause_.at(pending_cursor_++);
    record_fully_emitted_clause(pending_clause_, pending_witness_score_,
                                pending_model_clause_);
    ++external_clauses_emitted_;
    pending_clause_.clear();
    pending_cursor_ = 0;
    pending_ready_ = false;
    blocking_active_ = false;
    pending_witness_score_ = 0.0;
    pending_model_clause_ = false;
    return 0;
  }

  const std::vector<int> &observed() const { return observed_; }

  const std::vector<std::vector<int>> &preloaded_clauses() const {
    return input_vault_.clauses;
  }

  void attach_solver(CaDiCaL::Solver *solver) {
    if (!solver || solver_)
      throw std::runtime_error("score-threshold terminator solver differs");
    solver_ = solver;
  }

  std::string assignment_state() const {
    return std::string(reinterpret_cast<const char *>(assigned_.data()),
                       assigned_.size());
  }

  std::string trail_state() const {
    std::string result;
    result.reserve(8U + 8U * trail_.size());
    append_u32_le(result, static_cast<uint32_t>(current_level_));
    append_u32_le(result, static_cast<uint32_t>(trail_.size()));
    for (const TrailEntry &entry : trail_) {
      append_u32_le(result, entry.local);
      append_u32_le(result, entry.level);
    }
    return result;
  }

  std::string pending_state() const {
    std::string result;
    result.reserve(10U + 4U * pending_clause_.size());
    append_u32_le(result, static_cast<uint32_t>(pending_clause_.size()));
    append_u32_le(result, static_cast<uint32_t>(pending_cursor_));
    result.push_back(static_cast<char>(pending_ready_ ? 1 : 0));
    result.push_back(static_cast<char>(blocking_active_ ? 1 : 0));
    for (const int literal : pending_clause_)
      append_u32_le(result, static_cast<uint32_t>(static_cast<int32_t>(literal)));
    return result;
  }

  std::string group_cache_state() const {
    std::string result;
    result.reserve(8U * group_maxima_.size());
    for (const double maximum : group_maxima_) {
      uint64_t bits = 0;
      static_assert(sizeof(bits) == sizeof(maximum));
      std::memcpy(&bits, &maximum, sizeof(bits));
      append_u64_le(result, bits);
    }
    return result;
  }

  size_t bounded_state_bytes() const {
    return observed_.size() + 8U + 8U * observed_.size() + 10U +
           4U * observed_.size();
  }

  void write_json(std::ostream &out) const {
    const std::string assignments = assignment_state();
    const std::string trail = trail_state();
    const std::string pending = pending_state();
    const std::string cache = group_cache_state();
    const std::string canonical = assignments + trail + pending;
    const std::string persistent = canonical + cache;
    out << "\"factor_count\":" << field_.factors.size()
        << ",\"group_count\":" << groups_.size()
        << ",\"pair_group_count\":" << pair_group_count_
        << ",\"singleton_group_count\":" << singleton_group_count_
        << ",\"higher_order_group_count\":" << higher_order_group_count_
        << ",\"maximum_group_size\":" << maximum_group_size_
        << ",\"grouping_width_cap\":" << grouping_width_cap_
        << ",\"grouping_serialized_bytes\":" << grouping_serialized_bytes_
        << ",\"group_table_rows\":" << group_table_rows_
        << ",\"group_incident_edges\":" << group_incident_edges_
        << ",\"grouping_rule\":\"" << kGroupingRule
        << "\",\"grouping_sha256\":\"" << grouping_sha256_
        << "\",\"grouping_input_sha256\":\"" << grouping_input_sha256_
        << "\",\"observed_variables\":" << observed_.size()
        << ",\"observed_variables_sha256\":\"" << observed_sha256_
        << "\",\"source_sha256\":\"" << field_.source_sha256
        << "\",\"offset\":" << field_.offset << ",\"threshold\":"
        << threshold_ << ",\"root_upper_bound\":" << root_upper_bound_
        << ",\"root_upper_bound_f64le_hex\":\""
        << f64_le_hex(root_upper_bound_) << "\""
        << ",\"bound_rule\":\"" << kGroupedBoundRule
        << "\",\"complete_threshold_rule\":\"" << kCompleteThresholdRule
        << "\",\"decision_rule\":\"" << kDecisionRule
        << "\",\"external_implications\":0,\"cb_decide_calls\":"
        << cb_decide_calls_ << ",\"cb_decide_nonzero\":0"
        << ",\"cb_propagate_calls\":" << cb_propagate_calls_
        << ",\"assignment_callbacks\":" << assignment_callbacks_
        << ",\"assignment_literals\":" << assignment_literals_
        << ",\"new_decision_levels\":" << new_decision_levels_
        << ",\"backtracks\":" << backtracks_
        << ",\"backtracked_assignments\":" << backtracked_assignments_
        << ",\"maximum_assigned_variables\":" << maximum_assigned_
        << ",\"maximum_decision_level\":" << maximum_level_
        << ",\"bound_checks\":" << bound_checks_
        << ",\"bound_additions\":" << bound_additions_
        << ",\"incremental_group_recomputations\":"
        << incremental_group_recomputations_
        << ",\"maximum_incremental_groups_recomputed\":"
        << maximum_incremental_groups_recomputed_
        << ",\"group_maximum_evaluations\":" << group_maximum_evaluations_
        << ",\"group_row_evaluations\":" << group_row_evaluations_
        << ",\"minimum_upper_bound\":" << minimum_upper_bound_
        << ",\"maximum_upper_bound\":" << maximum_upper_bound_
        << ",\"threshold_prunes\":" << threshold_prunes_
        << ",\"trail_threshold_prunes\":" << trail_threshold_prunes_
        << ",\"model_threshold_prunes\":" << model_threshold_prunes_
        << ",\"external_clauses_queued\":" << external_clauses_queued_
        << ",\"external_clauses_emitted\":" << external_clauses_emitted_
        << ",\"external_clause_literals\":" << external_clause_literals_
        << ",\"minimum_clause_length\":" << minimum_clause_length()
        << ",\"maximum_clause_length\":" << maximum_clause_length_
        << ",\"maximum_pending_clause_length\":"
        << maximum_pending_clause_length_
        << ",\"pending_clause_count\":" << (pending_ready_ ? 1 : 0)
        << ",\"cb_has_external_clause_calls\":"
        << cb_has_external_clause_calls_ << ",\"model_checks\":"
        << model_checks_ << ",\"complete_model_score_checks\":"
        << complete_model_score_checks_ << ",\"models_below_threshold\":"
        << models_below_threshold_ << ",\"models_at_or_above_threshold\":"
        << models_at_or_above_threshold_ << ",\"minimum_complete_score\":";
    if (have_complete_score_)
      out << minimum_complete_score_;
    else
      out << "null";
    out << ",\"maximum_complete_score\":";
    if (have_complete_score_)
      out << maximum_complete_score_;
    else
      out << "null";
    out << ",\"trace_sha256\":\"" << trace_.hex_digest()
        << "\",\"state\":{\"schema\":\"" << kGroupedStateSchema
        << "\",\"encoding\":\"" << kGroupedStateEncoding
        << "\",\"persistent_state_scope\":\"" << kPersistentStateScope
        << "\",\"assignment_bytes\":" << assignments.size()
        << ",\"bounded_trail_bytes\":" << 8U + 8U * observed_.size()
        << ",\"bounded_pending_bytes\":" << 10U + 4U * observed_.size()
        << ",\"bounded_state_bytes\":" << bounded_state_bytes()
        << ",\"derived_group_cache_bytes\":" << cache.size()
        << ",\"bounded_persistent_state_bytes\":"
        << bounded_state_bytes() + cache.size()
        << ",\"live_trail_bytes\":" << trail.size()
        << ",\"live_pending_bytes\":" << pending.size()
        << ",\"live_state_bytes\":" << canonical.size()
        << ",\"live_persistent_state_bytes\":" << persistent.size()
        << ",\"maximum_live_trail_bytes\":"
        << 8U + 8U * maximum_live_trail_entries_
        << ",\"maximum_live_state_bytes\":" << maximum_live_state_bytes_
        << ",\"maximum_live_persistent_state_bytes\":"
        << maximum_live_state_bytes_ + cache.size()
        << ",\"current_assigned_variables\":" << assigned_count_
        << ",\"current_decision_level\":" << current_level_
        << ",\"trail_entries\":" << trail_.size()
        << ",\"pending_clause_length\":" << pending_clause_.size()
        << ",\"assignment_hex\":\"" << bytes_hex(assignments)
        << "\",\"trail_hex\":\"" << bytes_hex(trail)
        << "\",\"pending_hex\":\"" << bytes_hex(pending)
        << "\",\"group_cache_hex\":\"" << bytes_hex(cache)
        << "\",\"assignment_sha256\":\"" << sha256(assignments)
        << "\",\"trail_sha256\":\"" << sha256(trail)
        << "\",\"pending_sha256\":\"" << sha256(pending)
        << "\",\"group_cache_sha256\":\"" << sha256(cache)
        << "\",\"sha256\":\"" << sha256(canonical)
        << "\",\"persistent_sha256\":\"" << sha256(persistent) << "\"}";
  }

  void write_vault_json(std::ostream &out) const {
    std::string emitted_aggregate;
    for (const EmittedVaultClause &emitted : emitted_clauses_)
      emitted_aggregate += emitted.canonical;
    const std::string terminal_reason = next_vault_terminal_reason();
    const bool next_available = terminal_reason.empty();
    const std::string next_payload =
        next_available ? next_vault_payload() : std::string();
    out << "\"schema\":\"" << kVaultTelemetrySchema
        << "\",\"binary_magic_hex\":\"" << bytes_hex(kVaultMagic)
        << "\",\"semantic_rule\":\"" << kVaultSemanticRule
        << "\",\"identity_rule\":\"" << kVaultIdentityRule
        << "\",\"clause_encoding\":\"" << kVaultClauseEncoding
        << "\",\"witness_encoding\":\"" << kVaultWitnessEncoding
        << "\",\"maximum_payload_bytes\":" << kMaximumVaultPayloadBytes
        << ",\"maximum_clause_count\":" << kMaximumVaultClauses
        << ",\"maximum_literal_count\":" << kMaximumVaultLiterals
        << ",\"input_sha256\":\"" << input_vault_.input_sha256
        << "\",\"input_serialized_bytes\":"
        << input_vault_.input_payload.size()
        << ",\"input_clause_count\":" << input_vault_.clauses.size()
        << ",\"input_literal_count\":" << input_vault_.literal_count
        << ",\"input_clause_aggregate_sha256\":\""
        << sha256(input_vault_.clause_aggregate)
        << "\",\"input_certification_rule\":\""
        << "partial-excluded-assignment-grouped-upper-bound-strictly-below-"
           "threshold;full-excluded-assignment-original-factor-exact-score-"
           "strictly-below-threshold"
        << "\",\"validated_input_clause_count\":"
        << validated_input_clause_count_
        << ",\"validated_input_literal_count\":"
        << validated_input_literal_count_
        << ",\"validated_input_clause_aggregate_sha256\":\""
        << validated_input_clause_aggregate_sha256_
        << "\",\"input_cnf_sha256\":\"" << input_vault_.cnf_sha256
        << "\",\"input_potential_sha256\":\""
        << input_vault_.potential_sha256
        << "\",\"input_grouping_sha256\":\""
        << input_vault_.grouping_sha256
        << "\",\"input_observed_variables_sha256\":\""
        << input_vault_.observed_sha256
        << "\",\"input_bound_rule_sha256\":\""
        << input_vault_.bound_rule_sha256
        << "\",\"input_threshold_f64le_hex\":\""
        << f64_le_hex(threshold_)
        << "\",\"preloaded_clause_count\":" << input_vault_.clauses.size()
        << ",\"preloaded_literal_count\":" << input_vault_.literal_count
        << ",\"fully_emitted_clause_count\":" << emitted_clauses_.size()
        << ",\"fully_emitted_literal_count\":"
        << fully_emitted_literal_count_
        << ",\"emitted_new_clause_count\":" << emitted_new_clause_count_
        << ",\"emitted_new_literal_count\":" << emitted_new_literal_count_
        << ",\"emitted_input_duplicate_clause_count\":"
        << emitted_input_duplicate_clause_count_
        << ",\"emitted_input_duplicate_literal_count\":"
        << emitted_input_duplicate_literal_count_
        << ",\"emitted_current_duplicate_clause_count\":"
        << emitted_current_duplicate_clause_count_
        << ",\"emitted_current_duplicate_literal_count\":"
        << emitted_current_duplicate_literal_count_
        << ",\"terminal_empty_clause_count\":"
        << terminal_empty_clause_count_
        << ",\"pending_clause_exported\":false"
        << ",\"fully_emitted_aggregate_sha256\":\""
        << sha256(emitted_aggregate) << "\",\"fully_emitted_clauses\":[";
    for (size_t index = 0; index < emitted_clauses_.size(); ++index) {
      const EmittedVaultClause &emitted = emitted_clauses_[index];
      if (index)
        out << ',';
      out << "{\"index\":" << index << ",\"source\":\""
          << emitted.source << "\",\"witness_score\":"
          << emitted.witness_score << ",\"witness_score_f64le_hex\":\""
          << f64_le_hex(emitted.witness_score)
          << "\",\"literal_count\":" << emitted.literals.size()
          << ",\"literals\":[";
      for (size_t literal_index = 0;
           literal_index < emitted.literals.size(); ++literal_index) {
        if (literal_index)
          out << ',';
        out << emitted.literals[literal_index];
      }
      out << "],\"clause_sha256\":\"" << emitted.clause_sha256
          << "\",\"witness_sha256\":\"" << emitted.witness_sha256
          << "\",\"classification\":\"" << emitted.classification
          << "\"}";
    }
    out << "],\"next_vault_available\":"
        << (next_available ? "true" : "false")
        << ",\"next_vault_terminal_reason\":";
    if (next_available)
      out << "null";
    else
      out << '"' << terminal_reason << '"';
    out
        << ",\"next_vault_sha256\":";
    if (next_available)
      out << '"' << sha256(next_payload) << '"';
    else
      out << "null";
    out << ",\"next_serialized_bytes\":";
    if (next_available)
      out << next_payload.size();
    else
      out << "null";
    out << ",\"next_clause_count\":";
    if (next_available)
      out << input_vault_.clauses.size() + emitted_new_clause_count_;
    else
      out << "null";
    out << ",\"next_literal_count\":";
    if (next_available)
      out << input_vault_.literal_count + emitted_new_literal_count_;
    else
      out << "null";
  }

private:
  struct TrailEntry {
    uint32_t local;
    uint32_t level;
  };

  size_t local_index(int variable) const {
    const auto found =
        std::lower_bound(observed_.begin(), observed_.end(), variable);
    if (found == observed_.end() || *found != variable)
      return observed_.size();
    return static_cast<size_t>(found - observed_.begin());
  }

  double certification_group_maximum(
      const CompatibilityGroup &group,
      const std::vector<int8_t> &values) const {
    double best = -std::numeric_limits<double>::infinity();
    for (size_t row = 0; row < group.energies.size(); ++row) {
      bool consistent = true;
      for (size_t position = 0; position < group.local_indices.size();
           ++position) {
        const int8_t spin = values.at(group.local_indices[position]);
        if (spin && ((row >> position) & 1U) !=
                        static_cast<unsigned>(spin > 0)) {
          consistent = false;
          break;
        }
      }
      if (consistent)
        best = std::max(best, group.energies[row]);
    }
    if (!std::isfinite(best))
      throw std::runtime_error(
          "score-threshold vault certification has no consistent group row");
    return best;
  }

  double certification_upper_bound(const std::vector<int8_t> &values) const {
    ExactDoubleSum exact;
    exact.add(field_.offset);
    for (const CompatibilityGroup &group : groups_)
      exact.add(certification_group_maximum(group, values));
    return upward_exact_sum(exact, "score-threshold vault certified upper bound");
  }

  void certify_input_vault() {
    for (const std::vector<int> &clause : input_vault_.clauses) {
      std::vector<int8_t> excluded(observed_.size(), 0);
      for (const int literal : clause) {
        const size_t local = local_index(std::abs(literal));
        if (local == observed_.size())
          throw std::runtime_error(
              "score-threshold vault certification scope differs");
        excluded[local] = literal < 0 ? int8_t{1} : int8_t{-1};
      }
      bool certified = false;
      if (clause.size() == observed_.size()) {
        ExactDoubleSum exact = complete_score_sum(excluded);
        exact.add(threshold_, true);
        certified = exact.compare_zero() < 0;
      } else {
        certified = certification_upper_bound(excluded) < threshold_;
      }
      if (!certified)
        throw std::runtime_error(
            "score-threshold vault clause certification differs");
      ++validated_input_clause_count_;
      validated_input_literal_count_ += clause.size();
    }
    validated_input_clause_aggregate_sha256_ =
        sha256(input_vault_.clause_aggregate);
  }

  std::string next_vault_payload() const {
    const size_t clause_count =
        input_vault_.clauses.size() + emitted_new_clause_count_;
    std::string result = input_vault_.identity_prefix;
    append_u32_le(result, static_cast<uint32_t>(clause_count));
    for (const std::vector<int> &clause : input_vault_.clauses)
      result += canonical_clause_bytes(clause);
    for (const EmittedVaultClause &emitted : emitted_clauses_) {
      if (emitted.classification == "new")
        result += emitted.canonical;
    }
    return result;
  }

  std::string next_vault_terminal_reason() const {
    if (terminal_empty_clause_count_)
      return "terminal_empty_clause";
    if (emitted_new_clause_count_ >
        kMaximumVaultClauses - input_vault_.clauses.size())
      return "capacity_clause_count";
    if (emitted_new_literal_count_ >
        kMaximumVaultLiterals - input_vault_.literal_count)
      return "capacity_literal_count";
    if (emitted_new_serialized_bytes_ >
        kMaximumVaultPayloadBytes - input_vault_.input_payload.size())
      return "capacity_payload_bytes";
    return {};
  }

  void record_fully_emitted_clause(const std::vector<int> &clause,
                                   double witness_score,
                                   bool model_clause) {
    if (capacity_crossed_)
      throw std::runtime_error(
          "score-threshold clause emitted after capacity crossing");
    EmittedVaultClause emitted;
    emitted.literals = clause;
    emitted.canonical = canonical_clause_bytes(clause);
    emitted.clause_sha256 = sha256(emitted.canonical);
    emitted.source =
        model_clause ? "complete_model_score" : "trail_upper_bound";
    emitted.witness_score = witness_score;
    if (clause.empty()) {
      emitted.classification = "terminal_empty";
      ++terminal_empty_clause_count_;
    } else if (input_vault_.clause_keys.count(emitted.canonical)) {
      emitted.classification = "input_duplicate";
      ++emitted_input_duplicate_clause_count_;
      emitted_input_duplicate_literal_count_ += clause.size();
    } else if (!current_new_clause_keys_.insert(emitted.canonical).second) {
      emitted.classification = "current_duplicate";
      ++emitted_current_duplicate_clause_count_;
      emitted_current_duplicate_literal_count_ += clause.size();
    } else {
      emitted.classification = "new";
      ++emitted_new_clause_count_;
      emitted_new_literal_count_ += clause.size();
      emitted_new_serialized_bytes_ += emitted.canonical.size();
    }
    const std::string terminal_reason = next_vault_terminal_reason();
    if (terminal_reason.rfind("capacity_", 0U) == 0U) {
      capacity_crossed_ = true;
      if (current_level_) {
        capacity_termination_armed_ = true;
        if (!solver_)
          throw std::runtime_error(
              "score-threshold capacity terminator lacks solver");
        solver_->terminate();
      }
    }
    std::string witness;
    witness.reserve(9U + emitted.canonical.size());
    witness.push_back(static_cast<char>(model_clause ? 2 : 1));
    append_u64_le(witness, f64_bits(witness_score));
    witness += emitted.canonical;
    emitted.witness_sha256 = sha256(witness);
    fully_emitted_literal_count_ += clause.size();
    emitted_clauses_.push_back(std::move(emitted));
  }

  void build_groups(const std::string &payload,
                    const std::string &potential_sha256) {
    if (payload.size() < kGroupingMagic.size() + 32U + 10U ||
        std::string_view(payload.data(), kGroupingMagic.size()) !=
            kGroupingMagic)
      throw std::runtime_error("compatibility grouping header differs");
    size_t cursor = kGroupingMagic.size();
    const std::string bound_potential_sha256 =
        bytes_hex(payload.substr(cursor, 32U));
    cursor += 32U;
    grouping_width_cap_ = read_u16_le(payload, cursor, "grouping width");
    const uint32_t factor_count =
        read_u32_le(payload, cursor, "grouping factor count");
    const uint32_t group_count =
        read_u32_le(payload, cursor, "grouping group count");
    if (bound_potential_sha256 != potential_sha256 ||
        grouping_width_cap_ != kRequiredCompatibilityWidth ||
        grouping_width_cap_ > kMaximumCompatibilityWidth ||
        factor_count != field_.factors.size() || group_count < 1U ||
        group_count > factor_count)
      throw std::runtime_error("compatibility grouping identity differs");

    std::vector<uint8_t> seen(field_.factors.size(), 0U);
    size_t previous_minimum = field_.factors.size();
    groups_.reserve(group_count);
    for (uint32_t group_index = 0; group_index < group_count; ++group_index) {
      CompatibilityGroup group;
      const uint32_t member_count =
          read_u32_le(payload, cursor, "grouping member count");
      if (member_count < 1U || member_count > factor_count)
        throw std::runtime_error("compatibility group member count differs");
      group.factor_indices.reserve(member_count);
      for (uint32_t member = 0; member < member_count; ++member) {
        const uint32_t factor_index =
            read_u32_le(payload, cursor, "grouping factor index");
        if (factor_index >= seen.size() || seen[factor_index] ||
            (!group.factor_indices.empty() &&
             factor_index <= group.factor_indices.back()))
          throw std::runtime_error("compatibility group membership differs");
        seen[factor_index] = 1U;
        group.factor_indices.push_back(factor_index);
      }
      if (group_index && group.factor_indices.front() <= previous_minimum)
        throw std::runtime_error("compatibility group order differs");
      previous_minimum = group.factor_indices.front();

      const uint16_t width =
          read_u16_le(payload, cursor, "grouping variable width");
      if (width < 1U || width > grouping_width_cap_)
        throw std::runtime_error("compatibility group width differs");
      group.variables.reserve(width);
      for (uint16_t position = 0; position < width; ++position) {
        const uint32_t variable =
            read_u32_le(payload, cursor, "grouping variable");
        if (!variable || variable > static_cast<uint32_t>(kMaximumVariables) ||
            (!group.variables.empty() &&
             variable <= static_cast<uint32_t>(group.variables.back())))
          throw std::runtime_error("compatibility group variable differs");
        group.variables.push_back(static_cast<int>(variable));
      }
      std::vector<int> expected_variables;
      for (const size_t factor_index : group.factor_indices)
        expected_variables =
            union_scope(expected_variables, field_.factors[factor_index].variables);
      if (group.variables != expected_variables)
        throw std::runtime_error("compatibility group scope differs");

      group.energies.resize(size_t{1} << group.variables.size());
      for (size_t row = 0; row < group.energies.size(); ++row) {
        ExactDoubleSum exact;
        for (const size_t factor_index : group.factor_indices) {
          const PotentialFactor &factor = field_.factors[factor_index];
          const size_t factor_row =
              project_union_row(row, group.variables, factor.variables);
          exact.add(factor.energies.at(factor_row));
        }
        group.energies[row] =
            upward_exact_sum(exact, "compatibility group energy");
      }
      if (member_count == 1U)
        ++singleton_group_count_;
      else if (member_count == 2U)
        ++pair_group_count_;
      else
        ++higher_order_group_count_;
      maximum_group_size_ =
          std::max(maximum_group_size_, group.factor_indices.size());
      groups_.push_back(std::move(group));
    }
    if (cursor != payload.size())
      throw std::runtime_error("compatibility grouping trailing bytes differ");
    if (std::find(seen.begin(), seen.end(), uint8_t{0}) != seen.end())
      throw std::runtime_error("compatibility grouping factor omission differs");
    grouping_input_sha256_ = sha256(payload);
    grouping_sha256_ = grouping_input_sha256_;
    grouping_serialized_bytes_ = payload.size();
  }

  double group_maximum(const CompatibilityGroup &group,
                       const std::vector<int8_t> &values) {
    ++group_maximum_evaluations_;
    group_row_evaluations_ += static_cast<int64_t>(group.energies.size());
    double best = -std::numeric_limits<double>::infinity();
    for (size_t row = 0; row < group.energies.size(); ++row) {
      bool consistent = true;
      for (size_t position = 0; position < group.local_indices.size();
           ++position) {
        const int8_t spin = values.at(group.local_indices[position]);
        if (spin && ((row >> position) & 1U) !=
                        static_cast<unsigned>(spin > 0)) {
          consistent = false;
          break;
        }
      }
      if (consistent)
        best = std::max(best, group.energies[row]);
    }
    if (!std::isfinite(best))
      throw std::runtime_error("grouped joint-score group has no consistent row");
    return best;
  }

  double upper_from_cached_maxima() {
    ExactDoubleSum exact;
    exact.add(field_.offset);
    for (const double maximum : group_maxima_) {
      exact.add(maximum);
      ++bound_additions_;
    }
    return upward_exact_sum(exact, "grouped joint-score upper bound");
  }

  ExactDoubleSum
  complete_score_sum(const std::vector<int8_t> &values) const {
    ExactDoubleSum result;
    result.add(field_.offset);
    for (const PotentialFactor &factor : field_.factors) {
      size_t row = 0;
      for (size_t position = 0; position < factor.local_indices.size();
           ++position) {
        const int8_t spin = values.at(factor.local_indices[position]);
        if (!spin)
          throw std::runtime_error("grouped joint-score complete model is partial");
        if (spin > 0)
          row |= size_t{1} << position;
      }
      result.add(factor.energies.at(row));
    }
    return result;
  }

  void refresh_group_maxima(const std::vector<size_t> &changed_locals) {
    std::vector<size_t> affected;
    for (const size_t local : changed_locals)
      affected.insert(affected.end(), incident_groups_.at(local).begin(),
                      incident_groups_.at(local).end());
    std::sort(affected.begin(), affected.end());
    affected.erase(std::unique(affected.begin(), affected.end()), affected.end());
    if (affected.empty())
      throw std::runtime_error("grouped joint-score update has no incident group");
    incremental_group_recomputations_ +=
        static_cast<int64_t>(affected.size());
    maximum_incremental_groups_recomputed_ =
        std::max(maximum_incremental_groups_recomputed_, affected.size());
    for (const size_t group_index : affected)
      group_maxima_.at(group_index) =
          group_maximum(groups_.at(group_index), assigned_);
  }

  void evaluate_current_bound(const std::vector<size_t> &changed_locals) {
    refresh_group_maxima(changed_locals);
    if (capacity_crossed_)
      return;
    const double upper = upper_from_cached_maxima();
    ++bound_checks_;
    minimum_upper_bound_ = std::min(minimum_upper_bound_, upper);
    maximum_upper_bound_ = std::max(maximum_upper_bound_, upper);
    if (upper < threshold_)
      queue_clause(assigned_, upper, false);
    else
      record_trace(upper, false, 0U);
  }

  void queue_clause(const std::vector<int8_t> &values, double score,
                    bool model_clause) {
    if (capacity_crossed_)
      throw std::runtime_error(
          "score-threshold clause queued after capacity crossing");
    if (pending_ready_ || blocking_active_)
      throw std::runtime_error(
          "grouped joint-score clause already blocks current trail");
    pending_clause_.clear();
    for (size_t local = 0; local < observed_.size(); ++local) {
      const int8_t spin = values.at(local);
      if (spin)
        pending_clause_.push_back(spin > 0 ? -observed_[local] : observed_[local]);
    }
    pending_cursor_ = 0;
    pending_ready_ = true;
    blocking_active_ = true;
    pending_witness_score_ = score;
    pending_model_clause_ = model_clause;
    ++threshold_prunes_;
    if (model_clause)
      ++model_threshold_prunes_;
    else
      ++trail_threshold_prunes_;
    ++external_clauses_queued_;
    external_clause_literals_ += static_cast<int64_t>(pending_clause_.size());
    if (!have_clause_length_) {
      minimum_clause_length_ = pending_clause_.size();
      have_clause_length_ = true;
    } else {
      minimum_clause_length_ =
          std::min(minimum_clause_length_, pending_clause_.size());
    }
    maximum_clause_length_ =
        std::max(maximum_clause_length_, pending_clause_.size());
    maximum_pending_clause_length_ =
        std::max(maximum_pending_clause_length_, pending_clause_.size());
    update_maximum_live_state();
    record_trace(score, true, pending_clause_.size());
  }

  void update_maximum_live_state() {
    const size_t live = observed_.size() + 8U + 8U * trail_.size() + 10U +
                        4U * pending_clause_.size();
    maximum_live_state_bytes_ = std::max(maximum_live_state_bytes_, live);
  }

  void record_trace(double upper, bool pruned, size_t clause_length) {
    std::string event;
    event.reserve(25U);
    append_u64_le(event, static_cast<uint64_t>(bound_checks_));
    append_u32_le(event, static_cast<uint32_t>(assigned_count_));
    uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(upper));
    std::memcpy(&bits, &upper, sizeof(bits));
    append_u64_le(event, bits);
    event.push_back(static_cast<char>(pruned ? 1 : 0));
    append_u32_le(event, static_cast<uint32_t>(clause_length));
    trace_.update(event);
  }

  size_t minimum_clause_length() const {
    return have_clause_length_ ? minimum_clause_length_ : 0U;
  }

  PotentialField field_;
  double threshold_;
  std::vector<int8_t> assigned_;
  std::vector<int> observed_;
  std::vector<CompatibilityGroup> groups_;
  std::vector<std::vector<size_t>> incident_groups_;
  std::vector<double> group_maxima_;
  std::vector<TrailEntry> trail_;
  size_t current_level_ = 0;
  std::vector<int> pending_clause_;
  size_t pending_cursor_ = 0;
  bool pending_ready_ = false;
  bool blocking_active_ = false;
  double pending_witness_score_ = 0.0;
  bool pending_model_clause_ = false;
  ScoreThresholdVault input_vault_;
  size_t validated_input_clause_count_ = 0;
  size_t validated_input_literal_count_ = 0;
  std::string validated_input_clause_aggregate_sha256_;
  std::vector<EmittedVaultClause> emitted_clauses_;
  std::set<std::string> current_new_clause_keys_;
  size_t fully_emitted_literal_count_ = 0;
  size_t emitted_new_clause_count_ = 0;
  size_t emitted_new_literal_count_ = 0;
  size_t emitted_new_serialized_bytes_ = 0;
  size_t emitted_input_duplicate_clause_count_ = 0;
  size_t emitted_input_duplicate_literal_count_ = 0;
  size_t emitted_current_duplicate_clause_count_ = 0;
  size_t emitted_current_duplicate_literal_count_ = 0;
  size_t terminal_empty_clause_count_ = 0;
  bool capacity_crossed_ = false;
  bool capacity_termination_armed_ = false;
  bool capacity_termination_grace_poll_seen_ = false;
  CaDiCaL::Solver *solver_ = nullptr;
  std::string observed_sha256_;
  std::string grouping_sha256_;
  std::string grouping_input_sha256_;
  size_t grouping_width_cap_ = 0;
  size_t grouping_serialized_bytes_ = 0;
  double root_upper_bound_ = 0.0;
  double minimum_upper_bound_ = 0.0;
  double maximum_upper_bound_ = 0.0;
  double minimum_complete_score_ = 0.0;
  double maximum_complete_score_ = 0.0;
  bool have_complete_score_ = false;
  bool have_clause_length_ = false;
  size_t pair_group_count_ = 0;
  size_t singleton_group_count_ = 0;
  size_t higher_order_group_count_ = 0;
  size_t maximum_group_size_ = 0;
  int64_t group_table_rows_ = 0;
  int64_t group_incident_edges_ = 0;
  int64_t assigned_count_ = 0;
  int64_t maximum_assigned_ = 0;
  size_t maximum_level_ = 0;
  size_t maximum_live_trail_entries_ = 0;
  size_t maximum_live_state_bytes_ = 0;
  int64_t assignment_callbacks_ = 0;
  int64_t assignment_literals_ = 0;
  int64_t new_decision_levels_ = 0;
  int64_t backtracks_ = 0;
  int64_t backtracked_assignments_ = 0;
  int64_t cb_decide_calls_ = 0;
  int64_t cb_propagate_calls_ = 0;
  int64_t cb_has_external_clause_calls_ = 0;
  int64_t bound_checks_ = 0;
  int64_t bound_additions_ = 0;
  int64_t incremental_group_recomputations_ = 0;
  size_t maximum_incremental_groups_recomputed_ = 0;
  int64_t group_maximum_evaluations_ = 0;
  int64_t group_row_evaluations_ = 0;
  int64_t threshold_prunes_ = 0;
  int64_t trail_threshold_prunes_ = 0;
  int64_t model_threshold_prunes_ = 0;
  int64_t external_clauses_queued_ = 0;
  int64_t external_clauses_emitted_ = 0;
  int64_t external_clause_literals_ = 0;
  size_t minimum_clause_length_ = 0;
  size_t maximum_clause_length_ = 0;
  size_t maximum_pending_clause_length_ = 0;
  int64_t model_checks_ = 0;
  int64_t complete_model_score_checks_ = 0;
  int64_t models_below_threshold_ = 0;
  int64_t models_at_or_above_threshold_ = 0;
  Sha256 trace_;
};

} // namespace

#ifndef O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN
int main(int argc, char **argv) {
  try {
    const GroupedArguments grouped_arguments =
        parse_grouped_arguments(argc, argv);
    const Arguments &arguments = grouped_arguments.base;
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");
    const std::string cnf_payload = read_binary_file(arguments.cnf_path, "CNF");
    const std::string potential_payload =
        read_binary_file(arguments.potential_path, "potential");
    const std::string grouping_payload =
        read_binary_file(grouped_arguments.grouping_path, "grouping");
    const std::string vault_payload =
        read_bounded_vault_file(grouped_arguments.vault_path);
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);

    std::unique_ptr<GroupedJointScoreSieveV6> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
          !solver.set("quiet", 1) || !solver.set("factor", 0) ||
          !solver.set("lucky", 0) || !solver.set("walk", 0) ||
          !solver.set("rephase", 0) || !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic search options");
      int variables = 0;
      if (const char *error =
              solver.read_dimacs(arguments.cnf_path.c_str(), variables, 2))
        throw std::runtime_error(std::string("DIMACS read failed: ") + error);
      if (variables < kKeyBits || variables > kMaximumVariables)
        throw std::runtime_error("DIMACS variable count differs");

      PotentialField field = parse_potential(potential_payload, variables);
      propagator = std::make_unique<GroupedJointScoreSieveV6>(
          std::move(field), grouping_payload, vault_payload, cnf_sha256,
          potential_sha256, arguments.threshold);
      propagator->attach_solver(&solver);
      for (const std::vector<int> &clause : propagator->preloaded_clauses()) {
        for (const int literal : clause)
          solver.add(literal);
        solver.add(0);
      }
      solver.connect_terminator(propagator.get());
      solver.connect_external_propagator(propagator.get());
      for (const int variable : propagator->observed())
        solver.add_observed_var(variable);
      if (!solver.limit("conflicts", arguments.conflict_limit))
        throw std::runtime_error("CaDiCaL rejected conflict limit");

      const int64_t conflicts_before_solve = statistic(solver, "conflicts");
      const auto started = std::chrono::steady_clock::now();
      const int status = solver.solve();
      const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - started);
      const CaDiCaL::State post_solve_state = solver.state();
      const int64_t conflicts = statistic(solver, "conflicts");
      if (conflicts < conflicts_before_solve)
        throw std::runtime_error("CaDiCaL conflict counter regressed");
      const int64_t solve_conflicts = conflicts - conflicts_before_solve;
      const int64_t decisions = statistic(solver, "decisions");
      const int64_t propagations = statistic(solver, "propagations");

      std::string model;
      if (status == 10) {
        if (post_solve_state != CaDiCaL::SATISFIED)
          throw std::runtime_error("CaDiCaL SAT terminal state differs");
        model = key_hex(solver);
      } else if (status == 20) {
        if (post_solve_state != CaDiCaL::UNSATISFIED)
          throw std::runtime_error("CaDiCaL UNSAT terminal state differs");
      } else if (status == 0) {
        if (post_solve_state != CaDiCaL::INCONCLUSIVE)
          throw std::runtime_error("CaDiCaL UNKNOWN terminal state differs");
      } else {
        throw std::runtime_error("CaDiCaL solve status differs");
      }

      std::ostringstream out;
      out << std::setprecision(std::numeric_limits<double>::max_digits10)
          << "{\"schema\":\"" << kGroupedSchema
          << "\",\"implementation_parent_schema\":\""
          << kImplementationParentSchema
          << "\",\"cadical_version\":\"" << CaDiCaL::Solver::version()
          << "\",\"variables\":" << variables
          << ",\"conflict_limit\":" << arguments.conflict_limit
          << ",\"seed\":" << arguments.seed << ",\"threshold\":"
          << arguments.threshold << ",\"status\":" << status
          << ",\"post_solve_state\":" << static_cast<int>(post_solve_state)
          << ",\"post_solve_state_name\":\"" << state_name(post_solve_state)
          << "\",\"teardown_rule\":\"" << kTeardownRule
          << "\",\"pending_backtrack_rule\":\"" << kPendingBacktrackRule
          << "\",\"key_model_hex\":";
      if (status == 10)
        out << '"' << model << '"';
      else
        out << "null";
      out << ",\"cnf_sha256\":\"" << cnf_sha256
          << "\",\"potential_sha256\":\"" << potential_sha256
          << "\",\"stats\":{\"conflicts\":" << conflicts
          << ",\"conflicts_before_solve\":" << conflicts_before_solve
          << ",\"solve_conflicts\":" << solve_conflicts
          << ",\"decisions\":" << decisions
          << ",\"propagations\":" << propagations << "},\"sieve\":{";
      propagator->write_json(out);
      out << "},\"vault\":{";
      propagator->write_vault_json(out);
      out << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
          << ",\"cpu_microseconds\":" << cpu_microseconds()
          << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
      result_json = out.str();
    }

    propagator.reset();
    std::cout << result_json;
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_joint_score_sieve_v6: " << error.what() << '\n';
    return 1;
  }
}
#endif
