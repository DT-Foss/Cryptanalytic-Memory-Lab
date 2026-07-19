// O1C-0072 one-shot backtrack-release ranked decision reader.
//
// The O1C-0071 rank derivation, table parser, and production seals are compiled
// unchanged.  This successor connects one new wrapper around frozen native v6.
// Its monotone cursor consumes every inspected rank row permanently: an
// already-assigned row is skipped, an unassigned row is returned once, and no
// backtrack can make a consumed row eligible again.
#define O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN
#include "cadical_o1_joint_score_sieve_v6.cpp"
#undef O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN

namespace {

// Frozen O1C-0071 rank-source, rank-table, and reader-specification surface.
constexpr const char *kRankOperator =
    "vault-suffix-vote-strength-then-singleton-grouped-bound-gap";
constexpr const char *kVoteRule =
    "delta(v)=count(+v)-count(-v);omit-delta-zero;omit-potential-unobserved";
constexpr const char *kRankBoundRule =
    "U+(v)=exact-width6-grouped-upper-bound(v=+1);"
    "U-(v)=exact-width6-grouped-upper-bound(v=-1);"
    "exact-binary64-lattice-factor-sum;round-once-positive-infinity;"
    "partial-group-maximum;exact-binary64-lattice-root-sum;"
    "round-once-positive-infinity";
constexpr const char *kGapRule =
    "gap(v)=abs(U+(v)-U-(v))-in-exact-binary64-lattice;"
    "round-once-positive-infinity;finite-input-bounds-required;positive-zero";
constexpr const char *kSortRule =
    "lexicographic:descending-abs-delta;descending-gap;ascending-variable";
constexpr const char *kLiteralRule = "literal(v)=sign(delta(v))*v";
constexpr const char *kOrderEncoding =
    "rank-order-concatenated-signed-i32le-literals";
constexpr const char *kTableEncoding =
    "rank-order-records:u32le-variable;i64le-delta;f64le-U+;f64le-U-;"
    "f64le-gap";
constexpr const char *kReturnedSequenceEncoding =
    "cb-decide-return-order-concatenated-signed-i32le-including-zero";
constexpr const char *kExpectedSpecSha256 =
    "974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543";
constexpr const char *kProductionOrderSha256 =
    "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5";
constexpr const char *kProductionTableSha256 =
    "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae";
constexpr const char *kProductionPotentialSourceSha256 =
    "b0ef8533128cbfdbb618c46b686bff0bc20f6b2389251b1ae5a2109729d34f26";
constexpr size_t kProductionRankRows = 255U;
constexpr size_t kProductionRankTableBytes = 9180U;
constexpr size_t kRankRecordBytes = 36U;
constexpr size_t kRankProductionSourceClauses = 202U;
constexpr size_t kRankProductionPrefixClauses = 12U;
constexpr size_t kRankProductionSuffixClauses = 190U;
constexpr size_t kRankProductionSuffixLiterals = 564667U;
constexpr const char *kRankProductionVaultSha256 =
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858";
constexpr const char *kRankProductionBaseVaultSha256 =
    "371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a";
constexpr const char *kRankProductionSuffixRecordsSha256 =
    "cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521";
constexpr const char *kRankProductionVoteFieldSha256 =
    "5d7fd1cfca56c1ab29f9e1490d28e16d3f5def611dad2f52c4ea4015678605fe";

constexpr std::string_view kRankSpec =
    "o1-vault-ranked-decision-v1\n"
    "inputs=canonical-vault-suffix-votes;canonical-public-potential;"
    "canonical-width6-grouping\n"
    "eligible=nonzero-vote-and-observed-by-potential\n"
    "delta(v)=count(+v)-count(-v)\n"
    "U+(v)=exact-width6-grouped-upper-bound-under-singleton-v=+1\n"
    "U-(v)=exact-width6-grouped-upper-bound-under-singleton-v=-1\n"
    "gap(v)=absolute-exact-binary64-lattice-difference-of-U+-and-U-;"
    "round-once-toward-positive-infinity;finite-bounds;positive-zero\n"
    "sort=descending-abs-delta;descending-gap;ascending-variable\n"
    "literal(v)=sign(delta(v))*v\n"
    "order-encoding=concatenated-signed-i32le-literals-in-rank-order\n"
    "table-encoding=rank-order-u32le-variable,i64le-delta,f64le-U+,"
    "f64le-U-,f64le-gap\n";

struct RankVoteField {
  std::array<int64_t, kKeyBits> delta{};
  std::string source_vault_sha256;
  std::string suffix_canonical_records_sha256;
  std::string field_sha256;
};

RankVoteField derive_rank_vote_field(const std::string &payload,
                                     size_t clause_start,
                                     size_t clause_stop,
                                     bool require_production_seal) {
  if (payload.size() < kVaultMinimumBytes ||
      std::string_view(payload.data(), kVaultMagic.size()) != kVaultMagic)
    throw std::runtime_error("rank vote-field vault header differs");
  RankVoteField result;
  result.source_vault_sha256 = sha256(payload);
  if (require_production_seal &&
      result.source_vault_sha256 != kRankProductionVaultSha256)
    throw std::runtime_error("rank vote-field source vault differs");
  size_t cursor = kVaultIdentityPrefixBytes;
  const uint32_t clause_count =
      read_u32_le(payload, cursor, "rank vote-field clause count");
  if (clause_start > clause_stop || clause_stop > clause_count)
    throw std::runtime_error("rank vote-field clause slice differs");
  std::array<int64_t, kKeyBits> positive{};
  std::array<int64_t, kKeyBits> negative{};
  std::string prefix_records;
  std::string suffix_records;
  std::set<std::string> seen;
  size_t suffix_literals = 0;
  for (size_t clause_index = 0; clause_index < clause_count; ++clause_index) {
    const size_t record_start = cursor;
    const uint32_t length =
        read_u32_le(payload, cursor, "rank vote-field clause length");
    if (!length || cursor > payload.size() ||
        static_cast<size_t>(length) > (payload.size() - cursor) / 4U)
      throw std::runtime_error("rank vote-field clause length differs");
    int64_t previous_absolute = 0;
    for (uint32_t literal_index = 0; literal_index < length;
         ++literal_index) {
      const int32_t literal =
          read_i32_le(payload, cursor, "rank vote-field literal");
      if (!literal || literal == std::numeric_limits<int32_t>::min())
        throw std::runtime_error("rank vote-field literal differs");
      const int64_t absolute =
          literal < 0 ? -static_cast<int64_t>(literal) : literal;
      if (absolute <= previous_absolute || absolute > kMaximumVariables)
        throw std::runtime_error("rank vote-field literal order differs");
      previous_absolute = absolute;
      if (clause_index >= clause_start && clause_index < clause_stop &&
          absolute <= static_cast<int64_t>(kKeyBits)) {
        auto &counts = literal > 0 ? positive : negative;
        ++counts.at(static_cast<size_t>(absolute - 1));
      }
    }
    const std::string record =
        payload.substr(record_start, cursor - record_start);
    if (!seen.insert(record).second)
      throw std::runtime_error("rank vote-field duplicate clause differs");
    if (clause_index < clause_start)
      prefix_records += record;
    if (clause_index >= clause_start && clause_index < clause_stop) {
      suffix_records += record;
      suffix_literals += length;
    }
  }
  if (cursor != payload.size())
    throw std::runtime_error("rank vote-field trailing bytes differ");
  std::string base_payload = payload.substr(0, kVaultIdentityPrefixBytes);
  append_u32_le(base_payload, static_cast<uint32_t>(clause_start));
  base_payload += prefix_records;
  result.suffix_canonical_records_sha256 = sha256(suffix_records);
  std::string field_bytes;
  field_bytes.reserve(4U * kKeyBits);
  size_t positive_phases = 0;
  size_t negative_phases = 0;
  std::vector<int> zero_variables;
  for (int variable = 1; variable <= static_cast<int>(kKeyBits); ++variable) {
    const size_t index = static_cast<size_t>(variable - 1);
    result.delta[index] = positive[index] - negative[index];
    const int literal = result.delta[index] > 0
                            ? variable
                            : result.delta[index] < 0 ? -variable : 0;
    append_u32_le(field_bytes,
                  static_cast<uint32_t>(static_cast<int32_t>(literal)));
    if (literal > 0)
      ++positive_phases;
    else if (literal < 0)
      ++negative_phases;
    else
      zero_variables.push_back(variable);
  }
  result.field_sha256 = sha256(field_bytes);
  if (require_production_seal &&
      (clause_count != kRankProductionSourceClauses ||
       clause_start != kRankProductionPrefixClauses ||
       clause_stop != kRankProductionSourceClauses ||
       clause_stop - clause_start != kRankProductionSuffixClauses ||
       suffix_literals != kRankProductionSuffixLiterals ||
       sha256(base_payload) != kRankProductionBaseVaultSha256 ||
       result.suffix_canonical_records_sha256 !=
           kRankProductionSuffixRecordsSha256 ||
       result.field_sha256 != kRankProductionVoteFieldSha256 ||
       positive_phases != 139U || negative_phases != 116U ||
       zero_variables != std::vector<int>{241}))
    throw std::runtime_error("sealed O1C71 rank vote field differs");
  return result;
}

struct RankedArguments {
  GroupedArguments grouped;
  std::string rank_table_path;
};

RankedArguments parse_ranked_arguments(int argc, char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string rank_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("ranked arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--rank-table") {
      if (!rank_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("rank-table argument differs");
      rank_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (rank_path.empty())
    throw std::runtime_error("rank-table argument is missing");
  RankedArguments result;
  result.grouped = parse_grouped_arguments(
      static_cast<int>(filtered.size()), filtered.data());
  result.rank_table_path = std::move(rank_path);
  return result;
}

int64_t signed_i64(uint64_t bits) {
  int64_t value = 0;
  static_assert(sizeof(value) == sizeof(bits));
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

double binary64(uint64_t bits) {
  double value = 0.0;
  static_assert(sizeof(value) == sizeof(bits));
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

double canonical_rank_gap(double first, double second) {
  if (!std::isfinite(first) || !std::isfinite(second))
    throw std::runtime_error("rank-table bound differs");
  const double high = std::max(first, second);
  const double low = std::min(first, second);
  ExactDoubleSum exact;
  exact.add(high);
  exact.add(low, true);
  if (exact.compare_zero() < 0)
    throw std::runtime_error("rank-table gap differs");
  if (!exact.compare_zero())
    return 0.0;
  double rounded = exact.rounded();
  ExactDoubleSum remainder;
  remainder.add(high);
  remainder.add(low, true);
  remainder.add(rounded, true);
  if (remainder.compare_zero() > 0)
    rounded =
        std::nextafter(rounded, std::numeric_limits<double>::infinity());
  if (!std::isfinite(rounded) || rounded < 0.0)
    throw std::runtime_error("rank-table gap differs");
  return rounded == 0.0 ? 0.0 : rounded;
}

struct RankRow {
  int variable = 0;
  int64_t delta = 0;
  double upper_positive = 0.0;
  double upper_negative = 0.0;
  double gap = 0.0;
  int literal = 0;
  size_t local = 0;
};

struct RankTable {
  std::vector<RankRow> rows;
  std::vector<int> literals;
  std::string payload;
  std::string payload_sha256;
  std::string order_bytes;
  std::string order_sha256;
};

bool rank_precedes(const RankRow &left, const RankRow &right) {
  const uint64_t left_magnitude =
      left.delta < 0 ? static_cast<uint64_t>(-(left.delta + 1)) + 1U
                     : static_cast<uint64_t>(left.delta);
  const uint64_t right_magnitude =
      right.delta < 0 ? static_cast<uint64_t>(-(right.delta + 1)) + 1U
                      : static_cast<uint64_t>(right.delta);
  if (left_magnitude != right_magnitude)
    return left_magnitude > right_magnitude;
  if (left.gap != right.gap)
    return left.gap > right.gap;
  return left.variable < right.variable;
}

RankTable parse_rank_table(const std::string &payload,
                           const RankVoteField &vote_field,
                           bool require_production_seal) {
  if (payload.empty() || payload.size() % kRankRecordBytes ||
      payload.size() > kKeyBits * kRankRecordBytes)
    throw std::runtime_error("rank-table size differs");
  RankTable result;
  result.payload = payload;
  result.payload_sha256 = sha256(payload);
  std::set<int> seen;
  size_t cursor = 0;
  while (cursor < payload.size()) {
    RankRow row;
    const uint32_t variable =
        read_u32_le(payload, cursor, "rank variable");
    const int64_t delta =
        signed_i64(read_u64_le(payload, cursor, "rank delta"));
    const double upper_positive =
        binary64(read_u64_le(payload, cursor, "rank positive bound"));
    const double upper_negative =
        binary64(read_u64_le(payload, cursor, "rank negative bound"));
    const double gap =
        binary64(read_u64_le(payload, cursor, "rank gap"));
    if (!variable || variable > kKeyBits || !delta ||
        !std::isfinite(upper_positive) || !std::isfinite(upper_negative) ||
        !std::isfinite(gap) || gap < 0.0 ||
        f64_bits(gap) !=
            f64_bits(canonical_rank_gap(upper_positive, upper_negative)) ||
        !seen.insert(static_cast<int>(variable)).second ||
        vote_field.delta.at(static_cast<size_t>(variable - 1U)) != delta)
      throw std::runtime_error("rank-table row differs");
    row.variable = static_cast<int>(variable);
    row.delta = delta;
    row.upper_positive = upper_positive;
    row.upper_negative = upper_negative;
    row.gap = gap;
    row.literal = delta > 0 ? row.variable : -row.variable;
    if (!result.rows.empty() && !rank_precedes(result.rows.back(), row))
      throw std::runtime_error("rank-table order differs");
    result.rows.push_back(row);
    result.literals.push_back(row.literal);
    append_u32_le(result.order_bytes,
                  static_cast<uint32_t>(static_cast<int32_t>(row.literal)));
  }
  result.order_sha256 = sha256(result.order_bytes);
  if (require_production_seal &&
      (result.rows.size() != kProductionRankRows ||
       result.payload.size() != kProductionRankTableBytes ||
       result.payload_sha256 != kProductionTableSha256 ||
       result.order_sha256 != kProductionOrderSha256))
    throw std::runtime_error("sealed O1C71 rank table differs");
  return result;
}

constexpr const char *kV11ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v11";
constexpr const char *kV11ImplementationParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v6";
constexpr const char *kReleaseReaderSchema =
    "o1-256-cadical-vault-backtrack-release-ranked-decision-reader-v1";
constexpr const char *kExpectedReleasePolicySpecSha256 =
    "bfa752664e19d5899d114ee8cf75dd15a52a8306ff2399fde046a5bb6ebdc132";
constexpr std::string_view kReleasePolicySpec =
    "o1-vault-backtrack-release-ranked-decision-reader-v1\n"
    "rank-spec-sha256="
    "974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543\n"
    "rank-order=immutable\n"
    "cursor=monotone-rank-index;consume-before-return-or-skip\n"
    "assigned-row=consume-and-skip-permanently\n"
    "unassigned-row=consume-and-return-signed-rank-literal-at-most-once\n"
    "backtrack=never-decrement-cursor;released-guided-literal-never-reasserted\n"
    "fallback=zero-after-rank-exhaustion\n"
    "phase-calls=0\n"
    "state=u32le-cursor;three-256-bit-rank-index-bitsets;"
    "bounded-once-return-and-release-sequences\n";
constexpr const char *kReleaseDecisionRule =
    "immutable-rank-monotone-consume;return-each-ranked-literal-at-most-once;"
    "assigned-before-opportunity-consumed;zero-after-none";
constexpr const char *kReleaseCallbackRule =
    "reuse-v6-assignment-backtrack-state;scan-from-monotone-rank-cursor;"
    "consume-assigned-ranked-rows;consume-before-nonzero-return;"
    "never-unconsume-on-backtrack;zero-delegates-to-solver";
constexpr const char *kConsumedStateEncoding =
    "rank-index-bitset-lsb-first-32-bytes";
constexpr const char *kOnceReturnSequenceEncoding =
    "callback-nonzero-return-order-concatenated-signed-i32le";
constexpr const char *kGuidedReleaseSequenceEncoding =
    "backtrack-callback-order;within-callback-immutable-rank-order;"
    "concatenated-signed-i32le";
constexpr const char *kBoundedReleaseStateRule =
    "u32le-monotone-cursor;three-256-bit-rank-index-bitsets;"
    "at-most-rank-rows-once-return-and-guided-release-i32le-sequences;"
    "independent-of-callback-count";
constexpr size_t kRankBitsetBytes = kKeyBits / 8U;

bool rank_bit(const std::string &bits, size_t index) {
  if (bits.size() != kRankBitsetBytes || index >= kKeyBits)
    throw std::runtime_error("backtrack-release rank bit index differs");
  return (static_cast<unsigned char>(bits[index / 8U]) >> (index % 8U)) &
         1U;
}

void set_rank_bit(std::string &bits, size_t index) {
  if (rank_bit(bits, index))
    throw std::runtime_error("backtrack-release rank bit was already set");
  bits[index / 8U] = static_cast<char>(
      static_cast<unsigned char>(bits[index / 8U]) |
      static_cast<unsigned char>(1U << (index % 8U)));
}

size_t count_rank_bits(const std::string &bits) {
  if (bits.size() != kRankBitsetBytes)
    throw std::runtime_error("backtrack-release rank bitset size differs");
  size_t result = 0;
  for (const unsigned char byte : bits)
    result += static_cast<size_t>(__builtin_popcount(byte));
  return result;
}

class BacktrackReleaseGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  BacktrackReleaseGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold, RankTable rank,
      RankVoteField vote_field, std::string potential_source_sha256)
      : base_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
              potential_sha256, threshold),
        rank_(std::move(rank)), vote_field_(std::move(vote_field)),
        potential_sha256_(potential_sha256),
        potential_source_sha256_(std::move(potential_source_sha256)),
        grouping_sha256_(sha256(grouping_payload)),
        consumed_state_(kRankBitsetBytes, '\0'),
        returned_state_(kRankBitsetBytes, '\0'),
        released_state_(kRankBitsetBytes, '\0') {
    const std::vector<int> &observed = base_.observed();
    std::set<int> eligible;
    for (int variable = 1; variable <= static_cast<int>(kKeyBits); ++variable) {
      const int64_t delta =
          vote_field_.delta.at(static_cast<size_t>(variable - 1));
      const bool is_observed =
          std::binary_search(observed.begin(), observed.end(), variable);
      if (!delta)
        zero_delta_variables_.push_back(variable);
      else if (!is_observed)
        unobserved_nonzero_variables_.push_back(variable);
      else
        eligible.insert(variable);
    }
    if (eligible.size() != rank_.rows.size())
      throw std::runtime_error(
          "backtrack-release rank eligible population differs");
    for (RankRow &row : rank_.rows) {
      if (!eligible.erase(row.variable))
        throw std::runtime_error(
            "backtrack-release rank observed population differs");
      const auto iterator =
          std::lower_bound(observed.begin(), observed.end(), row.variable);
      if (iterator == observed.end() || *iterator != row.variable)
        throw std::runtime_error(
            "backtrack-release rank variable is unobserved");
      row.local = static_cast<size_t>(iterator - observed.begin());
    }
    if (!eligible.empty())
      throw std::runtime_error(
          "backtrack-release rank omits eligible variable");
  }

  void notify_assignment(const std::vector<int> &literals) override {
    base_.notify_assignment(literals);
  }

  void notify_new_decision_level() override {
    base_.notify_new_decision_level();
  }

  void notify_backtrack(size_t new_level) override {
    const std::string before = base_.assignment_state();
    base_.notify_backtrack(new_level);
    const std::string after = base_.assignment_state();
    if (before.size() != base_.observed().size() ||
        after.size() != before.size())
      throw std::runtime_error(
          "backtrack-release assignment snapshot differs");
    for (size_t index = 0; index < rank_.rows.size(); ++index) {
      const RankRow &row = rank_.rows[index];
      if (!rank_bit(returned_state_, index) ||
          rank_bit(released_state_, index) || !before[row.local] ||
          after[row.local])
        continue;
      const int before_literal = before[row.local] > 0
                                     ? row.variable
                                     : -row.variable;
      if (before_literal != row.literal)
        throw std::runtime_error(
            "backtrack-release guided assignment sign differs");
      set_rank_bit(released_state_, index);
      append_u32_le(guided_release_sequence_,
                    static_cast<uint32_t>(
                        static_cast<int32_t>(row.literal)));
      ++released_guided_;
    }
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return base_.cb_check_found_model(model);
  }

  int cb_decide() override {
    if (base_.cb_decide() != 0)
      throw std::runtime_error(
          "implementation-parent decision callback differs");
    if (cb_decide_calls_ == std::numeric_limits<int64_t>::max())
      throw std::runtime_error(
          "backtrack-release decision callback count exceeds bound");
    ++cb_decide_calls_;
    const std::string assignment = base_.assignment_state();
    if (assignment.size() != base_.observed().size())
      throw std::runtime_error(
          "backtrack-release assignment projection differs");

    int result = 0;
    while (cursor_ < rank_.rows.size()) {
      const size_t index = cursor_++;
      const RankRow &row = rank_.rows[index];
      if (rank_bit(consumed_state_, index))
        throw std::runtime_error(
            "backtrack-release cursor revisited a consumed row");
      set_rank_bit(consumed_state_, index);
      ++rows_consumed_;
      if (row.local >= assignment.size())
        throw std::runtime_error(
            "backtrack-release rank projection differs");
      if (assignment[row.local]) {
        ++skipped_preassigned_;
        continue;
      }
      set_rank_bit(returned_state_, index);
      ++once_returns_;
      result = row.literal;
      append_u32_le(once_return_sequence_,
                    static_cast<uint32_t>(static_cast<int32_t>(result)));
      break;
    }

    std::string encoded;
    encoded.reserve(4U);
    append_u32_le(encoded,
                  static_cast<uint32_t>(static_cast<int32_t>(result)));
    callback_return_sha256_.update(encoded);
    if (!result) {
      ++cb_decide_zero_;
      if (!first_fallback_call_)
        first_fallback_call_ = cb_decide_calls_;
    }
    return result;
  }

  int cb_propagate() override { return base_.cb_propagate(); }

  int cb_add_reason_clause_lit(int propagated_literal) override {
    return base_.cb_add_reason_clause_lit(propagated_literal);
  }

  bool terminate() override { return base_.terminate(); }

  bool cb_has_external_clause(bool &forgettable) override {
    return base_.cb_has_external_clause(forgettable);
  }

  int cb_add_external_clause_lit() override {
    return base_.cb_add_external_clause_lit();
  }

  const std::vector<int> &observed() const { return base_.observed(); }

  const std::vector<std::vector<int>> &preloaded_clauses() const {
    return base_.preloaded_clauses();
  }

  void attach_solver(CaDiCaL::Solver *solver) { base_.attach_solver(solver); }

  void write_json(std::ostream &out) const { base_.write_json(out); }

  void write_vault_json(std::ostream &out) const {
    base_.write_vault_json(out);
  }

  void write_reader_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kReleaseReaderSchema
        << "\",\"operator\":\"" << kRankOperator
        << "\",\"source_vault_sha256\":\""
        << vote_field_.source_vault_sha256
        << "\",\"suffix_canonical_records_sha256\":\""
        << vote_field_.suffix_canonical_records_sha256
        << "\",\"vote_field_sha256\":\"" << vote_field_.field_sha256
        << "\",\"potential_sha256\":\"" << potential_sha256_
        << "\",\"potential_source_sha256\":\""
        << potential_source_sha256_ << "\",\"grouping_sha256\":\""
        << grouping_sha256_ << "\",\"grouping_width_cap\":6"
        << ",\"key_variable_count\":" << kKeyBits
        << ",\"observed_variable_count\":" << observed().size()
        << ",\"candidate_count\":" << rank_.rows.size()
        << ",\"zero_delta_count\":" << zero_delta_variables_.size()
        << ",\"unobserved_nonzero_count\":"
        << unobserved_nonzero_variables_.size() << ",\"vote_rule\":\""
        << kVoteRule << "\",\"bound_rule\":\"" << kRankBoundRule
        << "\",\"gap_rule\":\"" << kGapRule << "\",\"sort_rule\":\""
        << kSortRule << "\",\"literal_rule\":\"" << kLiteralRule
        << "\",\"reader_spec_bytes\":" << kRankSpec.size()
        << ",\"reader_spec_sha256\":\"" << kExpectedSpecSha256
        << "\",\"release_policy_spec_bytes\":"
        << kReleasePolicySpec.size()
        << ",\"release_policy_spec_sha256\":\""
        << kExpectedReleasePolicySpecSha256
        << "\",\"order_encoding\":\"" << kOrderEncoding
        << "\",\"ranked_literals\":[";
    for (size_t index = 0; index < rank_.literals.size(); ++index) {
      if (index)
        out << ',';
      out << rank_.literals[index];
    }
    out << "],\"order_bytes\":" << rank_.order_bytes.size()
        << ",\"order_sha256\":\"" << rank_.order_sha256
        << "\",\"rank_table_encoding\":\"" << kTableEncoding
        << "\",\"rank_table_rows\":" << rank_.rows.size()
        << ",\"rank_table_bytes\":" << rank_.payload.size()
        << ",\"rank_table_sha256\":\"" << rank_.payload_sha256
        << "\",\"decision_rule\":\"" << kReleaseDecisionRule
        << "\",\"callback_rule\":\"" << kReleaseCallbackRule
        << "\",\"cursor\":" << cursor_
        << ",\"rows_consumed\":" << rows_consumed_
        << ",\"once_returns\":" << once_returns_
        << ",\"skipped_preassigned\":" << skipped_preassigned_
        << ",\"consumed_state_bits\":" << kKeyBits
        << ",\"consumed_state_bytes\":" << consumed_state_.size()
        << ",\"consumed_state_encoding\":\"" << kConsumedStateEncoding
        << "\",\"consumed_state_hex\":\"" << bytes_hex(consumed_state_)
        << "\",\"consumed_state_sha256\":\"" << sha256(consumed_state_)
        << "\",\"returned_state_bits\":" << kKeyBits
        << ",\"returned_state_bytes\":" << returned_state_.size()
        << ",\"returned_state_encoding\":\"" << kConsumedStateEncoding
        << "\",\"returned_state_hex\":\"" << bytes_hex(returned_state_)
        << "\",\"returned_state_sha256\":\"" << sha256(returned_state_)
        << "\",\"released_state_bits\":" << kKeyBits
        << ",\"released_state_bytes\":" << released_state_.size()
        << ",\"released_state_encoding\":\"" << kConsumedStateEncoding
        << "\",\"released_state_hex\":\"" << bytes_hex(released_state_)
        << "\",\"released_state_sha256\":\"" << sha256(released_state_)
        << "\",\"once_return_sequence_encoding\":\""
        << kOnceReturnSequenceEncoding
        << "\",\"once_return_sequence_count\":" << once_returns_
        << ",\"once_return_sequence_bytes\":" << once_return_sequence_.size()
        << ",\"once_return_sequence_hex\":\""
        << bytes_hex(once_return_sequence_)
        << "\",\"once_return_sequence_sha256\":\""
        << sha256(once_return_sequence_) << "\",\"released_guided\":"
        << released_guided_ << ",\"guided_release_sequence_encoding\":\""
        << kGuidedReleaseSequenceEncoding
        << "\",\"guided_release_sequence_count\":" << released_guided_
        << ",\"guided_release_sequence_bytes\":"
        << guided_release_sequence_.size()
        << ",\"guided_release_sequence_hex\":\""
        << bytes_hex(guided_release_sequence_)
        << "\",\"guided_release_sequence_sha256\":\""
        << sha256(guided_release_sequence_)
        << "\",\"cb_decide_calls\":" << cb_decide_calls_
        << ",\"cb_decide_nonzero\":" << once_returns_
        << ",\"cb_decide_zero\":" << cb_decide_zero_
        << ",\"returned_sequence_encoding\":\""
        << kReturnedSequenceEncoding << "\",\"returned_sequence_count\":"
        << cb_decide_calls_ << ",\"returned_sequence_bytes\":"
        << 4U * static_cast<uint64_t>(cb_decide_calls_)
        << ",\"returned_sequence_hex\":\"" << bytes_hex(once_return_sequence_);
    for (int64_t index = 0; index < cb_decide_zero_; ++index)
      out << "00000000";
    out << "\",\"returned_sequence_sha256\":\""
        << callback_return_sha256_.hex_digest()
        << "\",\"unique_returned_variables\":" << once_returns_
        << ",\"redecisions\":0,\"first_fallback_call\":";
    if (first_fallback_call_)
      out << first_fallback_call_;
    else
      out << "null";
    out << ",\"solver_phase_calls\":0,\"bounded_state_rule\":\""
        << kBoundedReleaseStateRule
        << "\",\"bounded_guidance_state_bytes\":"
        << 4U + 3U * kRankBitsetBytes + 8U * rank_.rows.size()
        << ",\"live_guidance_state_bytes\":"
        << 4U + 3U * kRankBitsetBytes + once_return_sequence_.size() +
               guided_release_sequence_.size();
  }

private:
  void validate_telemetry() const {
    if (cursor_ > rank_.rows.size() || rows_consumed_ != cursor_ ||
        rows_consumed_ != once_returns_ + skipped_preassigned_ ||
        static_cast<uint64_t>(cb_decide_calls_) !=
            once_returns_ + static_cast<uint64_t>(cb_decide_zero_) ||
        once_return_sequence_.size() != 4U * once_returns_ ||
        guided_release_sequence_.size() != 4U * released_guided_ ||
        released_guided_ > once_returns_ ||
        count_rank_bits(consumed_state_) != rows_consumed_ ||
        count_rank_bits(returned_state_) != once_returns_ ||
        count_rank_bits(released_state_) != released_guided_)
      throw std::runtime_error(
          "backtrack-release reader telemetry differs");
    if ((!cb_decide_zero_ && first_fallback_call_) ||
        (cb_decide_zero_ &&
         (cursor_ != rank_.rows.size() ||
          static_cast<uint64_t>(first_fallback_call_) !=
              once_returns_ + 1U)))
      throw std::runtime_error(
          "backtrack-release fallback telemetry differs");

    std::string expected_returns;
    expected_returns.reserve(4U * once_returns_);
    for (size_t index = 0; index < rank_.rows.size(); ++index) {
      const bool consumed = rank_bit(consumed_state_, index);
      const bool returned = rank_bit(returned_state_, index);
      const bool released = rank_bit(released_state_, index);
      if (consumed != (index < cursor_) || (returned && !consumed) ||
          (released && !returned))
        throw std::runtime_error(
            "backtrack-release rank-state subset differs");
      if (returned)
        append_u32_le(expected_returns,
                      static_cast<uint32_t>(static_cast<int32_t>(
                          rank_.rows[index].literal)));
    }
    if (expected_returns != once_return_sequence_)
      throw std::runtime_error(
          "backtrack-release once-return order differs");

    std::set<int> released_literals;
    size_t release_cursor = 0;
    while (release_cursor < guided_release_sequence_.size()) {
      const int literal = read_i32_le(guided_release_sequence_, release_cursor,
                                      "guided release literal");
      const auto row = std::find_if(
          rank_.rows.begin(), rank_.rows.end(),
          [literal](const RankRow &candidate) {
            return candidate.literal == literal;
          });
      if (row == rank_.rows.end() ||
          !rank_bit(released_state_,
                    static_cast<size_t>(row - rank_.rows.begin())) ||
          !released_literals.insert(literal).second)
        throw std::runtime_error(
            "backtrack-release guided-release sequence differs");
    }
  }

  GroupedJointScoreSieveV6 base_;
  RankTable rank_;
  RankVoteField vote_field_;
  std::string potential_sha256_;
  std::string potential_source_sha256_;
  std::string grouping_sha256_;
  std::vector<int> zero_delta_variables_;
  std::vector<int> unobserved_nonzero_variables_;
  size_t cursor_ = 0;
  size_t rows_consumed_ = 0;
  size_t once_returns_ = 0;
  size_t skipped_preassigned_ = 0;
  size_t released_guided_ = 0;
  int64_t cb_decide_calls_ = 0;
  int64_t cb_decide_zero_ = 0;
  int64_t first_fallback_call_ = 0;
  std::string consumed_state_;
  std::string returned_state_;
  std::string released_state_;
  std::string once_return_sequence_;
  std::string guided_release_sequence_;
  Sha256 callback_return_sha256_;
};

void print_v11_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v11 --cnf PATH "
               "--potential PATH --grouping PATH --vault-in PATH "
               "--rank-table PATH --threshold FLOAT --conflict-limit N "
               "[--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v11_usage();
      return 0;
    }
    const RankedArguments ranked_arguments = parse_ranked_arguments(argc, argv);
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error(
          "vault-ranked backtrack-release reader requires seed zero");
    if (kRankSpec.size() != 674U ||
        sha256(kRankSpec) != kExpectedSpecSha256 ||
        kReleasePolicySpec.size() != 540U ||
        sha256(kReleasePolicySpec) != kExpectedReleasePolicySpecSha256)
      throw std::runtime_error(
          "vault-ranked backtrack-release reader specification differs");
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");

    const std::string cnf_payload =
        read_binary_file(arguments.cnf_path, "CNF");
    const std::string potential_payload =
        read_binary_file(arguments.potential_path, "potential");
    const std::string grouping_payload =
        read_binary_file(grouped_arguments.grouping_path, "grouping");
    const std::string vault_payload =
        read_bounded_vault_file(grouped_arguments.vault_path);
    const std::string rank_payload =
        read_binary_file(ranked_arguments.rank_table_path, "rank table");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);

#ifdef O1_CRYPTO_LAB_O1C72_PUBLIC_FIXTURE
    size_t fixture_cursor = kVaultIdentityPrefixBytes;
    const size_t vote_stop = read_u32_le(
        vault_payload, fixture_cursor, "fixture vault clause count");
    constexpr size_t vote_start = 0U;
    constexpr bool production_seal = false;
#else
    constexpr size_t vote_start = kRankProductionPrefixClauses;
    constexpr size_t vote_stop = kRankProductionSourceClauses;
    constexpr bool production_seal = true;
#endif
    RankVoteField vote_field = derive_rank_vote_field(
        vault_payload, vote_start, vote_stop, production_seal);
    RankTable rank =
        parse_rank_table(rank_payload, vote_field, production_seal);

    std::unique_ptr<BacktrackReleaseGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") ||
          !solver.set("seed", arguments.seed) || !solver.set("quiet", 1) ||
          !solver.set("factor", 0) || !solver.set("lucky", 0) ||
          !solver.set("walk", 0) || !solver.set("rephase", 0) ||
          !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic backtrack-release options");
      int variables = 0;
      if (const char *error =
              solver.read_dimacs(arguments.cnf_path.c_str(), variables, 2))
        throw std::runtime_error(std::string("DIMACS read failed: ") + error);
      if (variables < static_cast<int>(kKeyBits) ||
          variables > kMaximumVariables)
        throw std::runtime_error("DIMACS variable count differs");

      PotentialField field = parse_potential(potential_payload, variables);
      const std::string potential_source_sha256 = field.source_sha256;
      if (production_seal &&
          potential_source_sha256 != kProductionPotentialSourceSha256)
        throw std::runtime_error("sealed potential source differs");
      propagator =
          std::make_unique<BacktrackReleaseGroupedJointScoreSieve>(
              std::move(field), grouping_payload, vault_payload, cnf_sha256,
              potential_sha256, arguments.threshold, std::move(rank),
              std::move(vote_field), potential_source_sha256);
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
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::microseconds>(
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
          << "{\"schema\":\"" << kV11ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV11ImplementationParentSchema << "\",\"reader\":{";
      propagator->write_reader_json(out);
      out << "},\"cadical_version\":\"" << CaDiCaL::Solver::version()
          << "\",\"variables\":" << variables
          << ",\"conflict_limit\":" << arguments.conflict_limit
          << ",\"seed\":" << arguments.seed << ",\"threshold\":"
          << arguments.threshold << ",\"status\":" << status
          << ",\"post_solve_state\":" << static_cast<int>(post_solve_state)
          << ",\"post_solve_state_name\":\""
          << state_name(post_solve_state) << "\",\"teardown_rule\":\""
          << kTeardownRule << "\",\"pending_backtrack_rule\":\""
          << kPendingBacktrackRule << "\",\"key_model_hex\":";
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
    std::cerr << "cadical_o1_joint_score_sieve_v11: " << error.what()
              << '\n';
    return 1;
  }
}
