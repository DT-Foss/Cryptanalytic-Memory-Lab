// O1C-0073 bounded opposite-on-release contrast reader.
//
// Native v11 remains byte-for-byte frozen.  This translation unit compiles it
// under a private entry-point name and composes its exact consume-once reader.
// Once v11 delegates with zero, a genuinely released original literal may
// contribute its opposite exactly once, in release order, while unassigned.
#include <cadical.hpp>

#include <sys/resource.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <streambuf>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef O1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C72_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C73_UNDEF_O1C72_FIXTURE
#endif
namespace o1c72_embedded {
#include "cadical_o1_joint_score_sieve_v11.cpp"
} // namespace o1c72_embedded
#ifdef O1_CRYPTO_LAB_O1C73_UNDEF_O1C72_FIXTURE
#undef O1_CRYPTO_LAB_O1C72_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C73_UNDEF_O1C72_FIXTURE
#endif

using namespace o1c72_embedded;

namespace {

constexpr const char *kV12ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v12";
constexpr const char *kV12ImplementationParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v6";
constexpr const char *kV12ReleaseParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v11";
constexpr const char *kContrastReaderSchema =
    "o1-256-cadical-vault-release-contrast-ranked-decision-reader-v1";
constexpr const char *kContrastOperator =
    "vault-ranked-once-then-released-opposite-once";
constexpr const char *kContrastDecisionRule =
    "v11-original-first;after-rank-exhaustion-earliest-released-currently-"
    "unassigned-opposite-once;zero-delegates";
constexpr const char *kContrastCallbackRule =
    "preserve-v11-monotone-consume-once;enqueue-first-real-original-release;"
    "bounded-scan-defer-assigned;never-repeat-signed-literal";
constexpr const char *kContrastStateEncoding =
    "256-bits-lsb-first-by-rank-index";
constexpr const char *kContrastSequenceEncoding =
    "concatenated-signed-i32le-literals-in-observation-order";
constexpr const char *kNonzeroEventRule =
    "bounded-at-most-510-events;one-record-per-nonzero-callback;"
    "assignment-burst-finalized-at-next-cb-decide";
constexpr const char *kPairRecordRule =
    "bounded-at-most-255-original-returned-rank-records;callback-ordinals-"
    "one-based;release-after-call-and-new-level";
constexpr const char *kBoundedContrastStateRule =
    "six-256-bit-rank-bitsets;bounded-u16-release-order;bounded-510-nonzero-"
    "events;bounded-255-pair-records;one-256-bit-deferred-assignment-telemetry;"
    "incremental-all-callback-sha256";

constexpr std::string_view kContrastPolicySpec =
    "o1-vault-release-contrast-v1\n"
    "parent=o1-vault-backtrack-release-ranked-decision-v1\n"
    "original=monotone-rank-consume-once;assigned-rows-consumed-and-skipped\n"
    "enqueue=on-first-real-release-of-original-returned-signed-literal\n"
    "contrast=after-original-rank-exhaustion;earliest-release-order-currently-"
    "unassigned;return-exact-opposite-once\n"
    "defer=assigned-enqueued-row-remains-pending;bounded-full-queue-scan\n"
    "limits=at-most-255-original;at-most-255-contrast;at-most-two-decisions-"
    "per-variable;no-signed-literal-repeat\n"
    "fallback=zero-delegates-to-native-solver\n"
    "phase=none\n"
    "state=six-256-bit-rank-bitsets;u16-release-order;bounded-nonzero-events-"
    "and-pair-records;incremental-callback-hash\n";
constexpr const char *kExpectedContrastPolicySha256 =
    "96e040917b6566671683598a09c6d03f6ebec3809c6c63354f09ffca93c246b5";
constexpr size_t kMaximumNonzeroEvents = 2U * kProductionRankRows;

struct LocalTrailEntry {
  size_t local = 0;
  size_t level = 0;
};

struct NonzeroEvent {
  uint64_t call = 0;
  size_t rank_index = 0;
  int literal = 0;
  bool contrast = false;
  bool next_callback_observed = false;
  uint64_t assignment_burst_to_next_callback = 0;
};

struct PairRecord {
  int variable = 0;
  int original_literal = 0;
  int contrast_literal = 0;
  uint64_t original_return_call = 0;
  uint64_t original_release_after_call = 0;
  size_t original_release_level = 0;
  uint64_t contrast_return_call = 0;
  uint64_t contrast_release_after_call = 0;
  size_t contrast_release_level = 0;
};

class DiscardingStreamBuffer final : public std::streambuf {
protected:
  std::streamsize xsputn(const char *, std::streamsize count) override {
    return count;
  }

  int_type overflow(int_type character) override {
    return traits_type::not_eof(character);
  }
};

class ReleaseContrastGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  ReleaseContrastGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold, RankTable rank,
      RankVoteField vote_field, std::string potential_source_sha256)
      : parent_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
                potential_sha256, threshold, RankTable(rank),
                RankVoteField(vote_field), potential_source_sha256),
        rank_(std::move(rank)), vote_field_(std::move(vote_field)),
        potential_sha256_(potential_sha256),
        potential_source_sha256_(std::move(potential_source_sha256)),
        grouping_sha256_(sha256(grouping_payload)),
        consumed_state_(kRankBitsetBytes, '\0'),
        original_returned_state_(kRankBitsetBytes, '\0'),
        original_released_state_(kRankBitsetBytes, '\0'),
        contrast_enqueued_state_(kRankBitsetBytes, '\0'),
        contrast_returned_state_(kRankBitsetBytes, '\0'),
        contrast_released_state_(kRankBitsetBytes, '\0'),
        contrast_deferred_assigned_state_(kRankBitsetBytes, '\0') {
    const std::vector<int> &observed = parent_.observed();
    assignment_.assign(observed.size(), 0);
    pairs_.resize(rank_.rows.size());
    std::set<int> variables;
    for (size_t index = 0; index < rank_.rows.size(); ++index) {
      RankRow &row = rank_.rows[index];
      if (!variables.insert(row.variable).second)
        throw std::runtime_error("release-contrast rank variable repeats");
      const auto iterator =
          std::lower_bound(observed.begin(), observed.end(), row.variable);
      if (iterator == observed.end() || *iterator != row.variable)
        throw std::runtime_error("release-contrast rank variable is unobserved");
      row.local = static_cast<size_t>(iterator - observed.begin());
      PairRecord &pair = pairs_[index];
      pair.variable = row.variable;
      pair.original_literal = row.literal;
      pair.contrast_literal = -row.literal;
    }
    if (rank_.rows.size() > kProductionRankRows)
      throw std::runtime_error("release-contrast rank exceeds state capacity");
  }

  void notify_assignment(const std::vector<int> &literals) override {
    parent_.notify_assignment(literals);
    const std::vector<int> &observed = parent_.observed();
    for (const int literal : literals) {
      const auto iterator =
          std::lower_bound(observed.begin(), observed.end(), std::abs(literal));
      if (iterator == observed.end() || *iterator != std::abs(literal))
        throw std::runtime_error("release-contrast assignment is unobserved");
      const size_t local = static_cast<size_t>(iterator - observed.begin());
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assignment_.at(local);
      if (!slot) {
        slot = value;
        trail_.push_back({local, current_level_});
        ++assignment_literals_since_callback_;
        ++assignment_literals_observed_;
      } else if (slot != value) {
        throw std::runtime_error(
            "release-contrast assignment changed without backtrack");
      }
    }
  }

  void notify_new_decision_level() override {
    parent_.notify_new_decision_level();
    if (current_level_ == std::numeric_limits<size_t>::max())
      throw std::runtime_error("release-contrast decision level exceeds bound");
    ++current_level_;
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_)
      throw std::runtime_error("release-contrast backtrack level differs");
    const std::vector<int8_t> before = assignment_;
    parent_.notify_backtrack(new_level);
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t local = trail_.back().local;
      if (!assignment_.at(local))
        throw std::runtime_error("release-contrast trail state differs");
      assignment_[local] = 0;
      trail_.pop_back();
    }
    current_level_ = new_level;

    for (size_t index = 0; index < rank_.rows.size(); ++index) {
      const RankRow &row = rank_.rows[index];
      const int8_t prior = before.at(row.local);
      const int8_t after = assignment_.at(row.local);
      if (rank_bit(original_returned_state_, index) &&
          !rank_bit(original_released_state_, index) && prior && !after) {
        const int prior_literal = prior > 0 ? row.variable : -row.variable;
        if (prior_literal != row.literal)
          throw std::runtime_error(
              "release-contrast original released sign differs");
        set_rank_bit(original_released_state_, index);
        set_rank_bit(contrast_enqueued_state_, index);
        release_order_.push_back(static_cast<uint16_t>(index));
        append_i32(original_release_sequence_, row.literal);
        ++released_original_;
        ++contrast_enqueued_;
        PairRecord &pair = pairs_.at(index);
        pair.original_release_after_call =
            static_cast<uint64_t>(cb_decide_calls_);
        pair.original_release_level = new_level;
        maximum_queue_size_ = std::max(maximum_queue_size_, queue_size());
      }
      if (rank_bit(contrast_returned_state_, index) &&
          !rank_bit(contrast_released_state_, index) && prior && !after) {
        const int prior_literal = prior > 0 ? row.variable : -row.variable;
        if (prior_literal != -row.literal)
          throw std::runtime_error(
              "release-contrast opposite released sign differs");
        set_rank_bit(contrast_released_state_, index);
        append_i32(contrast_release_sequence_, -row.literal);
        ++contrast_releases_;
        PairRecord &pair = pairs_.at(index);
        pair.contrast_release_after_call =
            static_cast<uint64_t>(cb_decide_calls_);
        pair.contrast_release_level = new_level;
      }
    }
    if (release_order_.size() > rank_.rows.size())
      throw std::runtime_error("release-contrast queue exceeds rank");
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return parent_.cb_check_found_model(model);
  }

  int cb_decide() override {
    finalize_previous_event();
    const int parent_result = parent_.cb_decide();
    if (cb_decide_calls_ == std::numeric_limits<int64_t>::max())
      throw std::runtime_error(
          "release-contrast decision callback count exceeds bound");
    ++cb_decide_calls_;

    int expected_parent = 0;
    size_t original_index = rank_.rows.size();
    while (cursor_ < rank_.rows.size()) {
      const size_t index = cursor_++;
      const RankRow &row = rank_.rows[index];
      if (rank_bit(consumed_state_, index))
        throw std::runtime_error("release-contrast cursor revisited a row");
      set_rank_bit(consumed_state_, index);
      ++rows_consumed_;
      if (assignment_.at(row.local)) {
        ++skipped_preassigned_;
        continue;
      }
      set_rank_bit(original_returned_state_, index);
      ++original_once_returns_;
      expected_parent = row.literal;
      original_index = index;
      append_i32(original_return_sequence_, row.literal);
      PairRecord &pair = pairs_.at(index);
      pair.original_return_call = static_cast<uint64_t>(cb_decide_calls_);
      break;
    }
    if (parent_result != expected_parent)
      throw std::runtime_error(
          "release-contrast embedded v11 return differs");

    int result = parent_result;
    size_t result_index = original_index;
    bool contrast = false;
    if (result) {
      add_nonzero_event(result_index, result, false);
    } else {
      if (!first_parent_fallback_call_)
        first_parent_fallback_call_ = cb_decide_calls_;
      for (const uint16_t encoded_index : release_order_) {
        const size_t index = encoded_index;
        if (index >= rank_.rows.size() ||
            !rank_bit(contrast_enqueued_state_, index) ||
            rank_bit(contrast_returned_state_, index))
          continue;
        const RankRow &row = rank_.rows[index];
        if (assignment_.at(row.local)) {
          if (!rank_bit(contrast_deferred_assigned_state_, index)) {
            set_rank_bit(contrast_deferred_assigned_state_, index);
            ++contrast_deferred_assigned_;
          }
          continue;
        }
        set_rank_bit(contrast_returned_state_, index);
        ++contrast_returns_;
        result = -row.literal;
        result_index = index;
        contrast = true;
        append_i32(contrast_return_sequence_, result);
        PairRecord &pair = pairs_.at(index);
        pair.contrast_return_call = static_cast<uint64_t>(cb_decide_calls_);
        add_nonzero_event(index, result, true);
        break;
      }
    }

    std::string encoded;
    append_i32(encoded, result);
    callback_return_sha256_.update(encoded);
    if (result) {
      ++cb_decide_nonzero_;
      if (!contrast && result_index == rank_.rows.size())
        throw std::runtime_error("release-contrast original event lacks rank");
    } else {
      ++cb_decide_zero_;
      if (!first_final_fallback_call_)
        first_final_fallback_call_ = cb_decide_calls_;
    }
    assignment_literals_since_callback_ = 0;
    return result;
  }

  int cb_propagate() override { return parent_.cb_propagate(); }

  int cb_add_reason_clause_lit(int propagated_literal) override {
    return parent_.cb_add_reason_clause_lit(propagated_literal);
  }

  bool terminate() override { return parent_.terminate(); }

  bool cb_has_external_clause(bool &forgettable) override {
    return parent_.cb_has_external_clause(forgettable);
  }

  int cb_add_external_clause_lit() override {
    return parent_.cb_add_external_clause_lit();
  }

  const std::vector<int> &observed() const { return parent_.observed(); }

  const std::vector<std::vector<int>> &preloaded_clauses() const {
    return parent_.preloaded_clauses();
  }

  void attach_solver(CaDiCaL::Solver *solver) { parent_.attach_solver(solver); }

  void write_json(std::ostream &out) const { parent_.write_json(out); }

  void write_vault_json(std::ostream &out) const {
    parent_.write_vault_json(out);
  }

  void write_reader_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kContrastReaderSchema
        << "\",\"operator\":\"" << kContrastOperator
        << "\",\"implementation_release_parent_schema\":\""
        << kV12ReleaseParentSchema << "\",\"source_vault_sha256\":\""
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
        << ",\"vote_rule\":\"" << kVoteRule
        << "\",\"bound_rule\":\"" << kRankBoundRule
        << "\",\"gap_rule\":\"" << kGapRule
        << "\",\"sort_rule\":\"" << kSortRule
        << "\",\"literal_rule\":\"" << kLiteralRule
        << "\",\"reader_spec_bytes\":" << kRankSpec.size()
        << ",\"reader_spec_sha256\":\"" << kExpectedSpecSha256
        << "\",\"contrast_policy_spec_bytes\":"
        << kContrastPolicySpec.size()
        << ",\"contrast_policy_spec_sha256\":\""
        << kExpectedContrastPolicySha256 << "\",\"order_encoding\":\""
        << kOrderEncoding << "\",\"ranked_literals\":[";
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
        << "\",\"decision_rule\":\"" << kContrastDecisionRule
        << "\",\"callback_rule\":\"" << kContrastCallbackRule
        << "\",\"cursor\":" << cursor_
        << ",\"rows_consumed\":" << rows_consumed_
        << ",\"original_once_returns\":" << original_once_returns_
        << ",\"skipped_preassigned\":" << skipped_preassigned_
        << ",\"released_original\":" << released_original_
        << ",\"contrast_enqueued\":" << contrast_enqueued_
        << ",\"contrast_returns\":" << contrast_returns_
        << ",\"contrast_releases\":" << contrast_releases_
        << ",\"contrast_deferred_assigned\":"
        << contrast_deferred_assigned_
        << ",\"paired_variables\":" << contrast_returns_
        << ",\"variable_second_decisions\":" << contrast_returns_
        << ",\"same_signed_redecisions\":0"
        << ",\"solver_phase_calls\":0"
        << ",\"cb_decide_calls\":" << cb_decide_calls_
        << ",\"cb_decide_nonzero\":" << cb_decide_nonzero_
        << ",\"cb_decide_zero\":" << cb_decide_zero_
        << ",\"first_parent_fallback_call\":";
    write_nullable_u64(out, first_parent_fallback_call_);
    out << ",\"first_final_fallback_call\":";
    write_nullable_u64(out, first_final_fallback_call_);
    out << ",\"queue_size\":" << queue_size()
        << ",\"maximum_queue_size\":" << maximum_queue_size_
        << ",\"assignment_literals_observed\":"
        << assignment_literals_observed_;

    write_state(out, "consumed_state", consumed_state_);
    write_state(out, "original_returned_state", original_returned_state_);
    write_state(out, "original_released_state", original_released_state_);
    write_state(out, "contrast_enqueued_state", contrast_enqueued_state_);
    write_state(out, "contrast_returned_state", contrast_returned_state_);
    write_state(out, "contrast_released_state", contrast_released_state_);
    write_state(out, "contrast_deferred_assigned_state",
                contrast_deferred_assigned_state_);
    write_sequence(out, "original_return_sequence", original_return_sequence_,
                   original_once_returns_);
    write_sequence(out, "original_release_sequence",
                   original_release_sequence_, released_original_);
    write_sequence(out, "contrast_return_sequence", contrast_return_sequence_,
                   contrast_returns_);
    write_sequence(out, "contrast_release_sequence",
                   contrast_release_sequence_, contrast_releases_);

    out << ",\"returned_sequence_encoding\":\""
        << kReturnedSequenceEncoding << "\",\"returned_sequence_count\":"
        << cb_decide_calls_ << ",\"returned_sequence_bytes\":"
        << 4U * static_cast<uint64_t>(cb_decide_calls_)
        << ",\"returned_sequence_sha256\":\""
        << callback_return_sha256_.hex_digest()
        << "\",\"nonzero_event_rule\":\"" << kNonzeroEventRule
        << "\",\"nonzero_return_events\":[";
    for (size_t index = 0; index < events_.size(); ++index) {
      if (index)
        out << ',';
      const NonzeroEvent &event = events_[index];
      out << "{\"call\":" << event.call << ",\"kind\":\""
          << (event.contrast ? "contrast" : "original")
          << "\",\"rank_index\":" << event.rank_index
          << ",\"literal\":" << event.literal
          << ",\"next_callback_observed\":"
          << (event.next_callback_observed ? "true" : "false")
          << ",\"assignment_burst_to_next_callback\":"
          << event.assignment_burst_to_next_callback << '}';
    }
    out << "],\"pair_record_rule\":\"" << kPairRecordRule
        << "\",\"pair_records\":[";
    bool first_pair = true;
    for (size_t index = 0; index < pairs_.size(); ++index) {
      if (!rank_bit(original_returned_state_, index))
        continue;
      if (!first_pair)
        out << ',';
      first_pair = false;
      const PairRecord &pair = pairs_[index];
      out << "{\"rank_index\":" << index << ",\"variable\":"
          << pair.variable << ",\"original_literal\":"
          << pair.original_literal << ",\"contrast_literal\":"
          << pair.contrast_literal << ",\"original_return_call\":"
          << pair.original_return_call << ",\"original_release_after_call\":";
      write_nullable_u64(out, pair.original_release_after_call);
      out << ",\"original_release_level\":";
      write_nullable_size(out, pair.original_release_after_call,
                          pair.original_release_level);
      out << ",\"contrast_return_call\":";
      write_nullable_u64(out, pair.contrast_return_call);
      out << ",\"contrast_release_after_call\":";
      write_nullable_u64(out, pair.contrast_release_after_call);
      out << ",\"contrast_release_level\":";
      write_nullable_size(out, pair.contrast_release_after_call,
                          pair.contrast_release_level);
      out << '}';
    }
    out << "],\"bounded_state_rule\":\"" << kBoundedContrastStateRule
        << "\",\"bounded_guidance_state_bytes\":"
        << bounded_guidance_state_bytes()
        << ",\"live_guidance_state_bytes\":" << live_guidance_state_bytes()
        << ",\"bounded_telemetry_state_bytes\":"
        << bounded_telemetry_state_bytes();
  }

private:
  static void append_i32(std::string &payload, int literal) {
    append_u32_le(payload,
                  static_cast<uint32_t>(static_cast<int32_t>(literal)));
  }

  static void write_nullable_u64(std::ostream &out, uint64_t value) {
    if (value)
      out << value;
    else
      out << "null";
  }

  static void write_nullable_size(std::ostream &out, uint64_t present,
                                  size_t value) {
    if (present)
      out << value;
    else
      out << "null";
  }

  static void write_state(std::ostream &out, const char *prefix,
                          const std::string &state) {
    out << ",\"" << prefix << "_bits\":" << kKeyBits << ",\"" << prefix
        << "_bytes\":" << state.size() << ",\"" << prefix
        << "_encoding\":\"" << kContrastStateEncoding << "\",\"" << prefix
        << "_hex\":\"" << bytes_hex(state) << "\",\"" << prefix
        << "_sha256\":\"" << sha256(state) << '"';
  }

  static void write_sequence(std::ostream &out, const char *prefix,
                             const std::string &sequence, size_t count) {
    out << ",\"" << prefix << "_encoding\":\""
        << kContrastSequenceEncoding << "\",\"" << prefix
        << "_count\":" << count << ",\"" << prefix << "_bytes\":"
        << sequence.size() << ",\"" << prefix << "_hex\":\""
        << bytes_hex(sequence) << "\",\"" << prefix << "_sha256\":\""
        << sha256(sequence) << '"';
  }

  void finalize_previous_event() {
    if (pending_event_index_ < events_.size()) {
      NonzeroEvent &event = events_.at(pending_event_index_);
      if (event.next_callback_observed)
        throw std::runtime_error("release-contrast event finalized twice");
      event.next_callback_observed = true;
      event.assignment_burst_to_next_callback =
          assignment_literals_since_callback_;
    }
    pending_event_index_ = std::numeric_limits<size_t>::max();
  }

  void add_nonzero_event(size_t rank_index, int literal, bool contrast) {
    if (rank_index >= rank_.rows.size() || events_.size() >= kMaximumNonzeroEvents)
      throw std::runtime_error("release-contrast nonzero event exceeds bound");
    NonzeroEvent event;
    event.call = static_cast<uint64_t>(cb_decide_calls_);
    event.rank_index = rank_index;
    event.literal = literal;
    event.contrast = contrast;
    events_.push_back(event);
    pending_event_index_ = events_.size() - 1U;
  }

  size_t queue_size() const {
    if (contrast_returns_ > contrast_enqueued_)
      throw std::runtime_error("release-contrast queue count regressed");
    return contrast_enqueued_ - contrast_returns_;
  }

  size_t bounded_guidance_state_bytes() const {
    return 4U + 6U * kRankBitsetBytes +
           2U * kProductionRankRows;
  }

  size_t live_guidance_state_bytes() const {
    return 4U + 6U * kRankBitsetBytes + 2U * release_order_.size();
  }

  size_t bounded_telemetry_state_bytes() const {
    return bounded_guidance_state_bytes() +
           kRankBitsetBytes +
           kMaximumNonzeroEvents * sizeof(NonzeroEvent) +
           kProductionRankRows * sizeof(PairRecord) + sizeof(Sha256);
  }

  void validate_telemetry() const {
    DiscardingStreamBuffer parent_buffer;
    std::ostream parent_sink(&parent_buffer);
    parent_.write_reader_json(parent_sink);
    if (!parent_sink)
      throw std::runtime_error("release-contrast parent validation failed");
    if (cursor_ > rank_.rows.size() || rows_consumed_ != cursor_ ||
        rows_consumed_ != original_once_returns_ + skipped_preassigned_ ||
        released_original_ != contrast_enqueued_ ||
        contrast_returns_ > contrast_enqueued_ ||
        contrast_releases_ > contrast_returns_ ||
        cb_decide_calls_ < 0 || cb_decide_nonzero_ < 0 ||
        cb_decide_zero_ < 0 ||
        cb_decide_calls_ != cb_decide_nonzero_ + cb_decide_zero_ ||
        static_cast<size_t>(cb_decide_nonzero_) !=
            original_once_returns_ + contrast_returns_ ||
        events_.size() != static_cast<size_t>(cb_decide_nonzero_) ||
        release_order_.size() != released_original_ ||
        count_rank_bits(consumed_state_) != rows_consumed_ ||
        count_rank_bits(original_returned_state_) != original_once_returns_ ||
        count_rank_bits(original_released_state_) != released_original_ ||
        count_rank_bits(contrast_enqueued_state_) != contrast_enqueued_ ||
        count_rank_bits(contrast_returned_state_) != contrast_returns_ ||
        count_rank_bits(contrast_released_state_) != contrast_releases_ ||
        count_rank_bits(contrast_deferred_assigned_state_) !=
            contrast_deferred_assigned_ ||
        original_released_state_ != contrast_enqueued_state_ ||
        original_return_sequence_.size() != 4U * original_once_returns_ ||
        original_release_sequence_.size() != 4U * released_original_ ||
        contrast_return_sequence_.size() != 4U * contrast_returns_ ||
        contrast_release_sequence_.size() != 4U * contrast_releases_ ||
        maximum_queue_size_ > rank_.rows.size() ||
        queue_size() > maximum_queue_size_)
      throw std::runtime_error("release-contrast telemetry differs");

    std::string expected_original;
    std::set<int> expected_signed;
    std::map<int, size_t> variable_counts;
    for (size_t index = 0; index < rank_.rows.size(); ++index) {
      const bool consumed = rank_bit(consumed_state_, index);
      const bool original = rank_bit(original_returned_state_, index);
      const bool released = rank_bit(original_released_state_, index);
      const bool enqueued = rank_bit(contrast_enqueued_state_, index);
      const bool opposite = rank_bit(contrast_returned_state_, index);
      const bool opposite_released =
          rank_bit(contrast_released_state_, index);
      const bool deferred_assigned =
          rank_bit(contrast_deferred_assigned_state_, index);
      if (consumed != (index < cursor_) || (original && !consumed) ||
          (released && !original) || (enqueued != released) ||
          (opposite && !enqueued) || (opposite_released && !opposite) ||
          (deferred_assigned && !enqueued))
        throw std::runtime_error("release-contrast rank-state subset differs");
      const RankRow &row = rank_.rows[index];
      if (original) {
        append_i32(expected_original, row.literal);
        if (!expected_signed.insert(row.literal).second)
          throw std::runtime_error("release-contrast original signed repeat");
        ++variable_counts[row.variable];
      }
      if (opposite) {
        if (!expected_signed.insert(-row.literal).second)
          throw std::runtime_error("release-contrast opposite signed repeat");
        ++variable_counts[row.variable];
      }
      if (variable_counts[row.variable] > 2U)
        throw std::runtime_error("release-contrast variable exceeds two uses");
      const PairRecord &pair = pairs_.at(index);
      if (pair.variable != row.variable || pair.original_literal != row.literal ||
          pair.contrast_literal != -row.literal ||
          (original != static_cast<bool>(pair.original_return_call)) ||
          (released != static_cast<bool>(pair.original_release_after_call)) ||
          (opposite != static_cast<bool>(pair.contrast_return_call)) ||
          (opposite_released !=
           static_cast<bool>(pair.contrast_release_after_call)))
        throw std::runtime_error("release-contrast pair record differs");
    }
    if (expected_original != original_return_sequence_)
      throw std::runtime_error("release-contrast original order differs");

    std::string expected_release;
    std::set<size_t> release_indices;
    for (const uint16_t encoded_index : release_order_) {
      const size_t index = encoded_index;
      if (index >= rank_.rows.size() ||
          !rank_bit(original_released_state_, index) ||
          !release_indices.insert(index).second)
        throw std::runtime_error("release-contrast release order differs");
      append_i32(expected_release, rank_.rows[index].literal);
    }
    if (expected_release != original_release_sequence_)
      throw std::runtime_error("release-contrast release sequence differs");

    Sha256 expected_callback_hash;
    size_t event_cursor = 0;
    uint64_t last_event_call = 0;
    for (uint64_t call = 1; call <= static_cast<uint64_t>(cb_decide_calls_);
         ++call) {
      int literal = 0;
      if (event_cursor < events_.size() && events_[event_cursor].call == call) {
        const NonzeroEvent &event = events_[event_cursor++];
        if (event.call <= last_event_call || event.rank_index >= rank_.rows.size())
          throw std::runtime_error("release-contrast event order differs");
        last_event_call = event.call;
        const RankRow &row = rank_.rows[event.rank_index];
        const int expected = event.contrast ? -row.literal : row.literal;
        if (event.literal != expected ||
            (event.contrast &&
             !rank_bit(contrast_returned_state_, event.rank_index)) ||
            (!event.contrast &&
             !rank_bit(original_returned_state_, event.rank_index)))
          throw std::runtime_error("release-contrast event payload differs");
        literal = event.literal;
      }
      std::string encoded;
      append_i32(encoded, literal);
      expected_callback_hash.update(encoded);
    }
    if (event_cursor != events_.size() ||
        expected_callback_hash.hex_digest() !=
            callback_return_sha256_.hex_digest())
      throw std::runtime_error("release-contrast callback hash differs");

    size_t release_cursor = 0;
    for (size_t offset = 0; offset < contrast_return_sequence_.size();) {
      const int literal = read_i32_le(contrast_return_sequence_, offset,
                                      "contrast return literal");
      while (release_cursor < release_order_.size() &&
             !rank_bit(contrast_returned_state_,
                       release_order_[release_cursor]))
        ++release_cursor;
      if (release_cursor == release_order_.size() ||
          literal != -rank_.rows[release_order_[release_cursor]].literal)
        throw std::runtime_error("release-contrast return order differs");
      ++release_cursor;
    }
    if (contrast_returns_ &&
        (!first_parent_fallback_call_ || cursor_ != rank_.rows.size()))
      throw std::runtime_error("release-contrast parent fallback differs");
    if ((cb_decide_zero_ == 0) != (first_final_fallback_call_ == 0))
      throw std::runtime_error("release-contrast final fallback differs");
  }

  BacktrackReleaseGroupedJointScoreSieve parent_;
  RankTable rank_;
  RankVoteField vote_field_;
  std::string potential_sha256_;
  std::string potential_source_sha256_;
  std::string grouping_sha256_;
  std::vector<int8_t> assignment_;
  std::vector<LocalTrailEntry> trail_;
  size_t current_level_ = 0;
  size_t cursor_ = 0;
  size_t rows_consumed_ = 0;
  size_t original_once_returns_ = 0;
  size_t skipped_preassigned_ = 0;
  size_t released_original_ = 0;
  size_t contrast_enqueued_ = 0;
  size_t contrast_returns_ = 0;
  size_t contrast_releases_ = 0;
  size_t contrast_deferred_assigned_ = 0;
  size_t maximum_queue_size_ = 0;
  int64_t cb_decide_calls_ = 0;
  int64_t cb_decide_nonzero_ = 0;
  int64_t cb_decide_zero_ = 0;
  int64_t first_parent_fallback_call_ = 0;
  int64_t first_final_fallback_call_ = 0;
  uint64_t assignment_literals_since_callback_ = 0;
  uint64_t assignment_literals_observed_ = 0;
  size_t pending_event_index_ = std::numeric_limits<size_t>::max();
  std::string consumed_state_;
  std::string original_returned_state_;
  std::string original_released_state_;
  std::string contrast_enqueued_state_;
  std::string contrast_returned_state_;
  std::string contrast_released_state_;
  std::string contrast_deferred_assigned_state_;
  std::string original_return_sequence_;
  std::string original_release_sequence_;
  std::string contrast_return_sequence_;
  std::string contrast_release_sequence_;
  std::vector<uint16_t> release_order_;
  std::vector<NonzeroEvent> events_;
  std::vector<PairRecord> pairs_;
  Sha256 callback_return_sha256_;
};

void print_v12_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v12 --cnf PATH "
               "--potential PATH --grouping PATH --vault-in PATH "
               "--rank-table PATH --threshold FLOAT --conflict-limit N "
               "[--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v12_usage();
      return 0;
    }
    const RankedArguments ranked_arguments = parse_ranked_arguments(argc, argv);
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("release-contrast reader requires seed zero");
    if (kRankSpec.size() != 674U ||
        sha256(kRankSpec) != kExpectedSpecSha256 ||
        kContrastPolicySpec.size() != 674U ||
        sha256(kContrastPolicySpec) != kExpectedContrastPolicySha256)
      throw std::runtime_error("release-contrast reader specification differs");
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

#ifdef O1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE
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

    std::unique_ptr<ReleaseContrastGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") ||
          !solver.set("seed", arguments.seed) || !solver.set("quiet", 1) ||
          !solver.set("factor", 0) || !solver.set("lucky", 0) ||
          !solver.set("walk", 0) || !solver.set("rephase", 0) ||
          !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic release-contrast options");
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
          std::make_unique<ReleaseContrastGroupedJointScoreSieve>(
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
          << "{\"schema\":\"" << kV12ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV12ImplementationParentSchema
          << "\",\"implementation_release_parent_schema\":\""
          << kV12ReleaseParentSchema << "\",\"reader\":{";
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
    std::cerr << "cadical_o1_joint_score_sieve_v12: " << error.what()
              << '\n';
    return 1;
  }
}
