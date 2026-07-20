// O1C-0078 once-only rescue-prefix preemption over the O1C-0077 stack.
//
// Native v15 remains frozen.  This translation unit parses the exact raw
// signed-i32le prefix plan, consumes it once before the first parent decision
// callback, and thereafter forwards exactly one parent result unchanged.

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
#include <tuple>
#include <utility>
#include <vector>

#ifdef O1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C77_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C78_UNDEF_O1C77_FIXTURE
#endif
namespace o1c78_embedded_v15 {
#include "cadical_o1_joint_score_sieve_v15.cpp"
} // namespace o1c78_embedded_v15
#ifdef O1_CRYPTO_LAB_O1C78_UNDEF_O1C77_FIXTURE
#undef O1_CRYPTO_LAB_O1C77_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C78_UNDEF_O1C77_FIXTURE
#endif

using namespace o1c78_embedded_v15;

namespace {

constexpr const char *kV16ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v16";
constexpr const char *kV16ReleaseParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v15";
constexpr const char *kPrefixSchema =
    "o1-256-cadical-rescue-prefix-preemption-reader-v1";
constexpr const char *kPrefixOperator =
    "once-only-ordered-prefix-before-inherited-v15";
constexpr const char *kPrefixDecisionRule =
    "scan-exact-order;consume-assigned;return-first-unassigned-once;after-"
    "all-consumed-return-one-parent-result-unchanged";
constexpr const char *kPrefixCallbackRule =
    "no-parent-before-complete-prefix;then-one-parent-call-per-callback;"
    "never-override-or-discard-parent-return";
constexpr const char *kPrefixOrderEncoding = "signed-i32le";
constexpr const char *kPrefixOnceSequenceEncoding =
    "concatenated-signed-i32le-literals-in-return-order";
constexpr const char *kPrefixReturnedSequenceEncoding =
    "one-signed-i32le-literal-per-cb-decide-including-zero";
constexpr const char *kPrefixBoundedStateRule =
    "observed-i8-assignment;bounded-observed-u32-local,u32-level-trail;"
    "immutable-prefix-u32-local;bounded-4194304-outer-and-parent-return-"
    "bytes;bounded-once-u32-and-one-event-per-prefix-row";

constexpr size_t kMaximumPrefixPayloadBytes = 16384U;
constexpr size_t kMaximumPrefixRows = kMaximumPrefixPayloadBytes / 4U;
constexpr std::array<int, 11> kProductionPrefix = {
    130,    -131,   31874,  63746,  190565, 190566,
    190569, 191212, 191213, 191216, 191234,
};
constexpr const char *kProductionPrefixOrderSha256 =
    "b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c";
constexpr const char *kPrefixProductionSourceResultSha256 =
    "8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0";
constexpr const char *kPrefixProductionSourceAssignmentSha256 =
    "2d26cfd7d2cba61bd49d116a6cb64c35a8fabbacdb4244a431703ef1a562e6bc";
constexpr const char *kPrefixProductionBaselineTraceSha256 =
    "706ad4fa13a8a47cd81f99bc693c1bede46612112214e6f77dc52ee61d32bf15";
constexpr const char *kProductionActivePage5Sha256 =
    "07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208";
constexpr const char *kProductionFrontierPlanSha256 =
    "8a263e555b4b5a69d3c9a937cac3e7702a1f8e3de27db4feffc2d21563a24da1";
constexpr const char *kProductionStagingPlanSha256 =
    "ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023";

struct PrefixPlan {
  std::string payload_sha256;
  std::string order_bytes;
  std::string order_sha256;
  std::vector<int> literals;
};

std::string read_bounded_prefix_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input)
    throw std::runtime_error("cannot open rescue-prefix preemption plan");
  const std::streampos end = input.tellg();
  if (end <= 0 || static_cast<uint64_t>(end) > kMaximumPrefixPayloadBytes)
    throw std::runtime_error("rescue-prefix preemption plan size differs");
  const size_t size = static_cast<size_t>(end);
  std::string payload(size, '\0');
  input.seekg(0, std::ios::beg);
  if (!input.read(payload.data(), static_cast<std::streamsize>(size)))
    throw std::runtime_error("cannot read rescue-prefix preemption plan");
  char trailing = 0;
  if (input.get(trailing))
    throw std::runtime_error(
        "rescue-prefix preemption plan grew while reading");
  if (!input.eof() && input.fail())
    throw std::runtime_error(
        "cannot finish rescue-prefix preemption plan");
  return payload;
}

int prefix_read_i32(const std::string &payload, size_t &cursor) {
  if (cursor > payload.size() || payload.size() - cursor < 4U)
    throw std::runtime_error("rescue-prefix preemption literal differs");
  const uint32_t value = static_cast<unsigned char>(payload[cursor]) |
                         (static_cast<uint32_t>(static_cast<unsigned char>(
                              payload[cursor + 1U]))
                          << 8U) |
                         (static_cast<uint32_t>(static_cast<unsigned char>(
                              payload[cursor + 2U]))
                          << 16U) |
                         (static_cast<uint32_t>(static_cast<unsigned char>(
                              payload[cursor + 3U]))
                          << 24U);
  cursor += 4U;
  return static_cast<int32_t>(value);
}

PrefixPlan parse_prefix_plan(const std::string &payload) {
  if (payload.empty() || payload.size() % 4U ||
      payload.size() > kMaximumPrefixPayloadBytes)
    throw std::runtime_error("rescue-prefix preemption plan size differs");
  PrefixPlan plan;
  plan.payload_sha256 = sha256(payload);
  plan.order_bytes = payload;
  plan.order_sha256 = plan.payload_sha256;
  plan.literals.reserve(payload.size() / 4U);
  std::set<int> variables;
  size_t cursor = 0;
  while (cursor < payload.size()) {
    const int literal = prefix_read_i32(payload, cursor);
    if (!literal || literal == std::numeric_limits<int32_t>::min() ||
        !variables.insert(std::abs(literal)).second)
      throw std::runtime_error("rescue-prefix preemption literal differs");
    plan.literals.push_back(literal);
  }
  if (plan.literals.size() > kMaximumPrefixRows ||
      plan.literals.size() != kProductionPrefix.size() ||
      !std::equal(plan.literals.begin(), plan.literals.end(),
                  kProductionPrefix.begin()) ||
      plan.order_sha256 != kProductionPrefixOrderSha256)
    throw std::runtime_error(
        "sealed O1C78 rescue-prefix preemption plan differs");
  return plan;
}

void validate_o1c78_parent_stack(
    const FrontierPlan &frontier, const StagingPlan &staging,
    const std::string &active_vault_sha256,
    const std::string &frontier_plan_sha256,
    const std::string &staging_plan_sha256, bool production_seal) {
  if (!production_seal)
    return;
  if (active_vault_sha256 != kProductionActivePage5Sha256 ||
      frontier_plan_sha256 != kProductionFrontierPlanSha256 ||
      staging_plan_sha256 != kProductionStagingPlanSha256 ||
      frontier.payload_sha256 != kProductionFrontierPlanSha256 ||
      staging.payload_sha256 != kProductionStagingPlanSha256 ||
      staging.source_result_sha256 !=
          o1c78_embedded_v15::kProductionSourceResultSha256 ||
      staging.source_assignment_sha256 !=
          o1c78_embedded_v15::kProductionSourceAssignmentSha256 ||
      staging.active_vault_sha256 != kProductionActivePage5Sha256 ||
      staging.parent_frontier_plan_sha256 !=
          kProductionFrontierPlanSha256 ||
      staging.selected_active_index != kProductionSelectedActiveIndex ||
      staging.selected_union_index != kProductionSelectedUnionIndex ||
      staging.selected_clause_sha256 != kProductionSelectedClauseSha256 ||
      staging.selected_clause_literal_count !=
          kProductionSelectedClauseLiteralCount ||
      staging.source_rank_payload_sha256 !=
          kProductionSourceRankPayloadSha256 ||
      staging.source_rank_order_sha256 !=
          kProductionSourceRankOrderSha256 ||
      staging.effective_rank_order_sha256 !=
          kProductionEffectiveRankOrderSha256 ||
      staging.intersections.size() != kStagingIntersectionRows ||
      !same_intersection(staging.intersections[0], 28U, 105, -105, -105) ||
      !same_intersection(staging.intersections[1], 131U, -106, 106, 106) ||
      !same_intersection(staging.intersections[2], 224U, 131, 131, -131) ||
      !same_intersection(staging.intersections[3], 226U, -130, -130, 130) ||
      !same_intersection(staging.intersections[4], 235U, -129, 129, 129) ||
      staging.overlays.size() != kStagingOverlayRows ||
      !same_overlay(staging.overlays[0], 224U, 131, -131) ||
      !same_overlay(staging.overlays[1], 226U, -130, 130))
    throw std::runtime_error("sealed O1C78 inherited parent stack differs");
}

struct PrefixTrailEntry {
  uint32_t local = 0;
  uint32_t level = 0;
};

struct PrefixReturnEvent {
  uint64_t call = 0;
  uint32_t prefix_index = 0;
  int literal = 0;
};

class PrefixDiscardingStreamBuffer final : public std::streambuf {
protected:
  std::streamsize xsputn(const char *, std::streamsize count) override {
    return count;
  }
  int_type overflow(int_type character) override {
    return traits_type::not_eof(character);
  }
};

class RescuePrefixPreemptionGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  RescuePrefixPreemptionGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold, RankTable rank,
      RankVoteField vote_field, std::string potential_source_sha256,
      FrontierPlan frontier_plan, StagingPlan staging_plan,
      PrefixPlan prefix_plan, std::string active_vault_sha256,
      std::string parent_staging_plan_sha256)
      : parent_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
                potential_sha256, threshold, std::move(rank),
                std::move(vote_field), std::move(potential_source_sha256),
                std::move(frontier_plan), std::move(staging_plan)),
        plan_(std::move(prefix_plan)),
        active_vault_sha256_(std::move(active_vault_sha256)),
        parent_staging_plan_sha256_(std::move(parent_staging_plan_sha256)) {
    const std::vector<int> &observed = parent_.observed();
    assignment_.assign(observed.size(), 0);
    prefix_locals_.reserve(plan_.literals.size());
    for (const int literal : plan_.literals)
      prefix_locals_.push_back(
          static_cast<uint32_t>(local(std::abs(literal))));
  }

  void notify_assignment(const std::vector<int> &literals) override {
    parent_.notify_assignment(literals);
    for (const int literal : literals) {
      const size_t index = local(std::abs(literal));
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assignment_.at(index);
      if (!slot) {
        slot = value;
        trail_.push_back({static_cast<uint32_t>(index), current_level_});
        if (assignment_literals_observed_ ==
            std::numeric_limits<uint64_t>::max())
          throw std::runtime_error(
              "rescue-prefix preemption assignment count exceeds bound");
        ++assignment_literals_observed_;
      } else if (slot != value) {
        throw std::runtime_error(
            "rescue-prefix preemption assignment changed without backtrack");
      }
    }
  }

  void notify_new_decision_level() override {
    parent_.notify_new_decision_level();
    if (current_level_ == std::numeric_limits<uint32_t>::max())
      throw std::runtime_error(
          "rescue-prefix preemption decision level exceeds bound");
    ++current_level_;
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_)
      throw std::runtime_error(
          "rescue-prefix preemption backtrack level differs");
    parent_.notify_backtrack(new_level);
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t index = trail_.back().local;
      if (!assignment_.at(index))
        throw std::runtime_error(
            "rescue-prefix preemption trail state differs");
      assignment_[index] = 0;
      trail_.pop_back();
    }
    current_level_ = static_cast<uint32_t>(new_level);
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return parent_.cb_check_found_model(model);
  }

  int cb_decide() override {
    if (solve_finalized_)
      throw std::runtime_error(
          "rescue-prefix preemption callback occurred after solve end");
    if (outer_cb_decide_calls_ >= kMaximumCallbackRecords)
      throw std::runtime_error(
          "rescue-prefix preemption callback cap exceeded");
    const uint64_t call = ++outer_cb_decide_calls_;
    while (cursor_ < plan_.literals.size()) {
      const size_t index = cursor_++;
      ++rows_consumed_;
      const int literal = plan_.literals[index];
      const int8_t sign = assignment_.at(prefix_locals_[index]);
      if (sign) {
        if (literal_true(literal, sign))
          ++skipped_preassigned_falsifying_;
        else
          ++skipped_preassigned_rescue_;
        continue;
      }
      ++once_returns_;
      if (!first_once_return_call_)
        first_once_return_call_ = call;
      once_return_events_.push_back(
          {call, static_cast<uint32_t>(index), literal});
      staging_append_i32(once_return_sequence_, literal);
      record_outer_return(literal);
      return literal;
    }

    if (!first_parent_call_) {
      first_parent_call_ = call;
      all_rows_consumed_before_first_parent_call_ =
          rows_consumed_ == plan_.literals.size();
    }
    const int result = parent_.cb_decide();
    ++parent_cb_decide_calls_;
    if (result)
      ++parent_nonzero_returns_;
    else
      ++parent_zero_returns_;
    staging_append_i32(parent_returned_sequence_, result);
    record_outer_return(result);
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

  void finalize_after_solve() {
    if (solve_finalized_)
      throw std::runtime_error(
          "rescue-prefix preemption solve end finalized twice");
    parent_.finalize_after_solve();
    solve_finalized_ = true;
  }

  void write_json(std::ostream &out) const { parent_.write_json(out); }
  void write_vault_json(std::ostream &out) const {
    parent_.write_vault_json(out);
  }
  void write_reader_json(std::ostream &out) const {
    parent_.write_reader_json(out);
  }
  void write_frontier_json(std::ostream &out) const {
    parent_.write_frontier_json(out);
  }
  void write_staging_json(std::ostream &out) const {
    parent_.write_staging_json(out);
  }

  void write_prefix_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kPrefixSchema << "\",\"operator\":\""
        << kPrefixOperator << "\",\"plan_sha256\":\""
        << plan_.payload_sha256 << "\",\"source_result_sha256\":\""
        << kPrefixProductionSourceResultSha256
        << "\",\"source_assignment_sha256\":\""
        << kPrefixProductionSourceAssignmentSha256
        << "\",\"active_vault_sha256\":\""
        << active_vault_sha256_
        << "\",\"parent_staging_plan_sha256\":\""
        << parent_staging_plan_sha256_
        << "\",\"baseline_trace_sha256\":\""
        << kPrefixProductionBaselineTraceSha256
        << "\",\"prefix_order_encoding\":\"" << kPrefixOrderEncoding
        << "\",\"prefix_order_bytes\":" << plan_.order_bytes.size()
        << ",\"prefix_order_sha256\":\"" << plan_.order_sha256
        << "\",\"prefix_literals\":[";
    for (size_t index = 0; index < plan_.literals.size(); ++index) {
      if (index)
        out << ',';
      out << plan_.literals[index];
    }
    out << "],\"decision_rule\":\"" << kPrefixDecisionRule
        << "\",\"callback_rule\":\"" << kPrefixCallbackRule
        << "\",\"cursor\":" << cursor_ << ",\"rows_consumed\":"
        << rows_consumed_ << ",\"once_returns\":" << once_returns_
        << ",\"skipped_preassigned_falsifying\":"
        << skipped_preassigned_falsifying_
        << ",\"skipped_preassigned_rescue\":"
        << skipped_preassigned_rescue_ << ",\"cb_decide_calls\":"
        << outer_cb_decide_calls_ << ",\"parent_cb_decide_calls\":"
        << parent_cb_decide_calls_ << ",\"outer_nonzero_returns\":"
        << outer_nonzero_returns_ << ",\"outer_zero_returns\":"
        << outer_zero_returns_ << ",\"parent_nonzero_returns\":"
        << parent_nonzero_returns_ << ",\"parent_zero_returns\":"
        << parent_zero_returns_ << ",\"first_once_return_call\":";
    write_nullable_u64(out, first_once_return_call_);
    out << ",\"first_parent_call\":";
    write_nullable_u64(out, first_parent_call_);
    out << ",\"all_rows_consumed_before_first_parent_call\":"
        << (all_rows_consumed_before_first_parent_call_ ? "true" : "false")
        << ",\"mechanism_activated\":"
        << (once_returns_ ? "true" : "false")
        << ",\"assignment_literals_observed\":"
        << assignment_literals_observed_;
    write_sequence(out, "once_return_sequence", kPrefixOnceSequenceEncoding,
                   once_returns_, once_return_sequence_);
    write_sequence(out, "outer_returned_sequence",
                   kPrefixReturnedSequenceEncoding, outer_cb_decide_calls_,
                   outer_returned_sequence_);
    write_sequence(out, "parent_returned_sequence",
                   kPrefixReturnedSequenceEncoding, parent_cb_decide_calls_,
                   parent_returned_sequence_);
    out << ",\"once_return_events\":[";
    for (size_t index = 0; index < once_return_events_.size(); ++index) {
      if (index)
        out << ',';
      const PrefixReturnEvent &event = once_return_events_[index];
      out << "{\"call\":" << event.call << ",\"prefix_index\":"
          << event.prefix_index << ",\"literal\":" << event.literal << '}';
    }
    out << "],\"bounded_state_rule\":\"" << kPrefixBoundedStateRule
        << "\",\"bounded_guidance_state_bytes\":"
        << bounded_guidance_state_bytes()
        << ",\"live_guidance_state_bytes\":" << live_guidance_state_bytes()
        << ",\"bounded_telemetry_state_bytes\":"
        << bounded_telemetry_state_bytes();
  }

private:
  size_t local(int variable) const {
    const std::vector<int> &observed = parent_.observed();
    const auto iterator =
        std::lower_bound(observed.begin(), observed.end(), variable);
    if (iterator == observed.end() || *iterator != variable)
      throw std::runtime_error(
          "rescue-prefix preemption variable is unobserved");
    return static_cast<size_t>(iterator - observed.begin());
  }

  static bool literal_true(int literal, int8_t sign) {
    return sign && ((literal > 0) == (sign > 0));
  }

  void record_outer_return(int literal) {
    if (literal)
      ++outer_nonzero_returns_;
    else
      ++outer_zero_returns_;
    staging_append_i32(outer_returned_sequence_, literal);
  }

  static void write_nullable_u64(std::ostream &out, uint64_t value) {
    if (value)
      out << value;
    else
      out << "null";
  }

  static void write_sequence(std::ostream &out, const char *prefix,
                             const char *encoding, size_t count,
                             const std::string &payload) {
    out << ",\"" << prefix << "_encoding\":\"" << encoding << "\",\""
        << prefix << "_count\":" << count << ",\"" << prefix
        << "_bytes\":" << payload.size() << ",\"" << prefix
        << "_hex\":\"" << bytes_hex(payload) << "\",\"" << prefix
        << "_sha256\":\"" << sha256(payload) << '"';
  }

  size_t bounded_guidance_state_bytes() const {
    return 4U + assignment_.size() + 8U * assignment_.size() +
           4U * prefix_locals_.size();
  }

  size_t live_guidance_state_bytes() const {
    return 4U + assignment_.size() + 8U * trail_.size() +
           4U * prefix_locals_.size();
  }

  size_t bounded_telemetry_state_bytes() const {
    return bounded_guidance_state_bytes() +
           8U * kMaximumCallbackRecords +
           4U * kMaximumPrefixRows +
           kMaximumPrefixRows * sizeof(PrefixReturnEvent);
  }

  void validate_telemetry() const {
    PrefixDiscardingStreamBuffer parent_buffer;
    std::ostream parent_sink(&parent_buffer);
    parent_.write_reader_json(parent_sink);
    parent_.write_frontier_json(parent_sink);
    parent_.write_staging_json(parent_sink);
    if (!parent_sink || !solve_finalized_ || cursor_ > plan_.literals.size() ||
        rows_consumed_ != cursor_ ||
        rows_consumed_ != once_returns_ + skipped_preassigned_falsifying_ +
                              skipped_preassigned_rescue_ ||
        once_returns_ != once_return_events_.size() ||
        once_return_sequence_.size() != 4U * once_returns_ ||
        outer_returned_sequence_.size() !=
            4U * outer_cb_decide_calls_ ||
        parent_returned_sequence_.size() !=
            4U * parent_cb_decide_calls_ ||
        outer_cb_decide_calls_ != once_returns_ + parent_cb_decide_calls_ ||
        outer_cb_decide_calls_ !=
            outer_nonzero_returns_ + outer_zero_returns_ ||
        parent_cb_decide_calls_ !=
            parent_nonzero_returns_ + parent_zero_returns_ ||
        static_cast<bool>(once_returns_) !=
            static_cast<bool>(first_once_return_call_) ||
        static_cast<bool>(parent_cb_decide_calls_) !=
            static_cast<bool>(first_parent_call_) ||
        (first_parent_call_ &&
         (!all_rows_consumed_before_first_parent_call_ ||
          first_parent_call_ != once_returns_ + 1U)))
      throw std::runtime_error(
          "rescue-prefix preemption telemetry differs");
    std::string expected_once;
    uint64_t prior_call = 0;
    size_t prior_index = 0;
    bool have_event = false;
    for (const PrefixReturnEvent &event : once_return_events_) {
      if (!event.call || event.call > outer_cb_decide_calls_ ||
          event.call <= prior_call || event.prefix_index >= plan_.literals.size() ||
          (have_event && event.prefix_index <= prior_index) ||
          event.literal != plan_.literals[event.prefix_index])
        throw std::runtime_error(
            "rescue-prefix preemption return event differs");
      prior_call = event.call;
      prior_index = event.prefix_index;
      have_event = true;
      staging_append_i32(expected_once, event.literal);
    }
    if (expected_once != once_return_sequence_ ||
        outer_returned_sequence_.substr(0, once_return_sequence_.size()) !=
            once_return_sequence_ ||
        outer_returned_sequence_.substr(once_return_sequence_.size()) !=
            parent_returned_sequence_)
      throw std::runtime_error(
          "rescue-prefix preemption return sequence differs");
  }

  ResidualPolarityStagingGroupedJointScoreSieve parent_;
  PrefixPlan plan_;
  std::string active_vault_sha256_;
  std::string parent_staging_plan_sha256_;
  std::vector<int8_t> assignment_;
  std::vector<PrefixTrailEntry> trail_;
  std::vector<uint32_t> prefix_locals_;
  uint32_t current_level_ = 0;
  size_t cursor_ = 0;
  size_t rows_consumed_ = 0;
  size_t once_returns_ = 0;
  size_t skipped_preassigned_falsifying_ = 0;
  size_t skipped_preassigned_rescue_ = 0;
  uint64_t outer_cb_decide_calls_ = 0;
  uint64_t parent_cb_decide_calls_ = 0;
  size_t outer_nonzero_returns_ = 0;
  size_t outer_zero_returns_ = 0;
  size_t parent_nonzero_returns_ = 0;
  size_t parent_zero_returns_ = 0;
  uint64_t first_once_return_call_ = 0;
  uint64_t first_parent_call_ = 0;
  bool all_rows_consumed_before_first_parent_call_ = false;
  bool solve_finalized_ = false;
  uint64_t assignment_literals_observed_ = 0;
  std::string once_return_sequence_;
  std::string outer_returned_sequence_;
  std::string parent_returned_sequence_;
  std::vector<PrefixReturnEvent> once_return_events_;
};

struct PrefixArguments {
  StagingArguments staging;
  std::string prefix_plan_path;
};

PrefixArguments parse_prefix_arguments(int argc, char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string prefix_plan_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error(
          "rescue-prefix preemption arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--prefix-plan") {
      if (!prefix_plan_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("prefix-plan argument differs");
      prefix_plan_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (prefix_plan_path.empty())
    throw std::runtime_error("prefix-plan argument is missing");
  return {parse_staging_arguments(static_cast<int>(filtered.size()),
                                  filtered.data()),
          std::move(prefix_plan_path)};
}

void print_v16_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v16 --cnf PATH "
               "--potential PATH --grouping PATH --rank-vault PATH "
               "--vault-in PATH --rank-table PATH --frontier-plan PATH "
               "--staging-plan PATH --prefix-plan PATH --threshold FLOAT "
               "--conflict-limit N [--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v16_usage();
      return 0;
    }
    const PrefixArguments prefix_arguments =
        parse_prefix_arguments(argc, argv);
    const StagingArguments &staging_arguments = prefix_arguments.staging;
    const FrontierArguments &frontier_arguments = staging_arguments.frontier;
    const SplitRankedArguments &split_arguments = frontier_arguments.split;
    const RankedArguments &ranked_arguments = split_arguments.ranked;
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error(
          "rescue-prefix preemption requires seed zero");
    if (kRankSpec.size() != 674U ||
        sha256(kRankSpec) != kExpectedSpecSha256 ||
        kContrastPolicySpec.size() != 674U ||
        sha256(kContrastPolicySpec) != kExpectedContrastPolicySha256)
      throw std::runtime_error(
          "release-contrast reader specification differs");
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");

    const std::string cnf_payload =
        read_binary_file(arguments.cnf_path, "CNF");
    const std::string potential_payload =
        read_binary_file(arguments.potential_path, "potential");
    const std::string grouping_payload =
        read_binary_file(grouped_arguments.grouping_path, "grouping");
    const std::string rank_vault_payload =
        read_bounded_vault_file(split_arguments.rank_vault_path);
    const std::string active_vault_payload =
        read_bounded_vault_file(grouped_arguments.vault_path);
    if (rank_vault_payload.size() < kVaultIdentityPrefixBytes ||
        active_vault_payload.size() < kVaultIdentityPrefixBytes ||
        rank_vault_payload.compare(0, kVaultIdentityPrefixBytes,
                                   active_vault_payload, 0,
                                   kVaultIdentityPrefixBytes) != 0)
      throw std::runtime_error(
          "rank-source and active-vault identity differs");
    const std::string frontier_plan_payload =
        read_bounded_frontier_file(frontier_arguments.frontier_plan_path);
    FrontierPlan frontier_plan = parse_frontier_plan(frontier_plan_payload);
    const std::string staging_plan_payload =
        read_bounded_staging_file(staging_arguments.staging_plan_path);
    StagingPlan staging_plan = parse_staging_plan(staging_plan_payload);
    const std::string prefix_plan_payload =
        read_bounded_prefix_file(prefix_arguments.prefix_plan_path);
    PrefixPlan prefix_plan = parse_prefix_plan(prefix_plan_payload);
    const std::string rank_payload =
        read_binary_file(ranked_arguments.rank_table_path, "rank table");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);
    const std::string rank_source_vault_sha256 = sha256(rank_vault_payload);
    const std::string active_vault_sha256 = sha256(active_vault_payload);
    const std::string staging_plan_sha256 = sha256(staging_plan_payload);

#ifdef O1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE
    size_t fixture_cursor = kVaultIdentityPrefixBytes;
    const size_t vote_stop = read_u32_le(
        rank_vault_payload, fixture_cursor, "fixture rank vault clause count");
    constexpr size_t vote_start = 0U;
    constexpr bool production_seal = false;
#else
    constexpr size_t vote_start = kRankProductionPrefixClauses;
    constexpr size_t vote_stop = kRankProductionSourceClauses;
    constexpr bool production_seal = true;
#endif
    RankVoteField vote_field = derive_rank_vote_field(
        rank_vault_payload, vote_start, vote_stop, production_seal);
    if (vote_field.source_vault_sha256 != rank_source_vault_sha256)
      throw std::runtime_error("rank-source vault identity differs");
    RankTable rank = parse_rank_table(rank_payload, vote_field, production_seal);
    validate_o1c78_parent_stack(
        frontier_plan, staging_plan, active_vault_sha256,
        sha256(frontier_plan_payload), staging_plan_sha256, production_seal);

    std::unique_ptr<RescuePrefixPreemptionGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
          !solver.set("quiet", 1) || !solver.set("factor", 0) ||
          !solver.set("lucky", 0) || !solver.set("walk", 0) ||
          !solver.set("rephase", 0) || !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic rescue-prefix options");
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
      const std::vector<int> observed = observed_from_field(field);
      std::string observed_bytes;
      for (const int variable : observed)
        append_u32_le(observed_bytes, static_cast<uint32_t>(variable));
      const ScoreThresholdVault active_vault = parse_score_threshold_vault(
          active_vault_payload, cnf_sha256, potential_sha256,
          sha256(grouping_payload), sha256(observed_bytes), arguments.threshold,
          observed);
      // O1C-0078 intentionally rebinds the inherited staging/frontier stack to
      // fresh Page 5.  All generic parent bindings remain exact; only v15's
      // obsolete O1C-0077 fixed active-page seal is bypassed here.
      validate_and_apply_staging(
          staging_plan, rank, frontier_plan, active_vault, observed,
          sha256(frontier_plan_payload), false);

      propagator =
          std::make_unique<RescuePrefixPreemptionGroupedJointScoreSieve>(
              std::move(field), grouping_payload, active_vault_payload,
              cnf_sha256, potential_sha256, arguments.threshold,
              std::move(rank), std::move(vote_field), potential_source_sha256,
              std::move(frontier_plan), std::move(staging_plan),
              std::move(prefix_plan), active_vault_sha256,
              staging_plan_sha256);
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
      propagator->finalize_after_solve();
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

      const StagingPlan output_staging =
          parse_staging_plan(staging_plan_payload);
      const FrontierPlan output_frontier =
          parse_frontier_plan(frontier_plan_payload);
      const PrefixPlan output_prefix = parse_prefix_plan(prefix_plan_payload);
      std::ostringstream out;
      out << std::setprecision(std::numeric_limits<double>::max_digits10)
          << "{\"schema\":\"" << kV16ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV12ImplementationParentSchema
          << "\",\"implementation_release_parent_schema\":\""
          << kV16ReleaseParentSchema
          << "\",\"rank_source_vault_sha256\":\""
          << rank_source_vault_sha256
          << "\",\"frontier_plan_sha256\":\""
          << sha256(frontier_plan_payload)
          << "\",\"frontier_source_result_sha256\":\""
          << output_frontier.source_result_sha256
          << "\",\"staging_plan_sha256\":\""
          << staging_plan_sha256
          << "\",\"staging_source_result_sha256\":\""
          << output_staging.source_result_sha256
          << "\",\"reader_rank_role\":\"" << kReaderRankRole
          << "\",\"prefix_preemption_plan_sha256\":\""
          << output_prefix.payload_sha256
          << "\",\"prefix_preemption_source_result_sha256\":\""
          << kPrefixProductionSourceResultSha256 << "\",\"reader\":{";
      propagator->write_reader_json(out);
      out << "},\"frontier\":{";
      propagator->write_frontier_json(out);
      out << "},\"staging\":{";
      propagator->write_staging_json(out);
      out << "},\"prefix_preemption\":{";
      propagator->write_prefix_json(out);
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
    std::cerr << "cadical_o1_joint_score_sieve_v16: " << error.what() << '\n';
    return 1;
  }
}
