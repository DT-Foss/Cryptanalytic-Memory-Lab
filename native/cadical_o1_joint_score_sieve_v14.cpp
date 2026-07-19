// O1C-0076 target-free causal-frontier release-contrast reader.
//
// Native v12 remains frozen.  This translation unit embeds its exact reader,
// preserves every parent callback result, and composes a bounded frontier
// reader only when the parent delegates with zero.  The frontier plan is a
// checksummed canonical binary object; native code never parses JSON.

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

#ifdef O1_CRYPTO_LAB_O1C76_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C76_UNDEF_O1C73_FIXTURE
#endif
namespace o1c76_embedded_v12 {
#include "cadical_o1_joint_score_sieve_v12.cpp"
} // namespace o1c76_embedded_v12
#ifdef O1_CRYPTO_LAB_O1C76_UNDEF_O1C73_FIXTURE
#undef O1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C76_UNDEF_O1C73_FIXTURE
#endif

using namespace o1c76_embedded_v12;

namespace {

constexpr const char *kV14ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v14";
constexpr const char *kV14ReleaseParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v13";
constexpr const char *kFrontierSchema =
    "o1-256-cadical-causal-frontier-reader-v1";
constexpr const char *kFrontierOperator =
    "parent-first-causal-frontier-falsify-then-released-rescue";
constexpr const char *kFrontierDecisionRule =
    "parent-nonzero-unchanged;parent-zero-consume-initial-residual-to-"
    "exhaustion;then-earliest-released-currently-unassigned-satisfying-"
    "opposite-once;zero-delegates";
constexpr const char *kFrontierCallbackRule =
    "call-parent-every-callback;initial-assigned-rows-consumed-and-"
    "classified-once;enqueue-genuine-initial-release;defer-assigned-"
    "contrast;never-repeat-frontier-row-kind";
constexpr const char *kFrontierStateEncoding =
    "residual-plan-index-lsb-first";
constexpr const char *kFrontierSequenceEncoding =
    "concatenated-signed-i32le-literals-in-observation-order";
constexpr const char *kFrontierReturnedSequenceEncoding =
    "one-signed-i32le-literal-per-cb-decide-including-zero";
constexpr const char *kFrontierBoundedStateRule =
    "observed-i8-assignment;bounded-observed-u32-local,u32-level-trail;"
    "nine-residual-bitsets;bounded-u32-release-order;bounded-two-events-"
    "and-one-pair-record-per-residual;incremental-all-callback-sha256";

constexpr std::string_view kFrontierMagic("O1-CAUSAL-FRONTIER-V1\0", 22U);
constexpr uint32_t kFrontierVersion = 1U;
constexpr uint32_t kMaximumFrontierPayloadBytes = 16777216U;
constexpr uint32_t kMaximumFrontierAssignments = 1600000U;
constexpr uint32_t kMaximumFrontierSelectedIndices = 512U;
constexpr uint32_t kMaximumFrontierResidualLiterals = 1600000U;
constexpr size_t kFrontierChecksumBytes = 32U;

struct FrontierPlan {
  std::string payload_sha256;
  std::string source_result_sha256;
  std::string source_assignment_sha256;
  std::string active_vault_sha256;
  std::vector<uint32_t> selected_union_indices;
  uint32_t selected_active_index = 0;
  uint32_t selected_union_index = 0;
  std::string selected_clause_sha256;
  uint32_t selected_clause_literal_count = 0;
  uint32_t false_literal_count = 0;
  uint32_t true_literal_count = 0;
  uint32_t unassigned_literal_count = 0;
  std::vector<int8_t> prior_assignment;
  std::vector<int> residual_clause_literals;
  std::vector<int> falsifying_decision_literals;
};

std::string read_bounded_frontier_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input)
    throw std::runtime_error("cannot open causal-frontier plan");
  const std::streampos end = input.tellg();
  if (end < 0 || static_cast<uint64_t>(end) > kMaximumFrontierPayloadBytes)
    throw std::runtime_error("causal-frontier plan exceeds hard cap");
  const size_t size = static_cast<size_t>(end);
  std::string payload(size, '\0');
  input.seekg(0, std::ios::beg);
  if (size && !input.read(payload.data(), static_cast<std::streamsize>(size)))
    throw std::runtime_error("cannot read causal-frontier plan");
  char trailing = 0;
  if (input.get(trailing))
    throw std::runtime_error("causal-frontier plan grew while reading");
  if (!input.eof() && input.fail())
    throw std::runtime_error("cannot finish reading causal-frontier plan");
  return payload;
}

void require_frontier_literal(int literal, int previous_absolute,
                              const char *field) {
  if (!literal || literal == std::numeric_limits<int32_t>::min() ||
      std::abs(literal) <= previous_absolute)
    throw std::runtime_error(std::string(field) + " differs");
}

FrontierPlan parse_frontier_plan(const std::string &payload) {
  if (payload.size() <= kFrontierMagic.size() + kFrontierChecksumBytes ||
      payload.size() > kMaximumFrontierPayloadBytes)
    throw std::runtime_error("causal-frontier plan size differs");
  const size_t body_size = payload.size() - kFrontierChecksumBytes;
  const std::string body = payload.substr(0, body_size);
  const std::string checksum = bytes_hex(payload.substr(body_size));
  if (sha256(body) != checksum)
    throw std::runtime_error("causal-frontier plan checksum differs");
  size_t cursor = 0;
  if (body.size() < kFrontierMagic.size() ||
      body.compare(0, kFrontierMagic.size(), kFrontierMagic.data(),
                   kFrontierMagic.size()) != 0)
    throw std::runtime_error("causal-frontier plan magic differs");
  cursor += kFrontierMagic.size();
  const std::array<uint32_t, 5> expected_header = {
      kFrontierVersion, kMaximumFrontierPayloadBytes,
      kMaximumFrontierAssignments, kMaximumFrontierSelectedIndices,
      kMaximumFrontierResidualLiterals};
  for (const uint32_t expected : expected_header)
    if (read_u32_le(body, cursor, "causal-frontier header") != expected)
      throw std::runtime_error("causal-frontier version or caps differs");

  FrontierPlan plan;
  plan.payload_sha256 = sha256(payload);
  plan.source_result_sha256 =
      read_digest_hex(body, cursor, "frontier source result digest");
  plan.source_assignment_sha256 =
      read_digest_hex(body, cursor, "frontier source assignment digest");
  plan.active_vault_sha256 =
      read_digest_hex(body, cursor, "frontier active vault digest");
  const uint32_t selected_count =
      read_u32_le(body, cursor, "frontier selected index count");
  if (!selected_count || selected_count > kMaximumFrontierSelectedIndices)
    throw std::runtime_error("causal-frontier selected index count differs");
  std::set<uint32_t> selected_unique;
  plan.selected_union_indices.reserve(selected_count);
  for (uint32_t index = 0; index < selected_count; ++index) {
    const uint32_t union_index =
        read_u32_le(body, cursor, "frontier selected union index");
    if (!selected_unique.insert(union_index).second)
      throw std::runtime_error("causal-frontier selected indices repeat");
    plan.selected_union_indices.push_back(union_index);
  }
  plan.selected_active_index =
      read_u32_le(body, cursor, "frontier selected active index");
  plan.selected_union_index =
      read_u32_le(body, cursor, "frontier selected union index");
  if (plan.selected_active_index >= plan.selected_union_indices.size() ||
      plan.selected_union_indices[plan.selected_active_index] !=
          plan.selected_union_index)
    throw std::runtime_error("causal-frontier selected index mapping differs");
  plan.selected_clause_sha256 =
      read_digest_hex(body, cursor, "frontier selected clause digest");
  plan.selected_clause_literal_count =
      read_u32_le(body, cursor, "frontier selected clause length");
  plan.false_literal_count =
      read_u32_le(body, cursor, "frontier false literal count");
  plan.true_literal_count =
      read_u32_le(body, cursor, "frontier true literal count");
  plan.unassigned_literal_count =
      read_u32_le(body, cursor, "frontier unassigned literal count");
  if (plan.true_literal_count ||
      static_cast<uint64_t>(plan.false_literal_count) +
              plan.true_literal_count + plan.unassigned_literal_count !=
          plan.selected_clause_literal_count ||
      plan.unassigned_literal_count > kMaximumFrontierResidualLiterals)
    throw std::runtime_error("causal-frontier literal counts differ");

  const uint32_t assignment_count =
      read_u32_le(body, cursor, "frontier assignment count");
  if (assignment_count > kMaximumFrontierAssignments ||
      cursor > body.size() || body.size() - cursor < assignment_count)
    throw std::runtime_error("causal-frontier assignment count differs");
  const std::string assignment_payload = body.substr(cursor, assignment_count);
  cursor += assignment_count;
  plan.prior_assignment.reserve(assignment_count);
  for (const unsigned char byte : assignment_payload) {
    if (byte != 0U && byte != 1U && byte != 255U)
      throw std::runtime_error("causal-frontier assignment differs");
    plan.prior_assignment.push_back(byte == 255U ? int8_t{-1}
                                                 : static_cast<int8_t>(byte));
  }
  if (sha256(assignment_payload) != plan.source_assignment_sha256)
    throw std::runtime_error("causal-frontier assignment digest differs");

  const uint32_t residual_count =
      read_u32_le(body, cursor, "frontier residual count");
  if (residual_count != plan.unassigned_literal_count ||
      residual_count > kMaximumFrontierResidualLiterals)
    throw std::runtime_error("causal-frontier residual count differs");
  int previous_absolute = 0;
  plan.residual_clause_literals.reserve(residual_count);
  for (uint32_t index = 0; index < residual_count; ++index) {
    const int literal =
        read_i32_le(body, cursor, "frontier residual literal");
    require_frontier_literal(literal, previous_absolute,
                             "causal-frontier residual literal");
    previous_absolute = std::abs(literal);
    plan.residual_clause_literals.push_back(literal);
  }
  const uint32_t decision_count =
      read_u32_le(body, cursor, "frontier decision count");
  if (decision_count != residual_count)
    throw std::runtime_error("causal-frontier decision count differs");
  previous_absolute = 0;
  plan.falsifying_decision_literals.reserve(decision_count);
  for (uint32_t index = 0; index < decision_count; ++index) {
    const int literal =
        read_i32_le(body, cursor, "frontier decision literal");
    require_frontier_literal(literal, previous_absolute,
                             "causal-frontier decision literal");
    previous_absolute = std::abs(literal);
    if (literal != -plan.residual_clause_literals[index])
      throw std::runtime_error("causal-frontier decision polarity differs");
    plan.falsifying_decision_literals.push_back(literal);
  }
  if (cursor != body.size())
    throw std::runtime_error("causal-frontier plan trailing bytes differ");
  return plan;
}

struct FrontierTrailEntry {
  size_t local = 0;
  size_t level = 0;
};

struct FrontierRow {
  size_t local = 0;
  int clause_literal = 0;
  int initial_literal = 0;
};

struct FrontierSubstitutionEvent {
  uint64_t call = 0;
  size_t plan_index = 0;
  int literal = 0;
  bool contrast = false;
};

struct FrontierPairRecord {
  int clause_literal = 0;
  int initial_literal = 0;
  uint64_t initial_return_call = 0;
  uint64_t initial_release_after_call = 0;
  size_t initial_release_level = 0;
  uint64_t contrast_return_call = 0;
  uint64_t contrast_release_after_call = 0;
  size_t contrast_release_level = 0;
};

class FrontierDiscardingStreamBuffer final : public std::streambuf {
protected:
  std::streamsize xsputn(const char *, std::streamsize count) override {
    return count;
  }
  int_type overflow(int_type character) override {
    return traits_type::not_eof(character);
  }
};

class CausalFrontierGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  CausalFrontierGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold, RankTable rank,
      RankVoteField vote_field, std::string potential_source_sha256,
      FrontierPlan plan)
      : parent_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
                potential_sha256, threshold, std::move(rank),
                std::move(vote_field), std::move(potential_source_sha256)),
        plan_(std::move(plan)) {
    const std::vector<int> &observed = parent_.observed();
    assignment_.assign(observed.size(), 0);
    if (plan_.prior_assignment.size() != observed.size() ||
        plan_.selected_union_indices.size() !=
            parent_.preloaded_clauses().size() ||
        plan_.selected_active_index >= parent_.preloaded_clauses().size())
      throw std::runtime_error("causal-frontier population binding differs");
    validate_plan_selection();
    selected_clause_ =
        parent_.preloaded_clauses().at(plan_.selected_active_index);
    selected_clause_locals_.reserve(selected_clause_.size());
    for (const int literal : selected_clause_)
      selected_clause_locals_.push_back(observed_local(std::abs(literal)));
    rows_.reserve(plan_.residual_clause_literals.size());
    pairs_.resize(plan_.residual_clause_literals.size());
    for (size_t index = 0; index < plan_.residual_clause_literals.size();
         ++index) {
      const int clause_literal = plan_.residual_clause_literals[index];
      rows_.push_back({observed_local(std::abs(clause_literal)),
                       clause_literal,
                       plan_.falsifying_decision_literals[index]});
      pairs_[index].clause_literal = clause_literal;
      pairs_[index].initial_literal =
          plan_.falsifying_decision_literals[index];
    }
    const size_t state_bytes = (rows_.size() + 7U) / 8U;
    consumed_state_.assign(state_bytes, '\0');
    initial_returned_state_.assign(state_bytes, '\0');
    initial_released_state_.assign(state_bytes, '\0');
    contrast_enqueued_state_.assign(state_bytes, '\0');
    contrast_returned_state_.assign(state_bytes, '\0');
    contrast_released_state_.assign(state_bytes, '\0');
    skipped_falsifying_state_.assign(state_bytes, '\0');
    skipped_rescue_state_.assign(state_bytes, '\0');
    contrast_deferred_assigned_state_.assign(state_bytes, '\0');
    update_live_clause_counts();
  }

  void notify_assignment(const std::vector<int> &literals) override {
    parent_.notify_assignment(literals);
    for (const int literal : literals) {
      const size_t local = observed_local(std::abs(literal));
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assignment_.at(local);
      if (!slot) {
        slot = value;
        trail_.push_back({local, current_level_});
        ++assignment_literals_observed_;
      } else if (slot != value) {
        throw std::runtime_error(
            "causal-frontier assignment changed without backtrack");
      }
    }
    update_live_clause_counts();
  }

  void notify_new_decision_level() override {
    parent_.notify_new_decision_level();
    if (current_level_ == std::numeric_limits<size_t>::max())
      throw std::runtime_error("causal-frontier decision level exceeds bound");
    ++current_level_;
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_)
      throw std::runtime_error("causal-frontier backtrack level differs");
    const std::vector<int8_t> before = assignment_;
    parent_.notify_backtrack(new_level);
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t local = trail_.back().local;
      if (!assignment_.at(local))
        throw std::runtime_error("causal-frontier trail state differs");
      assignment_[local] = 0;
      trail_.pop_back();
    }
    current_level_ = new_level;
    for (size_t index = 0; index < rows_.size(); ++index) {
      const FrontierRow &row = rows_[index];
      const int8_t prior = before.at(row.local);
      const int8_t after = assignment_.at(row.local);
      if (frontier_bit(initial_returned_state_, index) &&
          !frontier_bit(initial_released_state_, index) && prior && !after) {
        if (signed_literal(row.local, prior) != row.initial_literal)
          throw std::runtime_error(
              "causal-frontier initial released sign differs");
        set_frontier_bit(initial_released_state_, index);
        set_frontier_bit(contrast_enqueued_state_, index);
        release_order_.push_back(static_cast<uint32_t>(index));
        frontier_append_i32(initial_release_sequence_, row.initial_literal);
        ++initial_releases_;
        ++contrast_enqueued_;
        FrontierPairRecord &pair = pairs_.at(index);
        pair.initial_release_after_call = cb_decide_calls_;
        pair.initial_release_level = new_level;
        maximum_queue_size_ = std::max(maximum_queue_size_, queue_size());
      }
      if (frontier_bit(contrast_returned_state_, index) &&
          !frontier_bit(contrast_released_state_, index) && prior && !after) {
        if (signed_literal(row.local, prior) != row.clause_literal)
          throw std::runtime_error(
              "causal-frontier contrast released sign differs");
        set_frontier_bit(contrast_released_state_, index);
        frontier_append_i32(contrast_release_sequence_, row.clause_literal);
        ++contrast_releases_;
        FrontierPairRecord &pair = pairs_.at(index);
        pair.contrast_release_after_call = cb_decide_calls_;
        pair.contrast_release_level = new_level;
      }
    }
    if (release_order_.size() > rows_.size())
      throw std::runtime_error("causal-frontier release queue exceeds plan");
    update_live_clause_counts();
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return parent_.cb_check_found_model(model);
  }

  int cb_decide() override {
    const int parent_result = parent_.cb_decide();
    if (cb_decide_calls_ == std::numeric_limits<uint64_t>::max())
      throw std::runtime_error("causal-frontier callback count exceeds bound");
    ++cb_decide_calls_;
    int result = parent_result;
    if (parent_result) {
      ++parent_nonzero_returns_;
    } else {
      ++parent_zero_returns_;
      if (!first_parent_zero_call_)
        first_parent_zero_call_ = cb_decide_calls_;
      while (cursor_ < rows_.size()) {
        const size_t index = cursor_++;
        const FrontierRow &row = rows_[index];
        if (frontier_bit(consumed_state_, index))
          throw std::runtime_error("causal-frontier cursor revisited a row");
        set_frontier_bit(consumed_state_, index);
        ++rows_consumed_;
        const int8_t assigned = assignment_.at(row.local);
        if (assigned) {
          const int assigned_literal = signed_literal(row.local, assigned);
          if (assigned_literal == row.initial_literal) {
            set_frontier_bit(skipped_falsifying_state_, index);
            ++initial_skipped_preassigned_falsifying_;
          } else if (assigned_literal == row.clause_literal) {
            set_frontier_bit(skipped_rescue_state_, index);
            ++initial_skipped_preassigned_rescue_;
          } else {
            throw std::runtime_error(
                "causal-frontier preassigned row sign differs");
          }
          continue;
        }
        set_frontier_bit(initial_returned_state_, index);
        ++initial_once_returns_;
        result = row.initial_literal;
        frontier_append_i32(initial_return_sequence_, result);
        pairs_.at(index).initial_return_call = cb_decide_calls_;
        add_substitution_event(index, result, false);
        break;
      }
      if (!result && cursor_ == rows_.size()) {
        for (const uint32_t encoded_index : release_order_) {
          const size_t index = encoded_index;
          if (index >= rows_.size() ||
              !frontier_bit(contrast_enqueued_state_, index) ||
              frontier_bit(contrast_returned_state_, index))
            continue;
          const FrontierRow &row = rows_[index];
          if (assignment_.at(row.local)) {
            if (!frontier_bit(contrast_deferred_assigned_state_, index)) {
              set_frontier_bit(contrast_deferred_assigned_state_, index);
              ++contrast_deferred_assigned_;
            }
            continue;
          }
          set_frontier_bit(contrast_returned_state_, index);
          ++contrast_returns_;
          result = row.clause_literal;
          frontier_append_i32(contrast_return_sequence_, result);
          pairs_.at(index).contrast_return_call = cb_decide_calls_;
          add_substitution_event(index, result, true);
          break;
        }
      }
    }
    std::string encoded;
    frontier_append_i32(encoded, result);
    outer_return_sha256_.update(encoded);
    if (result) {
      ++outer_nonzero_returns_;
      if (!parent_result && !first_frontier_return_call_)
        first_frontier_return_call_ = cb_decide_calls_;
    } else {
      ++outer_zero_returns_;
      if (!first_outer_zero_call_)
        first_outer_zero_call_ = cb_decide_calls_;
    }
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
    parent_.write_reader_json(out);
  }

  void write_frontier_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kFrontierSchema << "\",\"operator\":\""
        << kFrontierOperator << "\",\"plan_sha256\":\""
        << plan_.payload_sha256 << "\",\"source_result_sha256\":\""
        << plan_.source_result_sha256
        << "\",\"source_assignment_sha256\":\""
        << plan_.source_assignment_sha256
        << "\",\"active_vault_sha256\":\""
        << plan_.active_vault_sha256
        << "\",\"selected_active_index\":"
        << plan_.selected_active_index << ",\"selected_union_index\":"
        << plan_.selected_union_index
        << ",\"selected_clause_sha256\":\""
        << plan_.selected_clause_sha256
        << "\",\"selected_clause_literal_count\":"
        << plan_.selected_clause_literal_count
        << ",\"prior_false_literal_count\":" << plan_.false_literal_count
        << ",\"prior_true_literal_count\":" << plan_.true_literal_count
        << ",\"prior_unassigned_literal_count\":"
        << plan_.unassigned_literal_count
        << ",\"residual_clause_literals\":[";
    write_literal_array(out, plan_.residual_clause_literals);
    out << "],\"falsifying_decision_literals\":[";
    write_literal_array(out, plan_.falsifying_decision_literals);
    out << "],\"decision_rule\":\"" << kFrontierDecisionRule
        << "\",\"callback_rule\":\"" << kFrontierCallbackRule
        << "\",\"cursor\":" << cursor_
        << ",\"rows_consumed\":" << rows_consumed_
        << ",\"initial_once_returns\":" << initial_once_returns_
        << ",\"initial_skipped_preassigned_falsifying\":"
        << initial_skipped_preassigned_falsifying_
        << ",\"initial_skipped_preassigned_rescue\":"
        << initial_skipped_preassigned_rescue_
        << ",\"initial_releases\":" << initial_releases_
        << ",\"contrast_enqueued\":" << contrast_enqueued_
        << ",\"contrast_returns\":" << contrast_returns_
        << ",\"contrast_releases\":" << contrast_releases_
        << ",\"contrast_deferred_assigned\":"
        << contrast_deferred_assigned_
        << ",\"queue_size\":" << queue_size()
        << ",\"maximum_queue_size\":" << maximum_queue_size_
        << ",\"cb_decide_calls\":" << cb_decide_calls_
        << ",\"parent_nonzero_returns\":" << parent_nonzero_returns_
        << ",\"parent_zero_returns\":" << parent_zero_returns_
        << ",\"outer_nonzero_returns\":" << outer_nonzero_returns_
        << ",\"outer_zero_returns\":" << outer_zero_returns_
        << ",\"first_parent_zero_call\":";
    write_nullable_u64(out, first_parent_zero_call_);
    out << ",\"first_frontier_return_call\":";
    write_nullable_u64(out, first_frontier_return_call_);
    out << ",\"first_outer_zero_call\":";
    write_nullable_u64(out, first_outer_zero_call_);
    out << ",\"assignment_literals_observed\":"
        << assignment_literals_observed_
        << ",\"live_false_literal_count\":" << live_false_literal_count_
        << ",\"live_true_literal_count\":" << live_true_literal_count_
        << ",\"live_unassigned_literal_count\":"
        << live_unassigned_literal_count_
        << ",\"minimum_live_false_literal_count\":"
        << minimum_live_false_literal_count_
        << ",\"minimum_live_true_literal_count\":"
        << minimum_live_true_literal_count_
        << ",\"minimum_live_unassigned_literal_count\":"
        << minimum_live_unassigned_literal_count_
        << ",\"prior_distance_reached\":"
        << (prior_distance_reached_ ? "true" : "false")
        << ",\"unit_distance_reached\":"
        << (unit_distance_reached_ ? "true" : "false");

    write_state(out, "consumed_state", consumed_state_);
    write_state(out, "initial_returned_state", initial_returned_state_);
    write_state(out, "initial_released_state", initial_released_state_);
    write_state(out, "contrast_enqueued_state", contrast_enqueued_state_);
    write_state(out, "contrast_returned_state", contrast_returned_state_);
    write_state(out, "contrast_released_state", contrast_released_state_);
    write_state(out, "skipped_falsifying_state", skipped_falsifying_state_);
    write_state(out, "skipped_rescue_state", skipped_rescue_state_);
    write_state(out, "contrast_deferred_assigned_state",
                contrast_deferred_assigned_state_);
    write_sequence(out, "initial_return_sequence", initial_return_sequence_,
                   initial_once_returns_);
    write_sequence(out, "initial_release_sequence", initial_release_sequence_,
                   initial_releases_);
    write_sequence(out, "contrast_return_sequence", contrast_return_sequence_,
                   contrast_returns_);
    write_sequence(out, "contrast_release_sequence",
                   contrast_release_sequence_, contrast_releases_);
    out << ",\"returned_sequence_encoding\":\""
        << kFrontierReturnedSequenceEncoding
        << "\",\"returned_sequence_count\":" << cb_decide_calls_
        << ",\"returned_sequence_bytes\":" << 4U * cb_decide_calls_
        << ",\"returned_sequence_sha256\":\""
        << outer_return_sha256_.hex_digest()
        << "\",\"substitution_events\":[";
    for (size_t index = 0; index < events_.size(); ++index) {
      if (index)
        out << ',';
      const FrontierSubstitutionEvent &event = events_[index];
      out << "{\"call\":" << event.call << ",\"kind\":\""
          << (event.contrast ? "contrast" : "initial")
          << "\",\"plan_index\":" << event.plan_index
          << ",\"literal\":" << event.literal << '}';
    }
    out << "],\"pair_records\":[";
    bool first_pair = true;
    for (size_t index = 0; index < pairs_.size(); ++index) {
      if (!frontier_bit(initial_returned_state_, index))
        continue;
      if (!first_pair)
        out << ',';
      first_pair = false;
      const FrontierPairRecord &pair = pairs_[index];
      out << "{\"plan_index\":" << index << ",\"clause_literal\":"
          << pair.clause_literal << ",\"initial_literal\":"
          << pair.initial_literal << ",\"initial_return_call\":"
          << pair.initial_return_call << ",\"initial_release_after_call\":";
      write_nullable_u64(out, pair.initial_release_after_call);
      out << ",\"initial_release_level\":";
      write_nullable_size(out, pair.initial_release_after_call,
                          pair.initial_release_level);
      out << ",\"contrast_return_call\":";
      write_nullable_u64(out, pair.contrast_return_call);
      out << ",\"contrast_release_after_call\":";
      write_nullable_u64(out, pair.contrast_release_after_call);
      out << ",\"contrast_release_level\":";
      write_nullable_size(out, pair.contrast_release_after_call,
                          pair.contrast_release_level);
      out << '}';
    }
    out << "],\"bounded_state_rule\":\"" << kFrontierBoundedStateRule
        << "\",\"bounded_guidance_state_bytes\":"
        << bounded_guidance_state_bytes()
        << ",\"live_guidance_state_bytes\":"
        << live_guidance_state_bytes()
        << ",\"bounded_telemetry_state_bytes\":"
        << bounded_telemetry_state_bytes();
  }

private:
  size_t observed_local(int variable) const {
    const std::vector<int> &values = parent_.observed();
    const auto iterator = std::lower_bound(values.begin(), values.end(), variable);
    if (iterator == values.end() || *iterator != variable)
      throw std::runtime_error("causal-frontier variable is unobserved");
    return static_cast<size_t>(iterator - values.begin());
  }

  int signed_literal(size_t local, int8_t sign) const {
    if (!sign || local >= parent_.observed().size())
      throw std::runtime_error("causal-frontier signed literal differs");
    const int variable = parent_.observed()[local];
    return sign > 0 ? variable : -variable;
  }

  static bool literal_true(int literal, int8_t sign) {
    return sign && ((sign > 0) == (literal > 0));
  }

  void classify_clause(const std::vector<int> &clause,
                       const std::vector<int8_t> &assignment,
                       size_t &false_count, size_t &true_count,
                       std::vector<int> &residual) const {
    false_count = 0;
    true_count = 0;
    residual.clear();
    for (const int literal : clause) {
      const int8_t sign = assignment.at(observed_local(std::abs(literal)));
      if (!sign)
        residual.push_back(literal);
      else if (literal_true(literal, sign))
        ++true_count;
      else
        ++false_count;
    }
  }

  void validate_plan_selection() const {
    const std::vector<std::vector<int>> &clauses = parent_.preloaded_clauses();
    bool winner_present = false;
    std::tuple<size_t, std::string, size_t> winner;
    std::vector<int> selected_residual;
    size_t selected_false = 0;
    size_t selected_true = 0;
    for (size_t index = 0; index < clauses.size(); ++index) {
      size_t false_count = 0;
      size_t true_count = 0;
      std::vector<int> residual;
      classify_clause(clauses[index], plan_.prior_assignment, false_count,
                      true_count, residual);
      const std::string clause_sha256 =
          sha256(canonical_clause_bytes(clauses[index]));
      if (!true_count) {
        const auto candidate =
            std::make_tuple(residual.size(), clause_sha256, index);
        if (!winner_present || candidate < winner) {
          winner = candidate;
          winner_present = true;
        }
      }
      if (index == plan_.selected_active_index) {
        selected_false = false_count;
        selected_true = true_count;
        selected_residual = std::move(residual);
        if (clause_sha256 != plan_.selected_clause_sha256)
          throw std::runtime_error(
              "causal-frontier selected clause digest differs");
      }
    }
    if (!winner_present ||
        winner != std::make_tuple(
                      static_cast<size_t>(plan_.unassigned_literal_count),
                      plan_.selected_clause_sha256,
                      static_cast<size_t>(plan_.selected_active_index)) ||
        selected_false != plan_.false_literal_count ||
        selected_true != plan_.true_literal_count ||
        clauses[plan_.selected_active_index].size() !=
            plan_.selected_clause_literal_count ||
        selected_residual != plan_.residual_clause_literals)
      throw std::runtime_error("causal-frontier selected clause binding differs");
  }

  static void frontier_append_i32(std::string &payload, int literal) {
    append_u32_le(payload,
                  static_cast<uint32_t>(static_cast<int32_t>(literal)));
  }

  static bool frontier_bit(const std::string &state, size_t index) {
    if (index / 8U >= state.size())
      throw std::runtime_error("causal-frontier state index differs");
    const auto byte = static_cast<unsigned char>(state[index / 8U]);
    return (byte >> (index % 8U)) & 1U;
  }

  static void set_frontier_bit(std::string &state, size_t index) {
    if (frontier_bit(state, index))
      throw std::runtime_error("causal-frontier state bit repeats");
    auto byte = static_cast<unsigned char>(state[index / 8U]);
    byte = static_cast<unsigned char>(byte | (1U << (index % 8U)));
    state[index / 8U] = static_cast<char>(byte);
  }

  size_t count_frontier_bits(const std::string &state) const {
    size_t count = 0;
    for (size_t index = 0; index < rows_.size(); ++index)
      if (frontier_bit(state, index))
        ++count;
    return count;
  }

  void add_substitution_event(size_t plan_index, int literal, bool contrast) {
    if (plan_index >= rows_.size() || events_.size() >= 2U * rows_.size())
      throw std::runtime_error("causal-frontier event exceeds bound");
    events_.push_back(
        {cb_decide_calls_, plan_index, literal, contrast});
  }

  void update_live_clause_counts() {
    size_t false_count = 0;
    size_t true_count = 0;
    size_t unassigned_count = 0;
    for (size_t index = 0; index < selected_clause_.size(); ++index) {
      const int8_t sign = assignment_.at(selected_clause_locals_[index]);
      if (!sign)
        ++unassigned_count;
      else if (literal_true(selected_clause_[index], sign))
        ++true_count;
      else
        ++false_count;
    }
    live_false_literal_count_ = false_count;
    live_true_literal_count_ = true_count;
    live_unassigned_literal_count_ = unassigned_count;
    if (!live_counts_initialized_) {
      minimum_live_false_literal_count_ = false_count;
      minimum_live_true_literal_count_ = true_count;
      minimum_live_unassigned_literal_count_ = unassigned_count;
      live_counts_initialized_ = true;
    } else {
      minimum_live_false_literal_count_ =
          std::min(minimum_live_false_literal_count_, false_count);
      minimum_live_true_literal_count_ =
          std::min(minimum_live_true_literal_count_, true_count);
      minimum_live_unassigned_literal_count_ =
          std::min(minimum_live_unassigned_literal_count_, unassigned_count);
    }
    if (!true_count && unassigned_count <= plan_.unassigned_literal_count)
      prior_distance_reached_ = true;
    if (!true_count && unassigned_count <= 1U)
      unit_distance_reached_ = true;
  }

  size_t queue_size() const {
    if (contrast_returns_ > contrast_enqueued_)
      throw std::runtime_error("causal-frontier queue count regressed");
    return contrast_enqueued_ - contrast_returns_;
  }

  size_t bounded_guidance_state_bytes() const {
    const size_t bitsets = 9U * consumed_state_.size();
    return 4U + assignment_.size() + 8U * assignment_.size() + bitsets +
           4U * rows_.size();
  }

  size_t live_guidance_state_bytes() const {
    const size_t bitsets = 9U * consumed_state_.size();
    return 4U + assignment_.size() + 8U * trail_.size() + bitsets +
           4U * release_order_.size();
  }

  size_t bounded_telemetry_state_bytes() const {
    return bounded_guidance_state_bytes() + 17U * 2U * rows_.size() +
           56U * rows_.size() + 112U;
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

  static void write_literal_array(std::ostream &out,
                                  const std::vector<int> &literals) {
    for (size_t index = 0; index < literals.size(); ++index) {
      if (index)
        out << ',';
      out << literals[index];
    }
  }

  void write_state(std::ostream &out, const char *prefix,
                   const std::string &state) const {
    out << ",\"" << prefix << "_bits\":" << rows_.size() << ",\""
        << prefix << "_bytes\":" << state.size() << ",\"" << prefix
        << "_encoding\":\"" << kFrontierStateEncoding << "\",\""
        << prefix << "_hex\":\"" << bytes_hex(state) << "\",\""
        << prefix << "_sha256\":\"" << sha256(state) << '"';
  }

  static void write_sequence(std::ostream &out, const char *prefix,
                             const std::string &sequence, size_t count) {
    out << ",\"" << prefix << "_encoding\":\""
        << kFrontierSequenceEncoding << "\",\"" << prefix
        << "_count\":" << count << ",\"" << prefix << "_bytes\":"
        << sequence.size() << ",\"" << prefix << "_hex\":\""
        << bytes_hex(sequence) << "\",\"" << prefix
        << "_sha256\":\"" << sha256(sequence) << '"';
  }

  void validate_telemetry() const {
    FrontierDiscardingStreamBuffer parent_buffer;
    std::ostream parent_sink(&parent_buffer);
    parent_.write_reader_json(parent_sink);
    if (!parent_sink)
      throw std::runtime_error("causal-frontier parent validation failed");
    if (!live_counts_initialized_ || cursor_ > rows_.size() ||
        rows_consumed_ != cursor_ ||
        rows_consumed_ != initial_once_returns_ +
                              initial_skipped_preassigned_falsifying_ +
                              initial_skipped_preassigned_rescue_ ||
        initial_releases_ != contrast_enqueued_ ||
        contrast_returns_ > contrast_enqueued_ ||
        contrast_releases_ > contrast_returns_ ||
        cb_decide_calls_ != parent_nonzero_returns_ + parent_zero_returns_ ||
        cb_decide_calls_ != outer_nonzero_returns_ + outer_zero_returns_ ||
        outer_nonzero_returns_ !=
            parent_nonzero_returns_ + initial_once_returns_ +
                contrast_returns_ ||
        events_.size() != initial_once_returns_ + contrast_returns_ ||
        release_order_.size() != initial_releases_ ||
        count_frontier_bits(consumed_state_) != rows_consumed_ ||
        count_frontier_bits(initial_returned_state_) != initial_once_returns_ ||
        count_frontier_bits(initial_released_state_) != initial_releases_ ||
        count_frontier_bits(contrast_enqueued_state_) != contrast_enqueued_ ||
        count_frontier_bits(contrast_returned_state_) != contrast_returns_ ||
        count_frontier_bits(contrast_released_state_) != contrast_releases_ ||
        count_frontier_bits(skipped_falsifying_state_) !=
            initial_skipped_preassigned_falsifying_ ||
        count_frontier_bits(skipped_rescue_state_) !=
            initial_skipped_preassigned_rescue_ ||
        count_frontier_bits(contrast_deferred_assigned_state_) !=
            contrast_deferred_assigned_ ||
        initial_return_sequence_.size() != 4U * initial_once_returns_ ||
        initial_release_sequence_.size() != 4U * initial_releases_ ||
        contrast_return_sequence_.size() != 4U * contrast_returns_ ||
        contrast_release_sequence_.size() != 4U * contrast_releases_ ||
        queue_size() > maximum_queue_size_ ||
        maximum_queue_size_ > rows_.size() ||
        live_false_literal_count_ + live_true_literal_count_ +
                live_unassigned_literal_count_ !=
            selected_clause_.size())
      throw std::runtime_error("causal-frontier telemetry differs");

    for (size_t index = 0; index < rows_.size(); ++index) {
      const bool consumed = frontier_bit(consumed_state_, index);
      const bool initial = frontier_bit(initial_returned_state_, index);
      const bool released = frontier_bit(initial_released_state_, index);
      const bool enqueued = frontier_bit(contrast_enqueued_state_, index);
      const bool contrast = frontier_bit(contrast_returned_state_, index);
      const bool contrast_released =
          frontier_bit(contrast_released_state_, index);
      const bool skipped_falsifying =
          frontier_bit(skipped_falsifying_state_, index);
      const bool skipped_rescue = frontier_bit(skipped_rescue_state_, index);
      if (consumed != (index < cursor_) ||
          static_cast<unsigned>(initial) +
                  static_cast<unsigned>(skipped_falsifying) +
                  static_cast<unsigned>(skipped_rescue) >
              1U ||
          (initial && !consumed) || (released && !initial) ||
          (enqueued != released) || (contrast && !enqueued) ||
          (contrast_released && !contrast))
        throw std::runtime_error("causal-frontier plan-state subset differs");
      const FrontierPairRecord &pair = pairs_[index];
      if (pair.clause_literal != rows_[index].clause_literal ||
          pair.initial_literal != rows_[index].initial_literal ||
          (initial != static_cast<bool>(pair.initial_return_call)) ||
          (released != static_cast<bool>(pair.initial_release_after_call)) ||
          (contrast != static_cast<bool>(pair.contrast_return_call)) ||
          (contrast_released !=
           static_cast<bool>(pair.contrast_release_after_call)))
        throw std::runtime_error("causal-frontier pair record differs");
    }
    uint64_t prior_event_call = 0;
    std::set<std::pair<size_t, bool>> unique_events;
    for (const FrontierSubstitutionEvent &event : events_) {
      if (!event.call || event.call > cb_decide_calls_ ||
          event.call <= prior_event_call || event.plan_index >= rows_.size() ||
          !unique_events.insert({event.plan_index, event.contrast}).second)
        throw std::runtime_error("causal-frontier event order differs");
      prior_event_call = event.call;
      const FrontierRow &row = rows_[event.plan_index];
      const int expected =
          event.contrast ? row.clause_literal : row.initial_literal;
      if (event.literal != expected)
        throw std::runtime_error("causal-frontier event payload differs");
    }
    size_t prior_release_index = 0;
    for (const uint32_t encoded_index : release_order_) {
      const size_t index = encoded_index;
      if (index >= rows_.size() ||
          !frontier_bit(initial_released_state_, index))
        throw std::runtime_error("causal-frontier release order differs");
      if (prior_release_index && index == release_order_[prior_release_index - 1U])
        throw std::runtime_error("causal-frontier release order repeats");
      ++prior_release_index;
    }
    if ((parent_zero_returns_ == 0) != (first_parent_zero_call_ == 0) ||
        ((initial_once_returns_ + contrast_returns_ == 0) !=
         (first_frontier_return_call_ == 0)) ||
        ((outer_zero_returns_ == 0) != (first_outer_zero_call_ == 0)) ||
        (contrast_returns_ && cursor_ != rows_.size()))
      throw std::runtime_error("causal-frontier fallback causality differs");
  }

  ReleaseContrastGroupedJointScoreSieve parent_;
  FrontierPlan plan_;
  std::vector<int8_t> assignment_;
  std::vector<FrontierTrailEntry> trail_;
  size_t current_level_ = 0;
  std::vector<int> selected_clause_;
  std::vector<size_t> selected_clause_locals_;
  std::vector<FrontierRow> rows_;
  std::vector<FrontierPairRecord> pairs_;
  size_t cursor_ = 0;
  size_t rows_consumed_ = 0;
  size_t initial_once_returns_ = 0;
  size_t initial_skipped_preassigned_falsifying_ = 0;
  size_t initial_skipped_preassigned_rescue_ = 0;
  size_t initial_releases_ = 0;
  size_t contrast_enqueued_ = 0;
  size_t contrast_returns_ = 0;
  size_t contrast_releases_ = 0;
  size_t contrast_deferred_assigned_ = 0;
  size_t maximum_queue_size_ = 0;
  uint64_t cb_decide_calls_ = 0;
  uint64_t parent_nonzero_returns_ = 0;
  uint64_t parent_zero_returns_ = 0;
  uint64_t outer_nonzero_returns_ = 0;
  uint64_t outer_zero_returns_ = 0;
  uint64_t first_parent_zero_call_ = 0;
  uint64_t first_frontier_return_call_ = 0;
  uint64_t first_outer_zero_call_ = 0;
  uint64_t assignment_literals_observed_ = 0;
  bool live_counts_initialized_ = false;
  size_t live_false_literal_count_ = 0;
  size_t live_true_literal_count_ = 0;
  size_t live_unassigned_literal_count_ = 0;
  size_t minimum_live_false_literal_count_ = 0;
  size_t minimum_live_true_literal_count_ = 0;
  size_t minimum_live_unassigned_literal_count_ = 0;
  bool prior_distance_reached_ = false;
  bool unit_distance_reached_ = false;
  std::string consumed_state_;
  std::string initial_returned_state_;
  std::string initial_released_state_;
  std::string contrast_enqueued_state_;
  std::string contrast_returned_state_;
  std::string contrast_released_state_;
  std::string skipped_falsifying_state_;
  std::string skipped_rescue_state_;
  std::string contrast_deferred_assigned_state_;
  std::string initial_return_sequence_;
  std::string initial_release_sequence_;
  std::string contrast_return_sequence_;
  std::string contrast_release_sequence_;
  std::vector<uint32_t> release_order_;
  std::vector<FrontierSubstitutionEvent> events_;
  Sha256 outer_return_sha256_;
};

struct SplitRankedArguments {
  RankedArguments ranked;
  std::string rank_vault_path;
};

SplitRankedArguments parse_split_ranked_arguments(int argc, char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string rank_vault_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("split-ranked arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--rank-vault") {
      if (!rank_vault_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("rank-vault argument differs");
      rank_vault_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (rank_vault_path.empty())
    throw std::runtime_error("rank-vault argument is missing");
  return {parse_ranked_arguments(static_cast<int>(filtered.size()),
                                 filtered.data()),
          std::move(rank_vault_path)};
}

struct FrontierArguments {
  SplitRankedArguments split;
  std::string frontier_plan_path;
};

FrontierArguments parse_frontier_arguments(int argc, char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string frontier_plan_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("frontier arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--frontier-plan") {
      if (!frontier_plan_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("frontier-plan argument differs");
      frontier_plan_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (frontier_plan_path.empty())
    throw std::runtime_error("frontier-plan argument is missing");
  return {parse_split_ranked_arguments(static_cast<int>(filtered.size()),
                                       filtered.data()),
          std::move(frontier_plan_path)};
}

void print_v14_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v14 --cnf PATH "
               "--potential PATH --grouping PATH --rank-vault PATH "
               "--vault-in PATH --rank-table PATH --frontier-plan PATH "
               "--threshold FLOAT --conflict-limit N [--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v14_usage();
      return 0;
    }
    const FrontierArguments frontier_arguments =
        parse_frontier_arguments(argc, argv);
    const SplitRankedArguments &split_arguments = frontier_arguments.split;
    const RankedArguments &ranked_arguments = split_arguments.ranked;
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("causal-frontier reader requires seed zero");
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
    const std::string rank_vault_payload =
        read_bounded_vault_file(split_arguments.rank_vault_path);
    const std::string active_vault_payload =
        read_bounded_vault_file(grouped_arguments.vault_path);
    if (rank_vault_payload.size() < kVaultIdentityPrefixBytes ||
        active_vault_payload.size() < kVaultIdentityPrefixBytes ||
        rank_vault_payload.compare(0, kVaultIdentityPrefixBytes,
                                   active_vault_payload, 0,
                                   kVaultIdentityPrefixBytes) != 0)
      throw std::runtime_error("rank-source and active-vault identity differs");
    const std::string frontier_plan_payload =
        read_bounded_frontier_file(frontier_arguments.frontier_plan_path);
    FrontierPlan frontier_plan = parse_frontier_plan(frontier_plan_payload);
    if (frontier_plan.active_vault_sha256 != sha256(active_vault_payload))
      throw std::runtime_error("causal-frontier active vault digest differs");
    const std::string rank_payload =
        read_binary_file(ranked_arguments.rank_table_path, "rank table");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);
    const std::string rank_source_vault_sha256 = sha256(rank_vault_payload);

#ifdef O1_CRYPTO_LAB_O1C76_PUBLIC_FIXTURE
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

    std::unique_ptr<CausalFrontierGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
          !solver.set("quiet", 1) || !solver.set("factor", 0) ||
          !solver.set("lucky", 0) || !solver.set("walk", 0) ||
          !solver.set("rephase", 0) || !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic causal-frontier options");
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
      propagator = std::make_unique<CausalFrontierGroupedJointScoreSieve>(
          std::move(field), grouping_payload, active_vault_payload, cnf_sha256,
          potential_sha256, arguments.threshold, std::move(rank),
          std::move(vote_field), potential_source_sha256,
          std::move(frontier_plan));
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
          << "{\"schema\":\"" << kV14ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV12ImplementationParentSchema
          << "\",\"implementation_release_parent_schema\":\""
          << kV14ReleaseParentSchema
          << "\",\"rank_source_vault_sha256\":\""
          << rank_source_vault_sha256
          << "\",\"frontier_plan_sha256\":\""
          << sha256(frontier_plan_payload);
      out << "\",\"frontier_source_result_sha256\":\"";
      // The wrapper owns the moved plan; its telemetry repeats and validates
      // the exact source digest, while this top-level field is written below
      // from a fresh parse to keep provenance explicit.
      const FrontierPlan output_plan = parse_frontier_plan(frontier_plan_payload);
      out << output_plan.source_result_sha256 << "\",\"reader\":{";
      propagator->write_reader_json(out);
      out << "},\"frontier\":{";
      propagator->write_frontier_json(out);
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
    std::cerr << "cadical_o1_joint_score_sieve_v14: " << error.what() << '\n';
    return 1;
  }
}
