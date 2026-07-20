// O1C-0080 exact same-parent one-bit child-bound reader over the unchanged
// native v6 grouped score/vault core and O1C79 synchronized assignment shadow.
//
// The v11-v16 translation units are included only as frozen parsers and plan
// validators.  No legacy reader wrapper is constructed at runtime.  All six
// decision origins share one typed token lifecycle, so an assignment with the
// same variable but a foreign sign/origin cannot release a historical row.

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

#ifdef O1_CRYPTO_LAB_O1C80_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C80_UNDEF_O1C78_FIXTURE
#endif
namespace o1c79_embedded_v16 {
#include "cadical_o1_joint_score_sieve_v16.cpp"
} // namespace o1c79_embedded_v16
#ifdef O1_CRYPTO_LAB_O1C80_UNDEF_O1C78_FIXTURE
#undef O1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C80_UNDEF_O1C78_FIXTURE
#endif

#include "o1c80_decision_ownership.hpp"
#include "o1c80_one_bit_bound.hpp"

using namespace o1c79_embedded_v16;

namespace {

constexpr const char *kV18ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v18";
constexpr const char *kCentralReaderSchema =
    "o1-256-central-composed-reader-v2";
constexpr const char *kOneBitBoundReaderSchema =
    "o1-256-exact-one-bit-child-bound-reader-v1";
constexpr const char *kCentralOperator =
    "single-owner-bound-losing-child-prefix-rank-original-rank-contrast-"
    "frontier-initial-frontier-contrast-over-unchanged-v6";
constexpr const char *kCentralSelectionRule =
    "BOUND_LOSING_CHILD-reconsider-every-parent;PREFIX-until-consumed;"
    "RANK_ORIGINAL-until-consumed;released-"
    "RANK_CONTRAST;FRONTIER_INITIAL-until-consumed;released-"
    "FRONTIER_CONTRAST;base-zero";
constexpr const char *kCentralReleaseRule =
    "retire-every-token-bound-above-backtrack-level-atomically;enqueue-"
    "contrast-only-from-token-origin-and-row;confirmation-not-required";
constexpr const char *kSignedI32SequenceEncoding =
    "concatenated-signed-i32le-literals";
constexpr size_t kMaximumCallbackRecords = 4194304U;
constexpr size_t kMaximumRecordedBoundProbeEvents = 16384U;
constexpr const char *kOneBitCandidateOrderRule =
    "effective-rank-order-then-omitted-key-variables-ascending;unassigned-"
    "coordinates-reconsidered-at-every-parent";
constexpr const char *kOneBitBoundRule =
    "copied-parent-assignment;same-v6-compatibility-groups;bit0-spin-minus1-"
    "literal-minus-v;bit1-spin-plus1-literal-plus-v;upward-exact-sum";
constexpr const char *kOneBitDecisionRule =
    "strict-U-less-than-tau;equality-live;one-dead-propose-losing-child;both-"
    "dead-propose-lower-U;exact-tie-bit0";
constexpr const char *kOneBitRealizedPruneRule =
    "matching-bound-token-and-losing-assignment-plus-v6-threshold-prune-"
    "trail-prune-queued-canonical-no-good-lifecycle";
constexpr const char *kProductionPage7ActiveVaultSha256 =
    "92b6e547e143cdaf2f28fe731fd356bc69806926ee569205d6def432144258ff";
constexpr const char *kProductionPage7FrontierPlanSha256 =
    "321582ee831aca3820af944d4a4ca700bbb3eff22f26b8f532b6c16d1498be95";
constexpr const char *kProductionPage7StagingPlanSha256 =
    "83a73291160b6232c6fb834185476b1e6a6d6c0774c0d8ea5b0a434d6833aac0";
constexpr size_t kProductionPage7FrontierPlanBytes = 4479U;
constexpr size_t kProductionPage7StagingPlanBytes = 4477U;

struct CentralTrailEntry {
  uint32_t local = 0;
  uint32_t level = 0;
};

struct CentralRow {
  uint32_t local = 0;
  int initial_literal = 0;
  int contrast_literal = 0;
};

struct CentralReturnEvent {
  uint64_t call = 0;
  o1c80::DecisionOrigin origin = o1c80::DecisionOrigin::PREFIX;
  uint32_t row = 0;
  int literal = 0;
  uint64_t token = 0;
};

struct BoundStateDigest {
  std::string assignment_sha256;
  std::string trail_sha256;
  std::string pending_sha256;
  std::string group_cache_sha256;
  std::string trace_sha256;
  std::string counters_sha256;

  bool operator==(const BoundStateDigest &other) const {
    return assignment_sha256 == other.assignment_sha256 &&
           trail_sha256 == other.trail_sha256 &&
           pending_sha256 == other.pending_sha256 &&
           group_cache_sha256 == other.group_cache_sha256 &&
           trace_sha256 == other.trace_sha256 &&
           counters_sha256 == other.counters_sha256;
  }
};

struct V6LifecycleSnapshot {
  BoundStateDigest state;
  uint64_t threshold_prunes = 0;
  uint64_t trail_threshold_prunes = 0;
  uint64_t external_clauses_queued = 0;
  uint64_t external_clauses_emitted = 0;
  uint64_t pending_clause_count = 0;
  std::string pending_state;
};

struct BoundProbeEvent {
  uint64_t call = 0;
  uint64_t probe = 0;
  uint32_t coordinate_index = 0;
  uint32_t parent_level = 0;
  int variable = 0;
  std::string parent_assignment_sha256;
  o1c80::ChildUpperBounds bounds;
  o1c80::ChildSelectionClass selection =
      o1c80::ChildSelectionClass::NEITHER_PRUNABLE;
  int losing_literal = 0;
  uint64_t proposal_token = 0;
  BoundStateDigest state_before;
  BoundStateDigest state_after;
};

struct BoundIntervention {
  uint64_t token = 0;
  uint64_t call = 0;
  uint64_t probe = 0;
  uint32_t coordinate_index = 0;
  int variable = 0;
  uint32_t parent_level = 0;
  uint32_t level_bound = 0;
  std::string parent_assignment_sha256;
  o1c80::ChildUpperBounds bounds;
  o1c80::ChildSelectionClass selection =
      o1c80::ChildSelectionClass::NEITHER_PRUNABLE;
  int losing_literal = 0;
  BoundStateDigest state_before;
  BoundStateDigest state_after;
  bool matching_assignment_observed = false;
  int observed_literal = 0;
  uint64_t v6_threshold_prunes_before = 0;
  uint64_t v6_threshold_prunes_after = 0;
  uint64_t v6_trail_threshold_prunes_before = 0;
  uint64_t v6_trail_threshold_prunes_after = 0;
  uint64_t v6_external_clauses_queued_before = 0;
  uint64_t v6_external_clauses_queued_after = 0;
  uint64_t v6_pending_clause_count_before = 0;
  uint64_t v6_pending_clause_count_after = 0;
  std::string v6_pending_clause_sha256_before;
  std::string v6_pending_clause_sha256_after;
  std::string v6_trace_sha256_before;
  std::string v6_trace_sha256_after;
  std::vector<int> no_good_literals;
  std::string no_good_clause_sha256;
  bool realized_prune = false;
  bool fully_emitted = false;
  uint64_t fully_emitted_index = 0;
  bool released = false;
  bool unobserved_release = false;
};

void central_append_i32(std::string &payload, int literal) {
  append_u32_le(payload,
                static_cast<uint32_t>(static_cast<int32_t>(literal)));
}

bool central_literal_true(int literal, int8_t sign) {
  return sign && ((literal > 0) == (sign > 0));
}

void central_write_sequence(std::ostream &out, const char *prefix,
                            const std::string &payload, uint64_t count) {
  if (payload.size() != 4U * count)
    throw std::runtime_error("central reader sequence size differs");
  out << ",\"" << prefix << "_encoding\":\""
      << kSignedI32SequenceEncoding << "\",\"" << prefix
      << "_count\":" << count << ",\"" << prefix
      << "_bytes\":" << payload.size() << ",\"" << prefix
      << "_hex\":\"" << bytes_hex(payload) << "\",\"" << prefix
      << "_sha256\":\"" << sha256(payload) << '"';
}

uint64_t json_u64_field(const std::string &payload, const char *field) {
  const std::string marker = std::string("\"") + field + "\":";
  const size_t start = payload.find(marker);
  if (start == std::string::npos)
    throw std::runtime_error(std::string("v6 telemetry omits ") + field);
  size_t cursor = start + marker.size();
  if (cursor == payload.size() || payload[cursor] < '0' ||
      payload[cursor] > '9')
    throw std::runtime_error(std::string("v6 telemetry field differs: ") +
                             field);
  uint64_t result = 0;
  do {
    const unsigned digit = static_cast<unsigned>(payload[cursor] - '0');
    if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10U)
      throw std::runtime_error(std::string("v6 telemetry field overflows: ") +
                               field);
    result = result * 10U + digit;
    ++cursor;
  } while (cursor < payload.size() && payload[cursor] >= '0' &&
           payload[cursor] <= '9');
  return result;
}

std::string json_string_field(const std::string &payload, const char *field) {
  const std::string marker = std::string("\"") + field + "\":\"";
  const size_t start = payload.find(marker);
  if (start == std::string::npos)
    throw std::runtime_error(std::string("v6 telemetry omits ") + field);
  const size_t value_start = start + marker.size();
  const size_t stop = payload.find('"', value_start);
  if (stop == std::string::npos)
    throw std::runtime_error(std::string("v6 telemetry string differs: ") +
                             field);
  return payload.substr(value_start, stop - value_start);
}

void write_bound_state_digest(std::ostream &out,
                              const BoundStateDigest &state) {
  out << "{\"assignment_sha256\":\"" << state.assignment_sha256
      << "\",\"trail_sha256\":\"" << state.trail_sha256
      << "\",\"pending_sha256\":\"" << state.pending_sha256
      << "\",\"group_cache_sha256\":\"" << state.group_cache_sha256
      << "\",\"trace_sha256\":\"" << state.trace_sha256
      << "\",\"counters_sha256\":\"" << state.counters_sha256 << "\"}";
}

std::vector<int> pending_clause_literals(const std::string &pending) {
  size_t cursor = 0;
  const uint32_t length =
      read_u32_le(pending, cursor, "O1C80 pending clause length");
  (void)read_u32_le(pending, cursor, "O1C80 pending clause cursor");
  if (cursor > pending.size() || pending.size() - cursor < 2U)
    throw std::runtime_error("O1C80 pending clause flags are truncated");
  const bool ready = pending[cursor++] != 0;
  const bool blocking = pending[cursor++] != 0;
  if (pending.size() - cursor != 4U * static_cast<size_t>(length) ||
      ready != blocking || (length && !ready))
    throw std::runtime_error("O1C80 pending clause state differs");
  std::vector<int> result;
  result.reserve(length);
  for (uint32_t index = 0; index < length; ++index)
    result.push_back(static_cast<int32_t>(
        read_u32_le(pending, cursor, "O1C80 pending clause literal")));
  return result;
}

o1c80::ExactOneBitBoundReader build_one_bit_bound_reader(
    const PotentialField &field, const std::string &grouping_payload,
    const std::string &potential_sha256) {
  std::vector<int> observed;
  for (const PotentialFactor &factor : field.factors)
    observed.insert(observed.end(), factor.variables.begin(),
                    factor.variables.end());
  std::sort(observed.begin(), observed.end());
  observed.erase(std::unique(observed.begin(), observed.end()), observed.end());
  if (observed.empty())
    throw std::runtime_error("O1C80 potential observes no variables");
  if (grouping_payload.size() < kGroupingMagic.size() + 32U + 10U ||
      std::string_view(grouping_payload.data(), kGroupingMagic.size()) !=
          kGroupingMagic)
    throw std::runtime_error("O1C80 compatibility grouping header differs");
  size_t cursor = kGroupingMagic.size();
  const std::string bound_potential_sha256 =
      bytes_hex(grouping_payload.substr(cursor, 32U));
  cursor += 32U;
  const uint16_t width_cap =
      read_u16_le(grouping_payload, cursor, "O1C80 grouping width");
  const uint32_t factor_count =
      read_u32_le(grouping_payload, cursor, "O1C80 grouping factor count");
  const uint32_t group_count =
      read_u32_le(grouping_payload, cursor, "O1C80 grouping group count");
  if (bound_potential_sha256 != potential_sha256 ||
      width_cap != kRequiredCompatibilityWidth ||
      width_cap > kMaximumCompatibilityWidth ||
      factor_count != field.factors.size() || !group_count ||
      group_count > factor_count)
    throw std::runtime_error("O1C80 compatibility grouping identity differs");

  std::vector<uint8_t> seen(field.factors.size(), 0U);
  size_t previous_minimum = field.factors.size();
  std::vector<o1c80::BoundCompatibilityGroup> groups;
  groups.reserve(group_count);
  for (uint32_t group_index = 0; group_index < group_count; ++group_index) {
    const uint32_t member_count =
        read_u32_le(grouping_payload, cursor, "O1C80 grouping member count");
    if (!member_count || member_count > factor_count)
      throw std::runtime_error("O1C80 grouping member count differs");
    std::vector<size_t> factor_indices;
    factor_indices.reserve(member_count);
    for (uint32_t member = 0; member < member_count; ++member) {
      const uint32_t factor_index = read_u32_le(
          grouping_payload, cursor, "O1C80 grouping factor index");
      if (factor_index >= seen.size() || seen[factor_index] ||
          (!factor_indices.empty() &&
           factor_index <= factor_indices.back()))
        throw std::runtime_error("O1C80 grouping membership differs");
      seen[factor_index] = 1U;
      factor_indices.push_back(factor_index);
    }
    if (group_index && factor_indices.front() <= previous_minimum)
      throw std::runtime_error("O1C80 grouping order differs");
    previous_minimum = factor_indices.front();
    const uint16_t width = read_u16_le(
        grouping_payload, cursor, "O1C80 grouping variable width");
    if (!width || width > width_cap)
      throw std::runtime_error("O1C80 grouping variable width differs");
    std::vector<int> variables;
    variables.reserve(width);
    for (uint16_t position = 0; position < width; ++position) {
      const uint32_t variable =
          read_u32_le(grouping_payload, cursor, "O1C80 grouping variable");
      if (!variable || variable > static_cast<uint32_t>(kMaximumVariables) ||
          (!variables.empty() &&
           variable <= static_cast<uint32_t>(variables.back())))
        throw std::runtime_error("O1C80 grouping variable differs");
      variables.push_back(static_cast<int>(variable));
    }
    std::vector<int> expected_variables;
    for (const size_t factor_index : factor_indices)
      expected_variables = union_scope(
          expected_variables, field.factors.at(factor_index).variables);
    if (variables != expected_variables)
      throw std::runtime_error("O1C80 grouping scope differs");

    o1c80::BoundCompatibilityGroup group;
    for (const int variable : variables) {
      const auto found =
          std::lower_bound(observed.begin(), observed.end(), variable);
      if (found == observed.end() || *found != variable)
        throw std::runtime_error("O1C80 grouping local mapping differs");
      group.local_indices.push_back(
          static_cast<size_t>(found - observed.begin()));
    }
    group.energies.resize(size_t{1} << variables.size());
    for (size_t row = 0; row < group.energies.size(); ++row) {
      ExactDoubleSum exact;
      for (const size_t factor_index : factor_indices) {
        const PotentialFactor &factor = field.factors.at(factor_index);
        const size_t factor_row =
            project_union_row(row, variables, factor.variables);
        exact.add(factor.energies.at(factor_row));
      }
      group.energies[row] =
          upward_exact_sum(exact, "O1C80 compatibility group energy");
    }
    groups.push_back(std::move(group));
  }
  if (cursor != grouping_payload.size() ||
      std::find(seen.begin(), seen.end(), uint8_t{0}) != seen.end())
    throw std::runtime_error("O1C80 grouping coverage differs");
  return o1c80::ExactOneBitBoundReader(
      std::move(observed), kKeyBits, field.offset, std::move(groups));
}

class CentralOwnershipGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  CentralOwnershipGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold, RankTable rank,
      RankVoteField vote_field, std::string potential_source_sha256,
      FrontierPlan frontier_plan, StagingPlan staging_plan,
      PrefixPlan prefix_plan, std::string active_vault_sha256,
      std::string rank_source_vault_sha256,
      std::string frontier_plan_sha256,
      std::string staging_plan_sha256)
      : one_bit_reader_(build_one_bit_bound_reader(
            field, grouping_payload, potential_sha256)),
        base_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
              potential_sha256, threshold),
        rank_(std::move(rank)), vote_field_(std::move(vote_field)),
        frontier_plan_(std::move(frontier_plan)),
        staging_plan_(std::move(staging_plan)),
        prefix_plan_(std::move(prefix_plan)),
        potential_sha256_(potential_sha256),
        potential_source_sha256_(std::move(potential_source_sha256)),
        grouping_sha256_(sha256(grouping_payload)),
        active_vault_sha256_(std::move(active_vault_sha256)),
        rank_source_vault_sha256_(std::move(rank_source_vault_sha256)),
        frontier_plan_sha256_(std::move(frontier_plan_sha256)),
        staging_plan_sha256_(std::move(staging_plan_sha256)),
        threshold_(threshold) {
    const std::vector<int> &observed = base_.observed();
    assignment_.assign(observed.size(), 0);

    prefix_rows_.reserve(prefix_plan_.literals.size());
    for (const int literal : prefix_plan_.literals)
      prefix_rows_.push_back(
          {static_cast<uint32_t>(local(std::abs(literal))), literal, 0});

    rank_rows_.reserve(rank_.rows.size());
    std::set<int> rank_variables;
    for (RankRow &row : rank_.rows) {
      if (!rank_variables.insert(row.variable).second)
        throw std::runtime_error("central reader rank variable repeats");
      row.local = local(row.variable);
      rank_rows_.push_back({static_cast<uint32_t>(row.local), row.literal,
                            -row.literal});
    }

    std::vector<bool> candidate_seen(kKeyBits + 1U, false);
    for (const RankRow &row : rank_.rows) {
      if (row.variable <= 0 ||
          static_cast<size_t>(row.variable) > kKeyBits ||
          candidate_seen.at(static_cast<size_t>(row.variable)))
        continue;
      candidate_seen[static_cast<size_t>(row.variable)] = true;
      one_bit_candidates_.push_back(row.variable);
      ++ranked_one_bit_candidates_;
    }
    for (size_t variable = 1; variable <= kKeyBits; ++variable) {
      if (candidate_seen[variable] ||
          !std::binary_search(observed.begin(), observed.end(),
                              static_cast<int>(variable)))
        continue;
      candidate_seen[variable] = true;
      one_bit_candidates_.push_back(static_cast<int>(variable));
      ++omitted_one_bit_candidates_;
    }
    if (one_bit_candidates_.empty() ||
        one_bit_candidates_.size() != ranked_one_bit_candidates_ +
                                          omitted_one_bit_candidates_)
      throw std::runtime_error("one-bit child-bound candidate order differs");
    for (const int variable : one_bit_candidates_)
      central_append_i32(one_bit_candidate_order_, variable);

    if (frontier_plan_.prior_assignment.size() != observed.size() ||
        frontier_plan_.selected_union_indices.size() !=
            base_.preloaded_clauses().size() ||
        frontier_plan_.selected_active_index >=
            base_.preloaded_clauses().size())
      throw std::runtime_error("central reader frontier population differs");
    validate_frontier_selection();
    selected_clause_ =
        base_.preloaded_clauses().at(frontier_plan_.selected_active_index);
    selected_clause_locals_.reserve(selected_clause_.size());
    for (const int literal : selected_clause_)
      selected_clause_locals_.push_back(local(std::abs(literal)));
    frontier_rows_.reserve(frontier_plan_.residual_clause_literals.size());
    for (size_t index = 0;
         index < frontier_plan_.residual_clause_literals.size(); ++index) {
      const int clause_literal =
          frontier_plan_.residual_clause_literals[index];
      const int initial_literal =
          frontier_plan_.falsifying_decision_literals[index];
      frontier_rows_.push_back(
          {static_cast<uint32_t>(local(std::abs(clause_literal))),
           initial_literal, clause_literal});
    }

    rank_original_returned_.assign(rank_rows_.size(), false);
    rank_original_released_.assign(rank_rows_.size(), false);
    rank_contrast_returned_.assign(rank_rows_.size(), false);
    rank_contrast_released_.assign(rank_rows_.size(), false);
    frontier_initial_returned_.assign(frontier_rows_.size(), false);
    frontier_initial_released_.assign(frontier_rows_.size(), false);
    frontier_contrast_returned_.assign(frontier_rows_.size(), false);
    frontier_contrast_released_.assign(frontier_rows_.size(), false);
    prefix_returned_.assign(prefix_rows_.size(), false);
    prefix_released_.assign(prefix_rows_.size(), false);
    update_live_clause_counts();
  }

  void notify_assignment(const std::vector<int> &literals) override {
    base_.notify_assignment(literals);
    for (const int literal : literals) {
      const size_t index = local(std::abs(literal));
      const int8_t sign = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assignment_.at(index);
      if (!slot) {
        slot = sign;
        trail_.push_back({static_cast<uint32_t>(index), current_level_});
        ++assignment_literals_observed_;
      } else if (slot != sign) {
        throw std::runtime_error(
            "central reader assignment changed without backtrack");
      }
      ownership_.notify_assignment(literal);
    }
    observe_bound_assignments(literals);
    update_live_clause_counts();
  }

  void notify_new_decision_level() override {
    if (current_level_ == std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("central reader decision level exceeds bound");
    base_.notify_new_decision_level();
    ++current_level_;
    ownership_.notify_new_decision_level(current_level_);
    if (pending_bound_intervention_ != no_intervention()) {
      BoundIntervention &intervention =
          bound_interventions_.at(pending_bound_intervention_);
      if (intervention.level_bound)
        throw std::runtime_error(
            "one-bit child-bound intervention bound twice");
      intervention.level_bound = current_level_;
      pending_bound_intervention_ = no_intervention();
      ++bound_level_bindings_;
    }
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_ ||
        new_level > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("central reader backtrack level differs");
    base_.notify_backtrack(new_level);
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t index = trail_.back().local;
      if (!assignment_.at(index))
        throw std::runtime_error("central reader trail state differs");
      assignment_[index] = 0;
      trail_.pop_back();
    }
    const std::vector<o1c80::DecisionToken> released =
        ownership_.notify_backtrack(static_cast<uint32_t>(new_level));
    for (const o1c80::DecisionToken &token : released)
      apply_release(token);
    current_level_ = static_cast<uint32_t>(new_level);
    update_live_clause_counts();
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return base_.cb_check_found_model(model);
  }

  int cb_decide() override {
    if (solve_finalized_)
      throw std::runtime_error("central reader callback after solve end");
    if (ownership_.has_pending())
      throw std::runtime_error("central reader callback overlaps proposal");
    if (callback_calls_ >= kMaximumCallbackRecords)
      throw std::runtime_error("central reader callback cap exceeded");
    if (base_.cb_decide() != 0)
      throw std::runtime_error("central reader v6 callback differs");
    const uint64_t call = ++callback_calls_;

    int result = select_bound_losing_child(call);
    if (!result)
      result = select_prefix(call);
    if (!result)
      result = select_rank_original(call);
    if (!result && rank_cursor_ == rank_rows_.size())
      result = select_rank_contrast(call);
    if (!result && rank_cursor_ == rank_rows_.size() &&
        rank_contrast_exhausted())
      result = select_frontier_initial(call);
    if (!result && frontier_cursor_ == frontier_rows_.size())
      result = select_frontier_contrast(call);

    central_append_i32(returned_sequence_, result);
    if (result)
      ++nonzero_returns_;
    else
      ++zero_returns_;
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
    const int result = base_.cb_add_external_clause_lit();
    if (!result && emitting_bound_intervention_ != no_intervention()) {
      BoundIntervention &intervention =
          bound_interventions_.at(emitting_bound_intervention_);
      if (!intervention.realized_prune || intervention.fully_emitted)
        throw std::runtime_error(
            "one-bit child-bound emission lifecycle differs");
      const V6LifecycleSnapshot after = v6_snapshot();
      if (after.external_clauses_emitted !=
          intervention.fully_emitted_index + 1U)
        throw std::runtime_error(
            "one-bit child-bound emitted index differs");
      intervention.fully_emitted = true;
      emitting_bound_intervention_ = no_intervention();
      ++bound_fully_emitted_;
    }
    return result;
  }

  const std::vector<int> &observed() const { return base_.observed(); }
  const std::vector<std::vector<int>> &preloaded_clauses() const {
    return base_.preloaded_clauses();
  }
  void attach_solver(CaDiCaL::Solver *solver) { base_.attach_solver(solver); }

  void finalize_after_solve() {
    if (solve_finalized_)
      throw std::runtime_error("central reader solve end finalized twice");
    ownership_.validate_solve_end();
    solve_finalized_ = true;
  }

  void write_json(std::ostream &out) const { base_.write_json(out); }
  void write_vault_json(std::ostream &out) const {
    base_.write_vault_json(out);
  }
  void write_ownership_json(std::ostream &out) const {
    ownership_.write_json(out);
  }

  void write_one_bit_bound_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kOneBitBoundReaderSchema
        << "\",\"operator\":\"same-parent-exact-one-bit-U0-U1-losing-"
           "child-selector\""
        << ",\"runtime_parent_schema\":\""
        << "o1-256-cadical-joint-score-sieve-result-v6"
        << "\",\"candidate_order_rule\":\"" << kOneBitCandidateOrderRule
        << "\",\"bound_rule\":\"" << kOneBitBoundRule
        << "\",\"decision_rule\":\"" << kOneBitDecisionRule
        << "\",\"realized_prune_rule\":\"" << kOneBitRealizedPruneRule
        << "\",\"key_variable_count\":" << kKeyBits
        << ",\"threshold\":" << threshold_
        << ",\"threshold_f64le_hex\":\"" << f64_le_hex(threshold_)
        << "\",\"candidate_count\":" << one_bit_candidates_.size()
        << ",\"ranked_candidate_count\":" << ranked_one_bit_candidates_
        << ",\"omitted_candidate_count\":" << omitted_one_bit_candidates_
        << ",\"parent_scans\":" << bound_parent_scans_
        << ",\"probe_count\":" << bound_probe_count_
        << ",\"child_bound_evaluations\":" << bound_child_evaluations_
        << ",\"recorded_probe_event_count\":" << bound_probe_events_.size()
        << ",\"omitted_probe_event_count\":"
        << bound_probe_events_omitted_
        << ",\"probe_trace_encoding\":\"u64le-call;u64le-probe;u32le-"
           "coordinate;u32le-parent-level;i32le-variable;f64le-U0;f64le-U1;"
           "f64le-tau;u8-"
           "selection;i32le-losing-literal\""
        << ",\"probe_trace_count\":" << bound_probe_count_
        << ",\"probe_trace_bytes\":" << bound_probe_trace_bytes_
        << ",\"probe_trace_sha256\":\""
        << bound_probe_trace_.hex_digest()
        << "\",\"proposals\":" << bound_proposals_
        << ",\"level_bindings\":" << bound_level_bindings_
        << ",\"matching_assignments_observed\":"
        << bound_matching_assignments_
        << ",\"realized_prunes\":" << bound_realized_prunes_
        << ",\"fully_emitted_prunes\":" << bound_fully_emitted_
        << ",\"releases\":" << bound_releases_
        << ",\"live_tokens\":" << bound_proposals_ - bound_releases_
        << ",\"unobserved_releases\":" << bound_unobserved_releases_
        << ",\"class_counts\":{\"NEITHER_PRUNABLE\":"
        << bound_class_counts_[static_cast<size_t>(
               o1c80::ChildSelectionClass::NEITHER_PRUNABLE)]
        << ",\"ZERO_PRUNABLE\":"
        << bound_class_counts_[static_cast<size_t>(
               o1c80::ChildSelectionClass::ZERO_PRUNABLE)]
        << ",\"ONE_PRUNABLE\":"
        << bound_class_counts_[static_cast<size_t>(
               o1c80::ChildSelectionClass::ONE_PRUNABLE)]
        << ",\"BOTH_PRUNABLE\":"
        << bound_class_counts_[static_cast<size_t>(
               o1c80::ChildSelectionClass::BOTH_PRUNABLE)]
        << "},\"minimum_witness_tie_rule\":\"smaller-min-U0-U1;then-"
           "smaller-call;then-smaller-coordinate-index;then-smaller-variable\""
        << ",\"minimum_child_upper\":";
    if (have_minimum_child_upper_)
      out << minimum_child_upper_;
    else
      out << "null";
    out << ",\"minimum_child_upper_f64le_hex\":";
    if (have_minimum_child_upper_)
      out << '"' << f64_le_hex(minimum_child_upper_) << '"';
    else
      out << "null";
    out << ",\"minimum_child_margin\":";
    if (have_minimum_child_upper_)
      out << minimum_child_upper_ - threshold_;
    else
      out << "null";
    out << ",\"minimum_child_variable\":";
    if (have_minimum_child_upper_)
      out << minimum_child_variable_;
    else
      out << "null";
    out << ",\"minimum_upper_zero\":";
    if (have_minimum_child_upper_)
      out << minimum_child_bounds_.zero;
    else
      out << "null";
    out << ",\"minimum_upper_zero_f64le_hex\":";
    if (have_minimum_child_upper_)
      out << '"' << f64_le_hex(minimum_child_bounds_.zero) << '"';
    else
      out << "null";
    out << ",\"minimum_upper_one\":";
    if (have_minimum_child_upper_)
      out << minimum_child_bounds_.one;
    else
      out << "null";
    out << ",\"minimum_upper_one_f64le_hex\":";
    if (have_minimum_child_upper_)
      out << '"' << f64_le_hex(minimum_child_bounds_.one) << '"';
    else
      out << "null";
    out << ",\"minimum_witness\":";
    if (!have_minimum_child_upper_) {
      out << "null";
    } else {
      const BoundProbeEvent &event = minimum_child_event_;
      out << "{\"call\":" << event.call << ",\"probe\":" << event.probe
          << ",\"parent_level\":" << event.parent_level
          << ",\"coordinate_index\":" << event.coordinate_index
          << ",\"variable\":" << event.variable
          << ",\"parent_assignment_sha256\":\""
          << event.parent_assignment_sha256 << "\",\"upper_zero\":"
          << event.bounds.zero << ",\"upper_zero_f64le_hex\":\""
          << f64_le_hex(event.bounds.zero) << "\",\"upper_one\":"
          << event.bounds.one << ",\"upper_one_f64le_hex\":\""
          << f64_le_hex(event.bounds.one) << "\",\"threshold\":"
          << threshold_ << ",\"threshold_f64le_hex\":\""
          << f64_le_hex(threshold_) << "\",\"selection_class\":\""
          << o1c80::selection_class_name(event.selection)
          << "\",\"losing_bit\":";
      if (event.losing_literal)
        out << (event.losing_literal > 0 ? 1 : 0);
      else
        out << "null";
      out << ",\"losing_spin\":";
      if (event.losing_literal)
        out << (event.losing_literal > 0 ? 1 : -1);
      else
        out << "null";
      out << ",\"losing_literal\":";
      if (event.losing_literal)
        out << event.losing_literal;
      else
        out << "null";
      out << ",\"state_before\":";
      write_bound_state_digest(out, event.state_before);
      out << ",\"state_after\":";
      write_bound_state_digest(out, event.state_after);
      out << ",\"state_unchanged\":"
          << (event.state_before == event.state_after ? "true" : "false")
          << '}';
    }
    central_write_sequence(out, "candidate_order", one_bit_candidate_order_,
                           one_bit_candidates_.size());
    out << ",\"probe_events\":[";
    for (size_t index = 0; index < bound_probe_events_.size(); ++index) {
      if (index)
        out << ',';
      const BoundProbeEvent &event = bound_probe_events_[index];
      out << "{\"call\":" << event.call << ",\"probe\":" << event.probe
          << ",\"coordinate_index\":" << event.coordinate_index
          << ",\"parent_level\":" << event.parent_level
          << ",\"variable\":" << event.variable
          << ",\"parent_assignment_sha256\":\""
          << event.parent_assignment_sha256 << "\",\"upper_zero\":"
          << event.bounds.zero << ",\"upper_zero_f64le_hex\":\""
          << f64_le_hex(event.bounds.zero) << "\",\"upper_one\":"
          << event.bounds.one << ",\"upper_one_f64le_hex\":\""
          << f64_le_hex(event.bounds.one) << "\",\"threshold\":"
          << threshold_ << ",\"threshold_f64le_hex\":\""
          << f64_le_hex(threshold_) << "\",\"selection_class\":\""
          << o1c80::selection_class_name(event.selection)
          << "\",\"losing_bit\":";
      if (event.losing_literal)
        out << (event.losing_literal > 0 ? 1 : 0);
      else
        out << "null";
      out << ",\"losing_spin\":";
      if (event.losing_literal)
        out << (event.losing_literal > 0 ? 1 : -1);
      else
        out << "null";
      out << ",\"losing_literal\":";
      if (event.losing_literal)
        out << event.losing_literal;
      else
        out << "null";
      out << ",\"proposal_token\":";
      if (event.proposal_token)
        out << event.proposal_token;
      else
        out << "null";
      out << ",\"state_before\":";
      write_bound_state_digest(out, event.state_before);
      out << ",\"state_after\":";
      write_bound_state_digest(out, event.state_after);
      out << ",\"state_unchanged\":"
          << (event.state_before == event.state_after ? "true" : "false")
          << '}';
    }
    out << "],\"interventions\":[";
    for (size_t index = 0; index < bound_interventions_.size(); ++index) {
      if (index)
        out << ',';
      const BoundIntervention &event = bound_interventions_[index];
      out << "{\"token\":" << event.token << ",\"call\":" << event.call
          << ",\"probe\":" << event.probe
          << ",\"coordinate_index\":" << event.coordinate_index
          << ",\"variable\":" << event.variable
          << ",\"parent_level\":" << event.parent_level
          << ",\"level_bound\":";
      if (event.level_bound)
        out << event.level_bound;
      else
        out << "null";
      out << ",\"origin\":\"BOUND_LOSING_CHILD\""
          << ",\"parent_assignment_sha256\":\""
          << event.parent_assignment_sha256 << "\",\"upper_zero\":"
          << event.bounds.zero << ",\"upper_zero_f64le_hex\":\""
          << f64_le_hex(event.bounds.zero) << "\",\"upper_one\":"
          << event.bounds.one << ",\"upper_one_f64le_hex\":\""
          << f64_le_hex(event.bounds.one) << "\",\"threshold\":"
          << threshold_ << ",\"threshold_f64le_hex\":\""
          << f64_le_hex(threshold_) << "\",\"selection_class\":\""
          << o1c80::selection_class_name(event.selection)
          << "\",\"losing_bit\":"
          << (event.losing_literal > 0 ? 1 : 0)
          << ",\"losing_spin\":"
          << (event.losing_literal > 0 ? 1 : -1)
          << ",\"losing_literal\":" << event.losing_literal
          << ",\"state_before\":";
      write_bound_state_digest(out, event.state_before);
      out << ",\"state_after\":";
      write_bound_state_digest(out, event.state_after);
      out << ",\"state_unchanged\":"
          << (event.state_before == event.state_after ? "true" : "false")
          << ",\"matching_assignment_observed\":"
          << (event.matching_assignment_observed ? "true" : "false")
          << ",\"observed_literal\":";
      if (event.matching_assignment_observed)
        out << event.observed_literal;
      else
        out << "null";
      out << ",\"v6_threshold_prunes_before\":"
          << event.v6_threshold_prunes_before
          << ",\"v6_threshold_prunes_after\":"
          << event.v6_threshold_prunes_after
          << ",\"v6_trail_threshold_prunes_before\":"
          << event.v6_trail_threshold_prunes_before
          << ",\"v6_trail_threshold_prunes_after\":"
          << event.v6_trail_threshold_prunes_after
          << ",\"v6_external_clauses_queued_before\":"
          << event.v6_external_clauses_queued_before
          << ",\"v6_external_clauses_queued_after\":"
          << event.v6_external_clauses_queued_after
          << ",\"v6_pending_clause_count_before\":"
          << event.v6_pending_clause_count_before
          << ",\"v6_pending_clause_count_after\":"
          << event.v6_pending_clause_count_after
          << ",\"v6_pending_clause_sha256_before\":";
      if (event.v6_pending_clause_sha256_before.empty())
        out << "null";
      else
        out << '"' << event.v6_pending_clause_sha256_before << '"';
      out << ",\"v6_pending_clause_sha256_after\":";
      if (event.v6_pending_clause_sha256_after.empty())
        out << "null";
      else
        out << '"' << event.v6_pending_clause_sha256_after << '"';
      out << ",\"v6_trace_sha256_before\":\""
          << event.v6_trace_sha256_before
          << "\",\"v6_trace_sha256_after\":\""
          << event.v6_trace_sha256_after << "\",\"no_good_literals\":[";
      for (size_t literal_index = 0;
           literal_index < event.no_good_literals.size(); ++literal_index) {
        if (literal_index)
          out << ',';
        out << event.no_good_literals[literal_index];
      }
      out << "],\"no_good_clause_sha256\":";
      if (event.no_good_clause_sha256.empty())
        out << "null";
      else
        out << '"' << event.no_good_clause_sha256 << '"';
      out << ",\"realized_prune\":"
          << (event.realized_prune ? "true" : "false")
          << ",\"fully_emitted\":"
          << (event.fully_emitted ? "true" : "false")
          << ",\"fully_emitted_index\":";
      if (event.fully_emitted)
        out << event.fully_emitted_index;
      else
        out << "null";
      out << ",\"released\":" << (event.released ? "true" : "false")
          << ",\"unobserved_release\":"
          << (event.unobserved_release ? "true" : "false") << '}';
    }
    out << ']';
  }

  void write_central_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kCentralReaderSchema
        << "\",\"operator\":\"" << kCentralOperator
        << "\",\"selection_rule\":\"" << kCentralSelectionRule
        << "\",\"release_rule\":\"" << kCentralReleaseRule
        << "\",\"runtime_parent_schema\":\""
        << "o1-256-cadical-joint-score-sieve-result-v6"
        << "\",\"rank_source_vault_sha256\":\""
        << rank_source_vault_sha256_
        << "\",\"active_vault_sha256\":\"" << active_vault_sha256_
        << "\",\"potential_sha256\":\"" << potential_sha256_
        << "\",\"potential_source_sha256\":\""
        << potential_source_sha256_
        << "\",\"grouping_sha256\":\"" << grouping_sha256_
        << "\",\"rank_table_sha256\":\"" << rank_.payload_sha256
        << "\",\"effective_rank_order_sha256\":\""
        << rank_.order_sha256 << "\",\"frontier_plan_sha256\":\""
        << frontier_plan_sha256_ << "\",\"staging_plan_sha256\":\""
        << staging_plan_sha256_ << "\",\"prefix_plan_sha256\":\""
        << prefix_plan_.payload_sha256 << "\",\"callback_calls\":"
        << callback_calls_ << ",\"nonzero_returns\":" << nonzero_returns_
        << ",\"zero_returns\":" << zero_returns_
        << ",\"assignment_literals_observed\":"
        << assignment_literals_observed_
        << ",\"bound\":{\"candidate_count\":"
        << one_bit_candidates_.size()
        << ",\"parent_scans\":" << bound_parent_scans_
        << ",\"probes\":" << bound_probe_count_
        << ",\"returns\":" << bound_proposals_
        << ",\"level_bindings\":" << bound_level_bindings_
        << ",\"matching_assignments\":" << bound_matching_assignments_
        << ",\"realized_prunes\":" << bound_realized_prunes_
        << ",\"releases\":" << bound_releases_
        << ",\"live_tokens\":" << bound_proposals_ - bound_releases_
        << ",\"unobserved_releases\":" << bound_unobserved_releases_
        << "},\"prefix\":{"
        << "\"rows\":" << prefix_rows_.size()
        << ",\"cursor\":" << prefix_cursor_
        << ",\"returns\":" << prefix_returns_
        << ",\"releases\":" << prefix_releases_
        << ",\"skipped_preassigned_falsifying\":"
        << prefix_skipped_falsifying_
        << ",\"skipped_preassigned_rescue\":"
        << prefix_skipped_rescue_ << "},\"rank\":{"
        << "\"rows\":" << rank_rows_.size()
        << ",\"cursor\":" << rank_cursor_
        << ",\"original_returns\":" << rank_original_returns_
        << ",\"original_releases\":" << rank_original_releases_
        << ",\"contrast_enqueued\":" << rank_contrast_enqueued_
        << ",\"contrast_returns\":" << rank_contrast_returns_
        << ",\"contrast_releases\":" << rank_contrast_releases_
        << ",\"skipped_preassigned\":" << rank_skipped_preassigned_
        << "},\"frontier\":{"
        << "\"rows\":" << frontier_rows_.size()
        << ",\"cursor\":" << frontier_cursor_
        << ",\"initial_returns\":" << frontier_initial_returns_
        << ",\"initial_releases\":" << frontier_initial_releases_
        << ",\"contrast_enqueued\":" << frontier_contrast_enqueued_
        << ",\"contrast_returns\":" << frontier_contrast_returns_
        << ",\"contrast_releases\":" << frontier_contrast_releases_
        << ",\"skipped_preassigned_falsifying\":"
        << frontier_skipped_falsifying_
        << ",\"skipped_preassigned_rescue\":"
        << frontier_skipped_rescue_
        << ",\"live_false_literal_count\":" << live_false_literal_count_
        << ",\"live_true_literal_count\":" << live_true_literal_count_
        << ",\"live_unassigned_literal_count\":"
        << live_unassigned_literal_count_ << "},\"staging\":{"
        << "\"overlay_rows\":" << staging_plan_.overlays.size()
        << ",\"effective_original_returns\":"
        << staging_effective_original_returns_
        << ",\"source_contrast_returns\":"
        << staging_source_contrast_returns_
        << ",\"proposal_activated\":"
        << (staging_proposal_activated_ ? "true" : "false")
        << ",\"level_bound_activated\":"
        << (staging_level_bound_activated() ? "true" : "false")
        << ",\"confirmed_activated\":"
        << (staging_confirmed_activated() ? "true" : "false") << '}';
    central_write_sequence(out, "returned_sequence", returned_sequence_,
                           callback_calls_);
    central_write_sequence(out, "proposal_sequence", proposal_sequence_,
                           nonzero_returns_);
    central_write_sequence(out, "release_sequence", release_sequence_,
                           ownership_.releases());
    out << ",\"return_events\":[";
    for (size_t index = 0; index < return_events_.size(); ++index) {
      if (index)
        out << ',';
      const CentralReturnEvent &event = return_events_[index];
      out << "{\"call\":" << event.call << ",\"origin\":\""
          << o1c80::origin_name(event.origin) << "\",\"row\":"
          << event.row << ",\"literal\":" << event.literal
          << ",\"token\":" << event.token << '}';
    }
    out << "]";
  }

private:
  static size_t no_intervention() {
    return std::numeric_limits<size_t>::max();
  }

  V6LifecycleSnapshot v6_snapshot() const {
    V6LifecycleSnapshot result;
    const std::string assignment = base_.assignment_state();
    const std::string trail = base_.trail_state();
    result.pending_state = base_.pending_state();
    const std::string cache = base_.group_cache_state();
    std::ostringstream out;
    base_.write_json(out);
    const std::string telemetry = out.str();
    result.state.assignment_sha256 = sha256(assignment);
    result.state.trail_sha256 = sha256(trail);
    result.state.pending_sha256 = sha256(result.pending_state);
    result.state.group_cache_sha256 = sha256(cache);
    result.state.trace_sha256 =
        json_string_field(telemetry, "trace_sha256");
    // This digest covers every serialized v6 counter as well as its immutable
    // identity fields.  The four live-state digests above are kept separate.
    result.state.counters_sha256 = sha256(telemetry);
    result.threshold_prunes = json_u64_field(telemetry, "threshold_prunes");
    result.trail_threshold_prunes =
        json_u64_field(telemetry, "trail_threshold_prunes");
    result.external_clauses_queued =
        json_u64_field(telemetry, "external_clauses_queued");
    result.external_clauses_emitted =
        json_u64_field(telemetry, "external_clauses_emitted");
    result.pending_clause_count =
        json_u64_field(telemetry, "pending_clause_count");
    return result;
  }

  std::string shadow_assignment_sha256() const {
    const std::string payload(
        reinterpret_cast<const char *>(assignment_.data()),
        assignment_.size());
    return sha256(payload);
  }

  void append_bound_probe_trace(const BoundProbeEvent &event) {
    std::string record;
    record.reserve(49U);
    append_u64_le(record, event.call);
    append_u64_le(record, event.probe);
    append_u32_le(record, event.coordinate_index);
    append_u32_le(record, event.parent_level);
    central_append_i32(record, event.variable);
    append_u64_le(record, f64_bits(event.bounds.zero));
    append_u64_le(record, f64_bits(event.bounds.one));
    append_u64_le(record, f64_bits(threshold_));
    record.push_back(static_cast<char>(event.selection));
    central_append_i32(record, event.losing_literal);
    bound_probe_trace_.update(record);
    bound_probe_trace_bytes_ += record.size();
  }

  int select_bound_losing_child(uint64_t call) {
    ++bound_parent_scans_;
    const V6LifecycleSnapshot before = v6_snapshot();
    if (before.pending_clause_count)
      throw std::runtime_error(
          "one-bit child-bound selector overlaps pending v6 clause");
    const std::string parent_assignment_sha256 =
        shadow_assignment_sha256();
    if (parent_assignment_sha256 != before.state.assignment_sha256)
      throw std::runtime_error(
          "one-bit child-bound shadow assignment differs from v6");
    const o1c80::ExactOneBitParentCache<ExactDoubleSum> parent_cache =
        one_bit_reader_.prepare_parent<ExactDoubleSum>(assignment_);
    const size_t recorded_start = bound_probe_events_.size();
    const size_t intervention_start = bound_interventions_.size();
    int result = 0;
    for (size_t coordinate = 0; coordinate < one_bit_candidates_.size();
         ++coordinate) {
      const int variable = one_bit_candidates_[coordinate];
      const size_t variable_local = local(variable);
      if (assignment_.at(variable_local) ||
          ownership_.has_live_variable(variable))
        continue;
      const o1c80::ChildUpperBounds bounds =
          one_bit_reader_.child_upper_bounds<ExactDoubleSum>(
              parent_cache, variable,
              [](ExactDoubleSum exact, const char *field) {
                return upward_exact_sum(std::move(exact), field);
              });
      const o1c80::ChildBoundSelection selection =
          o1c80::ExactOneBitBoundReader::select(variable, bounds, threshold_);
      BoundProbeEvent event;
      event.call = call;
      event.probe = ++bound_probe_count_;
      event.coordinate_index = static_cast<uint32_t>(coordinate);
      event.parent_level = current_level_;
      event.variable = variable;
      event.parent_assignment_sha256 = parent_assignment_sha256;
      event.bounds = bounds;
      event.selection = selection.selection;
      event.losing_literal = selection.losing_literal;
      event.state_before = before.state;
      ++bound_child_evaluations_;
      ++bound_child_evaluations_;
      ++bound_class_counts_.at(static_cast<size_t>(selection.selection));

      if (selection.losing_literal) {
        result = propose(o1c80::DecisionOrigin::BOUND_LOSING_CHILD,
                         coordinate, selection.losing_literal, call);
        event.proposal_token = last_proposal_token_;
        BoundIntervention intervention;
        intervention.token = last_proposal_token_;
        intervention.call = call;
        intervention.probe = event.probe;
        intervention.coordinate_index = event.coordinate_index;
        intervention.variable = variable;
        intervention.parent_level = current_level_;
        intervention.parent_assignment_sha256 = parent_assignment_sha256;
        intervention.bounds = bounds;
        intervention.selection = selection.selection;
        intervention.losing_literal = selection.losing_literal;
        intervention.state_before = before.state;
        intervention.v6_threshold_prunes_before = before.threshold_prunes;
        intervention.v6_threshold_prunes_after = before.threshold_prunes;
        intervention.v6_trail_threshold_prunes_before =
            before.trail_threshold_prunes;
        intervention.v6_trail_threshold_prunes_after =
            before.trail_threshold_prunes;
        intervention.v6_external_clauses_queued_before =
            before.external_clauses_queued;
        intervention.v6_external_clauses_queued_after =
            before.external_clauses_queued;
        intervention.v6_pending_clause_count_before =
            before.pending_clause_count;
        intervention.v6_pending_clause_count_after =
            before.pending_clause_count;
        intervention.v6_trace_sha256_before = before.state.trace_sha256;
        intervention.v6_trace_sha256_after = before.state.trace_sha256;
        if (pending_bound_intervention_ != no_intervention())
          throw std::runtime_error(
              "one-bit child-bound proposal overlaps pending intervention");
        bound_interventions_.push_back(std::move(intervention));
        pending_bound_intervention_ = bound_interventions_.size() - 1U;
        ++bound_proposals_;
      }
      const double lower_child = std::min(bounds.zero, bounds.one);
      if (!have_minimum_child_upper_ || lower_child < minimum_child_upper_ ||
          (lower_child == minimum_child_upper_ &&
           std::tie(event.call, event.coordinate_index, event.variable) <
               std::tie(minimum_child_event_.call,
                        minimum_child_event_.coordinate_index,
                        minimum_child_event_.variable))) {
        have_minimum_child_upper_ = true;
        minimum_child_upper_ = lower_child;
        minimum_child_variable_ = variable;
        minimum_child_bounds_ = bounds;
        minimum_child_event_ = event;
      }
      append_bound_probe_trace(event);
      if (bound_probe_events_.size() < kMaximumRecordedBoundProbeEvents ||
          selection.losing_literal)
        bound_probe_events_.push_back(std::move(event));
      else
        ++bound_probe_events_omitted_;
      if (result)
        break;
    }
    const V6LifecycleSnapshot after = v6_snapshot();
    if (!(before.state == after.state) ||
        before.threshold_prunes != after.threshold_prunes ||
        before.trail_threshold_prunes != after.trail_threshold_prunes ||
        before.external_clauses_queued != after.external_clauses_queued ||
        before.external_clauses_emitted != after.external_clauses_emitted ||
        before.pending_clause_count != after.pending_clause_count ||
        before.pending_state != after.pending_state)
      throw std::runtime_error(
          "one-bit child-bound probe mutated authoritative v6 state");
    for (size_t index = recorded_start; index < bound_probe_events_.size();
         ++index)
      bound_probe_events_[index].state_after = after.state;
    if (intervention_start < bound_interventions_.size())
      bound_interventions_.back().state_after = after.state;
    if (have_minimum_child_upper_ && minimum_child_event_.call == call)
      minimum_child_event_.state_after = after.state;
    return result;
  }

  void observe_bound_assignments(const std::vector<int> &literals) {
    std::vector<size_t> matched;
    for (const int literal : literals) {
      for (size_t reverse = bound_interventions_.size(); reverse > 0;
           --reverse) {
        BoundIntervention &intervention = bound_interventions_[reverse - 1U];
        if (intervention.released || !intervention.level_bound ||
            intervention.matching_assignment_observed ||
            intervention.losing_literal != literal ||
            intervention.level_bound > current_level_)
          continue;
        intervention.matching_assignment_observed = true;
        intervention.observed_literal = literal;
        ++bound_matching_assignments_;
        matched.push_back(reverse - 1U);
        break;
      }
    }
    if (matched.empty())
      return;
    if (matched.size() != 1U)
      throw std::runtime_error(
          "one-bit child-bound assignment batch has ambiguous prune owner");
    const size_t realized_index = *std::max_element(
        matched.begin(), matched.end(),
        [this](size_t left, size_t right) {
          return bound_interventions_[left].level_bound <
                 bound_interventions_[right].level_bound;
        });
    BoundIntervention &intervention =
        bound_interventions_.at(realized_index);
    const V6LifecycleSnapshot after = v6_snapshot();
    intervention.v6_threshold_prunes_after = after.threshold_prunes;
    intervention.v6_trail_threshold_prunes_after =
        after.trail_threshold_prunes;
    intervention.v6_external_clauses_queued_after =
        after.external_clauses_queued;
    intervention.v6_pending_clause_count_after = after.pending_clause_count;
    intervention.v6_trace_sha256_after = after.state.trace_sha256;
    const bool lifecycle_matches =
        intervention.v6_threshold_prunes_after ==
            intervention.v6_threshold_prunes_before + 1U &&
        intervention.v6_trail_threshold_prunes_after ==
            intervention.v6_trail_threshold_prunes_before + 1U &&
        intervention.v6_external_clauses_queued_after ==
            intervention.v6_external_clauses_queued_before + 1U &&
        intervention.v6_pending_clause_count_before == 0U &&
        intervention.v6_pending_clause_count_after == 1U;
    if (!lifecycle_matches)
      throw std::runtime_error(
          "one-bit child-bound matching assignment lacks v6 prune lifecycle");
    intervention.no_good_literals =
        pending_clause_literals(after.pending_state);
    if (intervention.no_good_literals.empty() ||
        std::find(intervention.no_good_literals.begin(),
                  intervention.no_good_literals.end(),
                  -intervention.losing_literal) ==
            intervention.no_good_literals.end())
      throw std::runtime_error(
          "one-bit child-bound canonical no-good differs");
    intervention.no_good_clause_sha256 =
        sha256(canonical_clause_bytes(intervention.no_good_literals));
    intervention.v6_pending_clause_sha256_after =
        intervention.no_good_clause_sha256;
    intervention.realized_prune = true;
    intervention.fully_emitted_index = after.external_clauses_emitted;
    if (emitting_bound_intervention_ != no_intervention())
      throw std::runtime_error(
          "one-bit child-bound realized prune overlaps emission");
    emitting_bound_intervention_ = realized_index;
    ++bound_realized_prunes_;
  }

  size_t local(int variable) const {
    const std::vector<int> &values = base_.observed();
    const auto iterator = std::lower_bound(values.begin(), values.end(), variable);
    if (iterator == values.end() || *iterator != variable)
      throw std::runtime_error("central reader variable is unobserved");
    return static_cast<size_t>(iterator - values.begin());
  }

  void validate_frontier_selection() const {
    const std::vector<std::vector<int>> &clauses = base_.preloaded_clauses();
    bool have_winner = false;
    std::tuple<size_t, std::string, size_t> winner;
    for (size_t index = 0; index < clauses.size(); ++index) {
      size_t false_count = 0;
      size_t true_count = 0;
      std::vector<int> residual;
      for (const int literal : clauses[index]) {
        const int8_t sign =
            frontier_plan_.prior_assignment.at(local(std::abs(literal)));
        if (!sign)
          residual.push_back(literal);
        else if (central_literal_true(literal, sign))
          ++true_count;
        else
          ++false_count;
      }
      const std::string digest = sha256(canonical_clause_bytes(clauses[index]));
      if (!true_count) {
        const auto candidate = std::make_tuple(residual.size(), digest, index);
        if (!have_winner || candidate < winner) {
          winner = candidate;
          have_winner = true;
        }
      }
      if (index == frontier_plan_.selected_active_index &&
          (false_count != frontier_plan_.false_literal_count ||
           true_count != frontier_plan_.true_literal_count ||
           residual != frontier_plan_.residual_clause_literals ||
           digest != frontier_plan_.selected_clause_sha256))
        throw std::runtime_error("central reader frontier selection differs");
    }
    if (!have_winner ||
        winner != std::make_tuple(
                      static_cast<size_t>(frontier_plan_.unassigned_literal_count),
                      frontier_plan_.selected_clause_sha256,
                      static_cast<size_t>(frontier_plan_.selected_active_index)))
      throw std::runtime_error("central reader frontier winner differs");
  }

  int propose(o1c80::DecisionOrigin origin, size_t row, int literal,
              uint64_t call) {
    if (row > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("central reader proposal row exceeds bound");
    const uint64_t token = ownership_.propose(
        origin, static_cast<uint32_t>(row), literal, call);
    last_proposal_token_ = token;
    return_events_.push_back(
        {call, origin, static_cast<uint32_t>(row), literal, token});
    central_append_i32(proposal_sequence_, literal);
    if (origin == o1c80::DecisionOrigin::RANK_ORIGINAL)
      record_staging_original(row, literal);
    else if (origin == o1c80::DecisionOrigin::RANK_CONTRAST)
      record_staging_contrast(row, literal);
    return literal;
  }

  int select_prefix(uint64_t call) {
    while (prefix_cursor_ < prefix_rows_.size()) {
      const size_t index = prefix_cursor_;
      const CentralRow &row = prefix_rows_[index];
      if (ownership_.has_live_variable(std::abs(row.initial_literal)))
        return 0;
      ++prefix_cursor_;
      const int8_t sign = assignment_.at(row.local);
      if (sign) {
        if (central_literal_true(row.initial_literal, sign))
          ++prefix_skipped_falsifying_;
        else
          ++prefix_skipped_rescue_;
        continue;
      }
      prefix_returned_[index] = true;
      ++prefix_returns_;
      return propose(o1c80::DecisionOrigin::PREFIX, index,
                     row.initial_literal, call);
    }
    return 0;
  }

  int select_rank_original(uint64_t call) {
    if (prefix_cursor_ != prefix_rows_.size())
      return 0;
    while (rank_cursor_ < rank_rows_.size()) {
      const size_t index = rank_cursor_;
      const CentralRow &row = rank_rows_[index];
      if (ownership_.has_live_variable(std::abs(row.initial_literal)))
        return 0;
      ++rank_cursor_;
      if (assignment_.at(row.local)) {
        ++rank_skipped_preassigned_;
        continue;
      }
      rank_original_returned_[index] = true;
      ++rank_original_returns_;
      return propose(o1c80::DecisionOrigin::RANK_ORIGINAL, index,
                     row.initial_literal, call);
    }
    return 0;
  }

  int select_rank_contrast(uint64_t call) {
    for (const uint32_t index : rank_release_order_) {
      if (index >= rank_rows_.size() || rank_contrast_returned_[index] ||
          assignment_.at(rank_rows_[index].local) ||
          ownership_.has_live_variable(
              std::abs(rank_rows_[index].contrast_literal)))
        continue;
      rank_contrast_returned_[index] = true;
      ++rank_contrast_returns_;
      return propose(o1c80::DecisionOrigin::RANK_CONTRAST, index,
                     rank_rows_[index].contrast_literal, call);
    }
    return 0;
  }

  bool rank_contrast_exhausted() const {
    for (const uint32_t index : rank_release_order_)
      if (index < rank_rows_.size() && !rank_contrast_returned_[index] &&
          !assignment_.at(rank_rows_[index].local))
        return false;
    return true;
  }

  int select_frontier_initial(uint64_t call) {
    while (frontier_cursor_ < frontier_rows_.size()) {
      const size_t index = frontier_cursor_;
      const CentralRow &row = frontier_rows_[index];
      if (ownership_.has_live_variable(std::abs(row.initial_literal)))
        return 0;
      ++frontier_cursor_;
      const int8_t sign = assignment_.at(row.local);
      if (sign) {
        if (central_literal_true(row.initial_literal, sign))
          ++frontier_skipped_falsifying_;
        else if (central_literal_true(row.contrast_literal, sign))
          ++frontier_skipped_rescue_;
        else
          throw std::runtime_error("central reader frontier sign differs");
        continue;
      }
      frontier_initial_returned_[index] = true;
      ++frontier_initial_returns_;
      return propose(o1c80::DecisionOrigin::FRONTIER_INITIAL, index,
                     row.initial_literal, call);
    }
    return 0;
  }

  int select_frontier_contrast(uint64_t call) {
    for (const uint32_t index : frontier_release_order_) {
      if (index >= frontier_rows_.size() ||
          frontier_contrast_returned_[index] ||
          assignment_.at(frontier_rows_[index].local) ||
          ownership_.has_live_variable(
              std::abs(frontier_rows_[index].contrast_literal)))
        continue;
      frontier_contrast_returned_[index] = true;
      ++frontier_contrast_returns_;
      return propose(o1c80::DecisionOrigin::FRONTIER_CONTRAST, index,
                     frontier_rows_[index].contrast_literal, call);
    }
    return 0;
  }

  void apply_release(const o1c80::DecisionToken &token) {
    central_append_i32(release_sequence_, token.literal);
    const size_t index = token.row;
    switch (token.origin) {
    case o1c80::DecisionOrigin::NONE:
      throw std::runtime_error("central reader release lacks origin");
    case o1c80::DecisionOrigin::PREFIX:
      if (index >= prefix_returned_.size() || !prefix_returned_[index] ||
          prefix_released_[index])
        throw std::runtime_error("central reader prefix release differs");
      prefix_released_[index] = true;
      ++prefix_releases_;
      return;
    case o1c80::DecisionOrigin::RANK_ORIGINAL:
      if (index >= rank_original_returned_.size() ||
          !rank_original_returned_[index] || rank_original_released_[index])
        throw std::runtime_error("central reader rank release differs");
      rank_original_released_[index] = true;
      rank_release_order_.push_back(static_cast<uint32_t>(index));
      ++rank_original_releases_;
      ++rank_contrast_enqueued_;
      return;
    case o1c80::DecisionOrigin::RANK_CONTRAST:
      if (index >= rank_contrast_returned_.size() ||
          !rank_contrast_returned_[index] || rank_contrast_released_[index])
        throw std::runtime_error(
            "central reader rank contrast release differs");
      rank_contrast_released_[index] = true;
      ++rank_contrast_releases_;
      return;
    case o1c80::DecisionOrigin::FRONTIER_INITIAL:
      if (index >= frontier_initial_returned_.size() ||
          !frontier_initial_returned_[index] ||
          frontier_initial_released_[index])
        throw std::runtime_error("central reader frontier release differs");
      frontier_initial_released_[index] = true;
      frontier_release_order_.push_back(static_cast<uint32_t>(index));
      ++frontier_initial_releases_;
      ++frontier_contrast_enqueued_;
      return;
    case o1c80::DecisionOrigin::FRONTIER_CONTRAST:
      if (index >= frontier_contrast_returned_.size() ||
          !frontier_contrast_returned_[index] ||
          frontier_contrast_released_[index])
        throw std::runtime_error(
            "central reader frontier contrast release differs");
      frontier_contrast_released_[index] = true;
      ++frontier_contrast_releases_;
      return;
    case o1c80::DecisionOrigin::BOUND_LOSING_CHILD: {
      const auto found = std::find_if(
          bound_interventions_.begin(), bound_interventions_.end(),
          [&token](const BoundIntervention &intervention) {
            return intervention.token == token.token;
          });
      if (found == bound_interventions_.end() || found->released ||
          found->coordinate_index != index ||
          found->losing_literal != token.literal ||
          found->level_bound != token.bound_level ||
          found->matching_assignment_observed != token.confirmed)
        throw std::runtime_error(
            "one-bit child-bound release lifecycle differs");
      found->released = true;
      found->unobserved_release = !token.confirmed;
      ++bound_releases_;
      if (!token.confirmed)
        ++bound_unobserved_releases_;
      return;
    }
    }
    throw std::runtime_error("central reader release origin differs");
  }

  void record_staging_original(size_t rank_index, int literal) {
    for (const StagingOverlay &overlay : staging_plan_.overlays)
      if (overlay.rank_index == rank_index) {
        if (overlay.effective_literal != literal)
          throw std::runtime_error("central reader staging original differs");
        ++staging_effective_original_returns_;
        staging_proposal_activated_ = true;
      }
  }

  void record_staging_contrast(size_t rank_index, int literal) {
    for (const StagingOverlay &overlay : staging_plan_.overlays)
      if (overlay.rank_index == rank_index) {
        if (overlay.source_literal != literal)
          throw std::runtime_error("central reader staging contrast differs");
        ++staging_source_contrast_returns_;
      }
  }

  bool staging_level_bound_activated() const {
    for (const o1c80::OwnershipEvent &event : ownership_.events()) {
      if (event.kind != o1c80::OwnershipEventKind::LEVEL_BOUND ||
          event.origin != o1c80::DecisionOrigin::RANK_ORIGINAL)
        continue;
      for (const StagingOverlay &overlay : staging_plan_.overlays)
        if (overlay.rank_index == event.row)
          return true;
    }
    return false;
  }

  bool staging_confirmed_activated() const {
    for (const o1c80::OwnershipEvent &event : ownership_.events()) {
      if (event.kind != o1c80::OwnershipEventKind::CONFIRMED ||
          event.origin != o1c80::DecisionOrigin::RANK_ORIGINAL)
        continue;
      for (const StagingOverlay &overlay : staging_plan_.overlays)
        if (overlay.rank_index == event.row)
          return true;
    }
    return false;
  }

  void update_live_clause_counts() {
    size_t false_count = 0;
    size_t true_count = 0;
    size_t unassigned_count = 0;
    for (size_t index = 0; index < selected_clause_.size(); ++index) {
      const int8_t sign = assignment_.at(selected_clause_locals_[index]);
      if (!sign)
        ++unassigned_count;
      else if (central_literal_true(selected_clause_[index], sign))
        ++true_count;
      else
        ++false_count;
    }
    live_false_literal_count_ = false_count;
    live_true_literal_count_ = true_count;
    live_unassigned_literal_count_ = unassigned_count;
  }

  static size_t count_true(const std::vector<bool> &state) {
    return static_cast<size_t>(std::count(state.begin(), state.end(), true));
  }

  void validate_telemetry() const {
    const uint64_t bound_class_total =
        bound_class_counts_[0] + bound_class_counts_[1] +
        bound_class_counts_[2] + bound_class_counts_[3];
    if (!solve_finalized_ || callback_calls_ != nonzero_returns_ + zero_returns_ ||
        returned_sequence_.size() != 4U * callback_calls_ ||
        proposal_sequence_.size() != 4U * nonzero_returns_ ||
        release_sequence_.size() != 4U * ownership_.releases() ||
        return_events_.size() != nonzero_returns_ ||
        ownership_.proposals() != nonzero_returns_ ||
        prefix_cursor_ > prefix_rows_.size() ||
        rank_cursor_ > rank_rows_.size() ||
        frontier_cursor_ > frontier_rows_.size() ||
        count_true(prefix_returned_) != prefix_returns_ ||
        count_true(prefix_released_) != prefix_releases_ ||
        count_true(rank_original_returned_) != rank_original_returns_ ||
        count_true(rank_original_released_) != rank_original_releases_ ||
        count_true(rank_contrast_returned_) != rank_contrast_returns_ ||
        count_true(rank_contrast_released_) != rank_contrast_releases_ ||
        count_true(frontier_initial_returned_) != frontier_initial_returns_ ||
        count_true(frontier_initial_released_) != frontier_initial_releases_ ||
        count_true(frontier_contrast_returned_) != frontier_contrast_returns_ ||
        count_true(frontier_contrast_released_) != frontier_contrast_releases_ ||
        rank_release_order_.size() != rank_original_releases_ ||
        frontier_release_order_.size() != frontier_initial_releases_ ||
        rank_contrast_enqueued_ != rank_original_releases_ ||
        frontier_contrast_enqueued_ != frontier_initial_releases_ ||
        bound_parent_scans_ != callback_calls_ ||
        bound_child_evaluations_ != 2U * bound_probe_count_ ||
        bound_class_total != bound_probe_count_ ||
        bound_probe_events_.size() + bound_probe_events_omitted_ !=
            bound_probe_count_ ||
        one_bit_candidate_order_.size() !=
            4U * one_bit_candidates_.size() ||
        bound_interventions_.size() != bound_proposals_ ||
        bound_level_bindings_ != bound_proposals_ ||
        bound_matching_assignments_ != bound_realized_prunes_ ||
        bound_fully_emitted_ != bound_realized_prunes_ ||
        ownership_.origin_proposals(
            o1c80::DecisionOrigin::BOUND_LOSING_CHILD) != bound_proposals_ ||
        ownership_.origin_level_bound(
            o1c80::DecisionOrigin::BOUND_LOSING_CHILD) !=
            bound_level_bindings_ ||
        ownership_.origin_confirmed(
            o1c80::DecisionOrigin::BOUND_LOSING_CHILD) !=
            bound_matching_assignments_ ||
        ownership_.origin_releases(
            o1c80::DecisionOrigin::BOUND_LOSING_CHILD) != bound_releases_ ||
        (have_minimum_child_upper_ &&
         (minimum_child_event_.variable != minimum_child_variable_ ||
          minimum_child_event_.bounds.zero != minimum_child_bounds_.zero ||
          minimum_child_event_.bounds.one != minimum_child_bounds_.one ||
          std::min(minimum_child_event_.bounds.zero,
                   minimum_child_event_.bounds.one) !=
              minimum_child_upper_ ||
          minimum_child_event_.parent_assignment_sha256 !=
              minimum_child_event_.state_before.assignment_sha256 ||
          !(minimum_child_event_.state_before ==
            minimum_child_event_.state_after))) ||
        live_false_literal_count_ + live_true_literal_count_ +
                live_unassigned_literal_count_ !=
            selected_clause_.size())
      throw std::runtime_error("central reader telemetry differs");
    for (size_t index = 0; index < return_events_.size(); ++index) {
      const CentralReturnEvent &event = return_events_[index];
      if (!event.call || event.call > callback_calls_ || !event.token ||
          event.token != index + 1U)
        throw std::runtime_error("central reader return event differs");
    }
    for (const BoundProbeEvent &event : bound_probe_events_)
      if (!event.call || !event.probe ||
          event.coordinate_index >= one_bit_candidates_.size() ||
          one_bit_candidates_[event.coordinate_index] != event.variable ||
          event.parent_assignment_sha256 !=
              event.state_before.assignment_sha256 ||
          !(event.state_before == event.state_after) ||
          (event.losing_literal == 0) != (event.proposal_token == 0))
        throw std::runtime_error(
            "one-bit child-bound probe telemetry differs");
    size_t counted_releases = 0;
    size_t counted_unobserved = 0;
    size_t counted_live = 0;
    for (const BoundIntervention &event : bound_interventions_) {
      if (!event.token || !event.call || !event.probe ||
          !event.losing_literal || !event.level_bound ||
          event.parent_level + 1U != event.level_bound ||
          event.coordinate_index >= one_bit_candidates_.size() ||
          one_bit_candidates_[event.coordinate_index] != event.variable ||
          event.parent_assignment_sha256 !=
              event.state_before.assignment_sha256 ||
          !(event.state_before == event.state_after) ||
          event.v6_pending_clause_count_before != 0U ||
          event.matching_assignment_observed != event.realized_prune ||
          event.realized_prune != event.fully_emitted ||
          event.unobserved_release !=
              (event.released && !event.matching_assignment_observed) ||
          (event.realized_prune &&
           (event.no_good_literals.empty() ||
            event.no_good_clause_sha256.empty() ||
            event.v6_pending_clause_sha256_after !=
                event.no_good_clause_sha256)) ||
          (!event.realized_prune &&
           (!event.no_good_literals.empty() ||
            !event.no_good_clause_sha256.empty() ||
            !event.v6_pending_clause_sha256_after.empty())))
        throw std::runtime_error(
            "one-bit child-bound intervention telemetry differs");
      counted_releases += event.released ? 1U : 0U;
      counted_unobserved += event.unobserved_release ? 1U : 0U;
      counted_live += event.released ? 0U : 1U;
    }
    if (counted_releases != bound_releases_ ||
        counted_unobserved != bound_unobserved_releases_ ||
        counted_live != bound_proposals_ - bound_releases_)
      throw std::runtime_error(
          "one-bit child-bound release telemetry differs");
  }

  o1c80::ExactOneBitBoundReader one_bit_reader_;
  GroupedJointScoreSieveV6 base_;
  RankTable rank_;
  RankVoteField vote_field_;
  FrontierPlan frontier_plan_;
  StagingPlan staging_plan_;
  PrefixPlan prefix_plan_;
  std::string potential_sha256_;
  std::string potential_source_sha256_;
  std::string grouping_sha256_;
  std::string active_vault_sha256_;
  std::string rank_source_vault_sha256_;
  std::string frontier_plan_sha256_;
  std::string staging_plan_sha256_;
  double threshold_ = 0.0;
  std::vector<int8_t> assignment_;
  std::vector<CentralTrailEntry> trail_;
  uint32_t current_level_ = 0;
  o1c80::DecisionOwnershipLedger ownership_;
  std::vector<CentralRow> prefix_rows_;
  std::vector<CentralRow> rank_rows_;
  std::vector<CentralRow> frontier_rows_;
  std::vector<int> selected_clause_;
  std::vector<size_t> selected_clause_locals_;
  std::vector<bool> prefix_returned_;
  std::vector<bool> prefix_released_;
  std::vector<bool> rank_original_returned_;
  std::vector<bool> rank_original_released_;
  std::vector<bool> rank_contrast_returned_;
  std::vector<bool> rank_contrast_released_;
  std::vector<bool> frontier_initial_returned_;
  std::vector<bool> frontier_initial_released_;
  std::vector<bool> frontier_contrast_returned_;
  std::vector<bool> frontier_contrast_released_;
  std::vector<uint32_t> rank_release_order_;
  std::vector<uint32_t> frontier_release_order_;
  std::vector<int> one_bit_candidates_;
  size_t ranked_one_bit_candidates_ = 0;
  size_t omitted_one_bit_candidates_ = 0;
  std::string one_bit_candidate_order_;
  uint64_t bound_parent_scans_ = 0;
  uint64_t bound_probe_count_ = 0;
  uint64_t bound_child_evaluations_ = 0;
  std::array<uint64_t, 4> bound_class_counts_{};
  uint64_t bound_proposals_ = 0;
  uint64_t bound_level_bindings_ = 0;
  uint64_t bound_matching_assignments_ = 0;
  uint64_t bound_realized_prunes_ = 0;
  uint64_t bound_fully_emitted_ = 0;
  uint64_t bound_releases_ = 0;
  uint64_t bound_unobserved_releases_ = 0;
  uint64_t bound_probe_events_omitted_ = 0;
  uint64_t bound_probe_trace_bytes_ = 0;
  uint64_t last_proposal_token_ = 0;
  size_t pending_bound_intervention_ = no_intervention();
  size_t emitting_bound_intervention_ = no_intervention();
  bool have_minimum_child_upper_ = false;
  double minimum_child_upper_ = 0.0;
  int minimum_child_variable_ = 0;
  o1c80::ChildUpperBounds minimum_child_bounds_;
  BoundProbeEvent minimum_child_event_;
  Sha256 bound_probe_trace_;
  std::vector<BoundProbeEvent> bound_probe_events_;
  std::vector<BoundIntervention> bound_interventions_;
  size_t prefix_cursor_ = 0;
  size_t rank_cursor_ = 0;
  size_t frontier_cursor_ = 0;
  uint64_t callback_calls_ = 0;
  uint64_t nonzero_returns_ = 0;
  uint64_t zero_returns_ = 0;
  uint64_t assignment_literals_observed_ = 0;
  size_t prefix_returns_ = 0;
  size_t prefix_releases_ = 0;
  size_t prefix_skipped_falsifying_ = 0;
  size_t prefix_skipped_rescue_ = 0;
  size_t rank_original_returns_ = 0;
  size_t rank_original_releases_ = 0;
  size_t rank_contrast_enqueued_ = 0;
  size_t rank_contrast_returns_ = 0;
  size_t rank_contrast_releases_ = 0;
  size_t rank_skipped_preassigned_ = 0;
  size_t frontier_initial_returns_ = 0;
  size_t frontier_initial_releases_ = 0;
  size_t frontier_contrast_enqueued_ = 0;
  size_t frontier_contrast_returns_ = 0;
  size_t frontier_contrast_releases_ = 0;
  size_t frontier_skipped_falsifying_ = 0;
  size_t frontier_skipped_rescue_ = 0;
  size_t staging_effective_original_returns_ = 0;
  size_t staging_source_contrast_returns_ = 0;
  bool staging_proposal_activated_ = false;
  bool solve_finalized_ = false;
  size_t live_false_literal_count_ = 0;
  size_t live_true_literal_count_ = 0;
  size_t live_unassigned_literal_count_ = 0;
  std::string returned_sequence_;
  std::string proposal_sequence_;
  std::string release_sequence_;
  std::vector<CentralReturnEvent> return_events_;
};

[[maybe_unused]] void print_v18_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v18 --cnf PATH "
               "--potential PATH --grouping PATH --rank-vault PATH "
               "--vault-in PATH --rank-table PATH --frontier-plan PATH "
               "--staging-plan PATH --prefix-plan PATH --threshold FLOAT "
               "--conflict-limit N [--seed N]\n";
}

} // namespace

#ifndef O1_CRYPTO_LAB_O1C80_NO_MAIN
int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v18_usage();
      return 0;
    }
    const PrefixArguments prefix_arguments = parse_prefix_arguments(argc, argv);
    const StagingArguments &staging_arguments = prefix_arguments.staging;
    const FrontierArguments &frontier_arguments = staging_arguments.frontier;
    const SplitRankedArguments &split_arguments = frontier_arguments.split;
    const RankedArguments &ranked_arguments = split_arguments.ranked;
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("central ownership reader requires seed zero");
    if (kRankSpec.size() != 674U ||
        sha256(kRankSpec) != kExpectedSpecSha256 ||
        kContrastPolicySpec.size() != 674U ||
        sha256(kContrastPolicySpec) != kExpectedContrastPolicySha256)
      throw std::runtime_error("central ownership reader specification differs");
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
    const std::string frontier_payload =
        read_bounded_frontier_file(frontier_arguments.frontier_plan_path);
    FrontierPlan frontier_plan = parse_frontier_plan(frontier_payload);
    const std::string staging_payload =
        read_bounded_staging_file(staging_arguments.staging_plan_path);
    StagingPlan staging_plan = parse_staging_plan(staging_payload);
    const std::string prefix_payload =
        read_bounded_prefix_file(prefix_arguments.prefix_plan_path);
    PrefixPlan prefix_plan = parse_prefix_plan(prefix_payload);
    const std::string rank_payload =
        read_binary_file(ranked_arguments.rank_table_path, "rank table");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);
    const std::string rank_source_vault_sha256 = sha256(rank_vault_payload);
    const std::string active_vault_sha256 = sha256(active_vault_payload);
    const std::string frontier_sha256 = sha256(frontier_payload);
    const std::string staging_sha256 = sha256(staging_payload);

#ifdef O1_CRYPTO_LAB_O1C80_PUBLIC_FIXTURE
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
    // O1C80 intentionally rejects every consumed Page-6-or-earlier stack.
    // Public fixtures use exact structural bindings.  Production additionally
    // requires the exact fresh Page-7 binary identities and sizes.
    if (frontier_plan.payload_sha256 != frontier_sha256 ||
        staging_plan.payload_sha256 != staging_sha256 ||
        staging_plan.parent_frontier_plan_sha256 != frontier_sha256 ||
        staging_plan.active_vault_sha256 != active_vault_sha256 ||
        frontier_plan.active_vault_sha256 != active_vault_sha256)
      throw std::runtime_error("central ownership fresh plan binding differs");
    if (production_seal &&
        (active_vault_sha256 != kProductionPage7ActiveVaultSha256 ||
         frontier_sha256 != kProductionPage7FrontierPlanSha256 ||
         staging_sha256 != kProductionPage7StagingPlanSha256))
      throw std::runtime_error(
          "sealed O1C80 Page-7 parent stack differs");
    if (production_seal &&
        (frontier_payload.size() != kProductionPage7FrontierPlanBytes ||
         staging_payload.size() != kProductionPage7StagingPlanBytes ||
         prefix_payload.size() != 44U ||
         sha256(prefix_payload) != kProductionPrefixOrderSha256))
      throw std::runtime_error("sealed O1C80 Page-7 plan size differs");

    std::unique_ptr<CentralOwnershipGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
          !solver.set("quiet", 1) || !solver.set("factor", 0) ||
          !solver.set("lucky", 0) || !solver.set("walk", 0) ||
          !solver.set("rephase", 0) || !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic central ownership options");
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
      validate_and_apply_staging(staging_plan, rank, frontier_plan,
                                 active_vault, observed, frontier_sha256, false);

      propagator =
          std::make_unique<CentralOwnershipGroupedJointScoreSieve>(
              std::move(field), grouping_payload, active_vault_payload,
              cnf_sha256, potential_sha256, arguments.threshold,
              std::move(rank), std::move(vote_field), potential_source_sha256,
              std::move(frontier_plan), std::move(staging_plan),
              std::move(prefix_plan), active_vault_sha256,
              rank_source_vault_sha256, frontier_sha256, staging_sha256);
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

      std::ostringstream out;
      out << std::setprecision(std::numeric_limits<double>::max_digits10)
          << "{\"schema\":\"" << kV18ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << "o1-256-cadical-joint-score-sieve-result-v6"
          << "\",\"rank_source_vault_sha256\":\""
          << rank_source_vault_sha256
          << "\",\"active_vault_sha256\":\"" << active_vault_sha256
          << "\",\"frontier_plan_sha256\":\"" << frontier_sha256
          << "\",\"staging_plan_sha256\":\"" << staging_sha256
          << "\",\"prefix_preemption_plan_sha256\":\""
          << sha256(prefix_payload) << "\",\"one_bit_bound_reader\":{";
      propagator->write_one_bit_bound_json(out);
      out << "},\"central_reader\":{";
      propagator->write_central_json(out);
      out << "},\"decision_ownership\":{";
      propagator->write_ownership_json(out);
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
    std::cerr << "cadical_o1_joint_score_sieve_v18: " << error.what() << '\n';
    return 1;
  }
}
#endif
