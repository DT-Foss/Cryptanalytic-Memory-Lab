// O1C-0079 central decision-ownership reader over the unchanged native v6
// grouped score/vault core.
//
// The v11-v16 translation units are included only as frozen parsers and plan
// validators.  No legacy reader wrapper is constructed at runtime.  All five
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

#ifdef O1_CRYPTO_LAB_O1C79_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C79_UNDEF_O1C78_FIXTURE
#endif
namespace o1c79_embedded_v16 {
#include "cadical_o1_joint_score_sieve_v16.cpp"
} // namespace o1c79_embedded_v16
#ifdef O1_CRYPTO_LAB_O1C79_UNDEF_O1C78_FIXTURE
#undef O1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C79_UNDEF_O1C78_FIXTURE
#endif

#include "o1c79_decision_ownership.hpp"

using namespace o1c79_embedded_v16;

namespace {

constexpr const char *kV17ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v17";
constexpr const char *kCentralReaderSchema =
    "o1-256-central-composed-reader-v1";
constexpr const char *kCentralOperator =
    "single-owner-prefix-rank-original-rank-contrast-frontier-initial-"
    "frontier-contrast-over-unchanged-v6";
constexpr const char *kCentralSelectionRule =
    "PREFIX-until-consumed;RANK_ORIGINAL-until-consumed;released-"
    "RANK_CONTRAST;FRONTIER_INITIAL-until-consumed;released-"
    "FRONTIER_CONTRAST;base-zero";
constexpr const char *kCentralReleaseRule =
    "retire-every-token-bound-above-backtrack-level-atomically;enqueue-"
    "contrast-only-from-token-origin-and-row;confirmation-not-required";
constexpr const char *kSignedI32SequenceEncoding =
    "concatenated-signed-i32le-literals";
constexpr size_t kMaximumCallbackRecords = 4194304U;
constexpr const char *kProductionPage6ActiveVaultSha256 =
    "69bde6adc23e9e89f97581175ecb85dc9f1d94cddc6d162dfb2f93f9d60f3846";
constexpr const char *kProductionPage6FrontierPlanSha256 =
    "785cae9e32912e1d45858d046b36a7c7b9e4cf51799f233a7b3246aa6756ad65";
constexpr const char *kProductionPage6StagingPlanSha256 =
    "c536a94483467ee1197d52e0e3f81ad2f728a36ad3982124e1b9966e0011f927";
constexpr size_t kProductionPage6FrontierPlanBytes = 4479U;
constexpr size_t kProductionPage6StagingPlanBytes = 4477U;

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
  o1c79::DecisionOrigin origin = o1c79::DecisionOrigin::PREFIX;
  uint32_t row = 0;
  int literal = 0;
  uint64_t token = 0;
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
      : base_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
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
        staging_plan_sha256_(std::move(staging_plan_sha256)) {
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
    update_live_clause_counts();
  }

  void notify_new_decision_level() override {
    if (current_level_ == std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("central reader decision level exceeds bound");
    base_.notify_new_decision_level();
    ++current_level_;
    ownership_.notify_new_decision_level(current_level_);
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
    const std::vector<o1c79::DecisionToken> released =
        ownership_.notify_backtrack(static_cast<uint32_t>(new_level));
    for (const o1c79::DecisionToken &token : released)
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

    int result = select_prefix(call);
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
    return base_.cb_add_external_clause_lit();
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
        << ",\"prefix\":{"
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
          << o1c79::origin_name(event.origin) << "\",\"row\":"
          << event.row << ",\"literal\":" << event.literal
          << ",\"token\":" << event.token << '}';
    }
    out << "]";
  }

private:
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

  int propose(o1c79::DecisionOrigin origin, size_t row, int literal,
              uint64_t call) {
    if (row > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("central reader proposal row exceeds bound");
    const uint64_t token = ownership_.propose(
        origin, static_cast<uint32_t>(row), literal, call);
    return_events_.push_back(
        {call, origin, static_cast<uint32_t>(row), literal, token});
    central_append_i32(proposal_sequence_, literal);
    if (origin == o1c79::DecisionOrigin::RANK_ORIGINAL)
      record_staging_original(row, literal);
    else if (origin == o1c79::DecisionOrigin::RANK_CONTRAST)
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
      return propose(o1c79::DecisionOrigin::PREFIX, index,
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
      return propose(o1c79::DecisionOrigin::RANK_ORIGINAL, index,
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
      return propose(o1c79::DecisionOrigin::RANK_CONTRAST, index,
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
      return propose(o1c79::DecisionOrigin::FRONTIER_INITIAL, index,
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
      return propose(o1c79::DecisionOrigin::FRONTIER_CONTRAST, index,
                     frontier_rows_[index].contrast_literal, call);
    }
    return 0;
  }

  void apply_release(const o1c79::DecisionToken &token) {
    central_append_i32(release_sequence_, token.literal);
    const size_t index = token.row;
    switch (token.origin) {
    case o1c79::DecisionOrigin::NONE:
      throw std::runtime_error("central reader release lacks origin");
    case o1c79::DecisionOrigin::PREFIX:
      if (index >= prefix_returned_.size() || !prefix_returned_[index] ||
          prefix_released_[index])
        throw std::runtime_error("central reader prefix release differs");
      prefix_released_[index] = true;
      ++prefix_releases_;
      return;
    case o1c79::DecisionOrigin::RANK_ORIGINAL:
      if (index >= rank_original_returned_.size() ||
          !rank_original_returned_[index] || rank_original_released_[index])
        throw std::runtime_error("central reader rank release differs");
      rank_original_released_[index] = true;
      rank_release_order_.push_back(static_cast<uint32_t>(index));
      ++rank_original_releases_;
      ++rank_contrast_enqueued_;
      return;
    case o1c79::DecisionOrigin::RANK_CONTRAST:
      if (index >= rank_contrast_returned_.size() ||
          !rank_contrast_returned_[index] || rank_contrast_released_[index])
        throw std::runtime_error(
            "central reader rank contrast release differs");
      rank_contrast_released_[index] = true;
      ++rank_contrast_releases_;
      return;
    case o1c79::DecisionOrigin::FRONTIER_INITIAL:
      if (index >= frontier_initial_returned_.size() ||
          !frontier_initial_returned_[index] ||
          frontier_initial_released_[index])
        throw std::runtime_error("central reader frontier release differs");
      frontier_initial_released_[index] = true;
      frontier_release_order_.push_back(static_cast<uint32_t>(index));
      ++frontier_initial_releases_;
      ++frontier_contrast_enqueued_;
      return;
    case o1c79::DecisionOrigin::FRONTIER_CONTRAST:
      if (index >= frontier_contrast_returned_.size() ||
          !frontier_contrast_returned_[index] ||
          frontier_contrast_released_[index])
        throw std::runtime_error(
            "central reader frontier contrast release differs");
      frontier_contrast_released_[index] = true;
      ++frontier_contrast_releases_;
      return;
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
    for (const o1c79::OwnershipEvent &event : ownership_.events()) {
      if (event.kind != o1c79::OwnershipEventKind::LEVEL_BOUND ||
          event.origin != o1c79::DecisionOrigin::RANK_ORIGINAL)
        continue;
      for (const StagingOverlay &overlay : staging_plan_.overlays)
        if (overlay.rank_index == event.row)
          return true;
    }
    return false;
  }

  bool staging_confirmed_activated() const {
    for (const o1c79::OwnershipEvent &event : ownership_.events()) {
      if (event.kind != o1c79::OwnershipEventKind::CONFIRMED ||
          event.origin != o1c79::DecisionOrigin::RANK_ORIGINAL)
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
  }

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
  std::vector<int8_t> assignment_;
  std::vector<CentralTrailEntry> trail_;
  uint32_t current_level_ = 0;
  o1c79::DecisionOwnershipLedger ownership_;
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

void print_v17_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v17 --cnf PATH "
               "--potential PATH --grouping PATH --rank-vault PATH "
               "--vault-in PATH --rank-table PATH --frontier-plan PATH "
               "--staging-plan PATH --prefix-plan PATH --threshold FLOAT "
               "--conflict-limit N [--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v17_usage();
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

#ifdef O1_CRYPTO_LAB_O1C79_PUBLIC_FIXTURE
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
    // O1C79 intentionally rejects the frozen O1C78/Page-5 parent-stack seal.
    // Public fixtures use exact structural bindings.  Production additionally
    // requires the exact fresh Page-6 binary identities and sizes.
    if (frontier_plan.payload_sha256 != frontier_sha256 ||
        staging_plan.payload_sha256 != staging_sha256 ||
        staging_plan.parent_frontier_plan_sha256 != frontier_sha256 ||
        staging_plan.active_vault_sha256 != active_vault_sha256 ||
        frontier_plan.active_vault_sha256 != active_vault_sha256)
      throw std::runtime_error("central ownership fresh plan binding differs");
    if (production_seal &&
        (active_vault_sha256 != kProductionPage6ActiveVaultSha256 ||
         frontier_sha256 != kProductionPage6FrontierPlanSha256 ||
         staging_sha256 != kProductionPage6StagingPlanSha256))
      throw std::runtime_error(
          "sealed O1C79 Page-6 parent stack differs");
    if (production_seal &&
        (frontier_payload.size() != kProductionPage6FrontierPlanBytes ||
         staging_payload.size() != kProductionPage6StagingPlanBytes ||
         prefix_payload.size() != 44U ||
         sha256(prefix_payload) != kProductionPrefixOrderSha256))
      throw std::runtime_error("sealed O1C79 Page-6 plan size differs");

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
          << "{\"schema\":\"" << kV17ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << "o1-256-cadical-joint-score-sieve-result-v6"
          << "\",\"rank_source_vault_sha256\":\""
          << rank_source_vault_sha256
          << "\",\"active_vault_sha256\":\"" << active_vault_sha256
          << "\",\"frontier_plan_sha256\":\"" << frontier_sha256
          << "\",\"staging_plan_sha256\":\"" << staging_sha256
          << "\",\"prefix_preemption_plan_sha256\":\""
          << sha256(prefix_payload) << "\",\"central_reader\":{";
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
    std::cerr << "cadical_o1_joint_score_sieve_v17: " << error.what() << '\n';
    return 1;
  }
}
