#include <iterator>

#define main cadical_o1_joint_score_sieve_v1_embedded_main
#define JointScoreSieve FrozenIndependentJointScoreSieveV1
#include "cadical_o1_joint_score_sieve.cpp"
#undef JointScoreSieve
#undef main

namespace {

constexpr const char *kGroupedSchema =
    "o1-256-cadical-joint-score-sieve-result-v3";
constexpr const char *kGroupedStateSchema =
    "o1-256-cadical-joint-score-sieve-grouped-state-v1";
constexpr const char *kGroupingRule =
    "ascending-factor-greedy-smallest-unmatched-earlier-overlap-"
    "union-width-at-most-8;groups-ascending-min-factor-index";
constexpr const char *kGroupedBoundRule =
    "pair-cell-twosum-directed-positive-infinity;partial-group-maximum;"
    "nextafter-positive-infinity-after-each-group-maximum-addition";
constexpr const char *kGroupedStateEncoding =
    "observed-ascending-i8-sign;trail-u32le-level,u32le-count,"
    "u32le-local-index,u32le-level;pending-u32le-length,u32le-cursor,"
    "u8-ready,u8-blocking,i32le-literals;derived-group-cache-group-order-"
    "f64le-max";

struct CompatibilityGroup {
  std::vector<size_t> factor_indices;
  std::vector<int> variables;
  std::vector<size_t> local_indices;
  std::vector<double> energies;
};

bool scopes_overlap(const std::vector<int> &left,
                    const std::vector<int> &right) {
  size_t left_index = 0;
  size_t right_index = 0;
  while (left_index < left.size() && right_index < right.size()) {
    if (left[left_index] == right[right_index])
      return true;
    if (left[left_index] < right[right_index])
      ++left_index;
    else
      ++right_index;
  }
  return false;
}

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

double upward_pair_energy(double left, double right) {
  const double raw = left + right;
  if (raw == -std::numeric_limits<double>::infinity())
    return -std::numeric_limits<double>::max();
  if (!std::isfinite(raw))
    throw std::runtime_error("grouped pair energy is not representable");
  // Knuth TwoSum exposes whether round-to-nearest landed below the exact sum.
  const double right_virtual = raw - left;
  const double left_virtual = raw - right_virtual;
  const double residual =
      (left - left_virtual) + (right - right_virtual);
  const double bounded =
      residual > 0.0
          ? std::nextafter(raw, std::numeric_limits<double>::infinity())
          : raw;
  if (!std::isfinite(bounded))
    throw std::runtime_error("grouped pair energy is not representable");
  return bounded;
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

class GroupedJointScoreSieve final : public CaDiCaL::ExternalPropagator {
public:
  GroupedJointScoreSieve(PotentialField field, double threshold)
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
    build_groups();
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
    if (pair_group_count_ * 2U + singleton_group_count_ !=
            field_.factors.size() ||
        pair_group_count_ + singleton_group_count_ != groups_.size())
      throw std::runtime_error("grouped factor partition differs");
    std::string observed_bytes;
    observed_bytes.reserve(observed_.size() * 4U);
    for (const int variable : observed_)
      append_u32_le(observed_bytes, static_cast<uint32_t>(variable));
    observed_sha256_ = sha256(observed_bytes);
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
      if (pending_ready_ || blocking_active_)
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
    if (pending_ready_ || blocking_active_)
      throw std::runtime_error("grouped joint-score backtrack with pending clause");
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
    if (!changed.empty())
      evaluate_current_bound(changed);
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
    ++external_clauses_emitted_;
    pending_clause_.clear();
    pending_cursor_ = 0;
    pending_ready_ = false;
    blocking_active_ = false;
    return 0;
  }

  const std::vector<int> &observed() const { return observed_; }

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
        << ",\"group_table_rows\":" << group_table_rows_
        << ",\"group_incident_edges\":" << group_incident_edges_
        << ",\"grouping_rule\":\"" << kGroupingRule
        << "\",\"grouping_sha256\":\"" << grouping_sha256_
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

  void build_groups() {
    std::vector<uint8_t> unmatched(field_.factors.size(), 1U);
    std::vector<std::pair<size_t, size_t>> pairs;
    for (size_t second = 0; second < field_.factors.size(); ++second) {
      for (size_t first = 0; first < second; ++first) {
        if (!unmatched[first])
          continue;
        const PotentialFactor &left = field_.factors[first];
        const PotentialFactor &right = field_.factors[second];
        if (!scopes_overlap(left.variables, right.variables))
          continue;
        const std::vector<int> variables =
            union_scope(left.variables, right.variables);
        if (variables.size() > static_cast<size_t>(kMaximumFactorVariables))
          continue;
        unmatched[first] = 0U;
        unmatched[second] = 0U;
        pairs.emplace_back(first, second);
        break;
      }
    }
    groups_.reserve(pairs.size() + field_.factors.size());
    for (const auto [first, second] : pairs) {
      const PotentialFactor &left = field_.factors[first];
      const PotentialFactor &right = field_.factors[second];
      CompatibilityGroup group;
      group.factor_indices = {first, second};
      group.variables = union_scope(left.variables, right.variables);
      group.energies.resize(size_t{1} << group.variables.size());
      for (size_t row = 0; row < group.energies.size(); ++row) {
        const size_t left_row =
            project_union_row(row, group.variables, left.variables);
        const size_t right_row =
            project_union_row(row, group.variables, right.variables);
        group.energies[row] =
            upward_pair_energy(left.energies.at(left_row),
                               right.energies.at(right_row));
      }
      groups_.push_back(std::move(group));
      ++pair_group_count_;
    }
    for (size_t index = 0; index < field_.factors.size(); ++index) {
      if (!unmatched[index])
        continue;
      const PotentialFactor &factor = field_.factors[index];
      CompatibilityGroup group;
      group.factor_indices = {index};
      group.variables = factor.variables;
      group.energies = factor.energies;
      groups_.push_back(std::move(group));
      ++singleton_group_count_;
    }
    std::sort(groups_.begin(), groups_.end(),
              [](const CompatibilityGroup &left,
                 const CompatibilityGroup &right) {
                return left.factor_indices.front() <
                       right.factor_indices.front();
              });
    std::vector<uint8_t> seen(field_.factors.size(), 0U);
    for (const CompatibilityGroup &group : groups_) {
      if (group.factor_indices.empty() || group.factor_indices.size() > 2U ||
          group.variables.empty() ||
          group.variables.size() >
              static_cast<size_t>(kMaximumFactorVariables))
        throw std::runtime_error("grouped factor shape differs");
      for (const size_t index : group.factor_indices) {
        if (index >= seen.size() || seen[index])
          throw std::runtime_error("grouped factor membership differs");
        seen[index] = 1U;
      }
    }
    if (std::find(seen.begin(), seen.end(), uint8_t{0}) != seen.end())
      throw std::runtime_error("grouped factor omission differs");
    std::string serialized("O1-GROUPED-BOUND-V1\0", 20U);
    append_u32_le(serialized, static_cast<uint32_t>(groups_.size()));
    for (const CompatibilityGroup &group : groups_) {
      serialized.push_back(static_cast<char>(group.factor_indices.size()));
      for (const size_t factor_index : group.factor_indices)
        append_u32_le(serialized, static_cast<uint32_t>(factor_index));
      serialized.push_back(static_cast<char>(group.variables.size()));
      for (const int variable : group.variables)
        append_u32_le(serialized, static_cast<uint32_t>(variable));
    }
    grouping_sha256_ = sha256(serialized);
  }

  double outward_add(double left, double right) const {
    const double raw = left + right;
    if (!std::isfinite(raw))
      throw std::runtime_error("grouped joint-score upper bound is not finite");
    const double bounded =
        std::nextafter(raw, std::numeric_limits<double>::infinity());
    if (!std::isfinite(bounded))
      throw std::runtime_error(
          "grouped joint-score upper bound is not representable");
    return bounded;
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
    double result = field_.offset;
    for (const double maximum : group_maxima_) {
      result = outward_add(result, maximum);
      ++bound_additions_;
    }
    return result;
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
  std::string observed_sha256_;
  std::string grouping_sha256_;
  double root_upper_bound_ = 0.0;
  double minimum_upper_bound_ = 0.0;
  double maximum_upper_bound_ = 0.0;
  double minimum_complete_score_ = 0.0;
  double maximum_complete_score_ = 0.0;
  bool have_complete_score_ = false;
  bool have_clause_length_ = false;
  size_t pair_group_count_ = 0;
  size_t singleton_group_count_ = 0;
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

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");
    const std::string cnf_payload = read_binary_file(arguments.cnf_path, "CNF");
    const std::string potential_payload =
        read_binary_file(arguments.potential_path, "potential");
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
    auto propagator = std::make_unique<GroupedJointScoreSieve>(
        std::move(field), arguments.threshold);
    ExternalConnectionGuard connection(&solver);
    connection.connect(propagator.get());
    for (const int variable : propagator->observed())
      solver.add_observed_var(variable);
    if (!solver.limit("conflicts", arguments.conflict_limit))
      throw std::runtime_error("CaDiCaL rejected conflict limit");
    const int64_t conflicts_before_solve = statistic(solver, "conflicts");
    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);
    const int64_t conflicts = statistic(solver, "conflicts");
    if (conflicts < conflicts_before_solve)
      throw std::runtime_error("CaDiCaL conflict counter regressed");
    const int64_t solve_conflicts = conflicts - conflicts_before_solve;
    const std::string model = status == 10 ? key_hex(solver) : std::string();
    connection.disconnect();

    std::cout << std::setprecision(std::numeric_limits<double>::max_digits10)
              << "{\"schema\":\"" << kGroupedSchema
              << "\",\"cadical_version\":\"" << CaDiCaL::Solver::version()
              << "\",\"variables\":" << variables
              << ",\"conflict_limit\":" << arguments.conflict_limit
              << ",\"seed\":" << arguments.seed << ",\"threshold\":"
              << arguments.threshold << ",\"status\":" << status
              << ",\"key_model_hex\":";
    if (status == 10)
      std::cout << '"' << model << '"';
    else
      std::cout << "null";
    std::cout << ",\"cnf_sha256\":\"" << sha256(cnf_payload)
              << "\",\"potential_sha256\":\"" << sha256(potential_payload)
              << "\",\"stats\":{\"conflicts\":" << conflicts
              << ",\"conflicts_before_solve\":" << conflicts_before_solve
              << ",\"solve_conflicts\":" << solve_conflicts
              << ",\"decisions\":" << statistic(solver, "decisions")
              << ",\"propagations\":" << statistic(solver, "propagations")
              << "},\"sieve\":{";
    propagator->write_json(std::cout);
    std::cout << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
              << ",\"cpu_microseconds\":" << cpu_microseconds()
              << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_joint_score_sieve_v3: " << error.what() << '\n';
    return 1;
  }
}
