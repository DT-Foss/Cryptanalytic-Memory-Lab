#ifndef O1_CRYPTO_LAB_O1C80_ONE_BIT_BOUND_HPP
#define O1_CRYPTO_LAB_O1C80_ONE_BIT_BOUND_HPP

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace o1c80 {

// These signs deliberately match the native v6 convention: -1 is key bit 0
// and DIMACS literal -v, while +1 is key bit 1 and DIMACS literal +v.
struct ChildUpperBounds {
  double zero = 0.0;
  double one = 0.0;
};

enum class ChildProbeOrder : uint8_t {
  ZERO_THEN_ONE = 0,
  ONE_THEN_ZERO = 1,
};

enum class ChildSelectionClass : uint8_t {
  NEITHER_PRUNABLE = 0,
  ZERO_PRUNABLE = 1,
  ONE_PRUNABLE = 2,
  BOTH_PRUNABLE = 3,
};

inline const char *selection_class_name(ChildSelectionClass selection) {
  switch (selection) {
  case ChildSelectionClass::NEITHER_PRUNABLE:
    return "NEITHER_PRUNABLE";
  case ChildSelectionClass::ZERO_PRUNABLE:
    return "ZERO_PRUNABLE";
  case ChildSelectionClass::ONE_PRUNABLE:
    return "ONE_PRUNABLE";
  case ChildSelectionClass::BOTH_PRUNABLE:
    return "BOTH_PRUNABLE";
  }
  throw std::runtime_error("one-bit child selection class differs");
}

struct ChildBoundSelection {
  ChildUpperBounds bounds;
  ChildSelectionClass selection = ChildSelectionClass::NEITHER_PRUNABLE;
  int losing_literal = 0;
};

struct BoundCompatibilityGroup {
  std::vector<size_t> local_indices;
  std::vector<double> energies;
};

template <class ExactSum> struct ExactOneBitParentCache {
  const void *owner = nullptr;
  std::vector<int8_t> assignment;
  std::vector<double> group_maxima;
  ExactSum exact_sum;
};

// Immutable table view used by the O1C80 selector.  The caller builds these
// tables from the same potential and grouping bytes as v6, and supplies v6's
// ExactDoubleSum/upward_exact_sum pair to child_upper_bounds.  Probing copies
// the parent assignment and never invokes a propagator callback or touches a
// live group cache.
class ExactOneBitBoundReader final {
public:
  ExactOneBitBoundReader() = default;

  ExactOneBitBoundReader(std::vector<int> observed,
                         size_t key_variable_count, double offset,
                         std::vector<BoundCompatibilityGroup> groups)
      : observed_(std::move(observed)),
        key_variable_count_(key_variable_count), offset_(offset),
        groups_(std::move(groups)) {
    validate_model();
  }

  const std::vector<int> &observed() const { return observed_; }
  size_t key_variable_count() const { return key_variable_count_; }
  double offset() const { return offset_; }
  size_t group_count() const { return groups_.size(); }

  template <class ExactSum>
  ExactOneBitParentCache<ExactSum>
  prepare_parent(const std::vector<int8_t> &parent) const {
    validate_parent(parent);
    ExactOneBitParentCache<ExactSum> result;
    result.owner = this;
    result.assignment = parent;
    result.group_maxima.reserve(groups_.size());
    result.exact_sum.add(offset_);
    for (const BoundCompatibilityGroup &group : groups_) {
      const double maximum = certification_group_maximum(group, parent);
      result.group_maxima.push_back(maximum);
      result.exact_sum.add(maximum);
    }
    return result;
  }

  template <class ExactSum, class UpwardExactSum>
  ChildUpperBounds child_upper_bounds(
      const std::vector<int8_t> &parent, int variable,
      UpwardExactSum upward_exact_sum,
      ChildProbeOrder order = ChildProbeOrder::ZERO_THEN_ONE) const {
    const ExactOneBitParentCache<ExactSum> cache =
        prepare_parent<ExactSum>(parent);
    return child_upper_bounds(cache, variable, std::move(upward_exact_sum),
                              order);
  }

  template <class ExactSum, class UpwardExactSum>
  ChildUpperBounds child_upper_bounds(
      const ExactOneBitParentCache<ExactSum> &parent, int variable,
      UpwardExactSum upward_exact_sum,
      ChildProbeOrder order = ChildProbeOrder::ZERO_THEN_ONE) const {
    if (parent.owner != this || parent.assignment.size() != observed_.size() ||
        parent.group_maxima.size() != groups_.size())
      throw std::runtime_error("one-bit child-bound parent cache differs");
    validate_parent(parent.assignment);
    if (variable <= 0 ||
        static_cast<size_t>(variable) > key_variable_count_)
      throw std::runtime_error("one-bit child-bound variable is non-key");
    const auto found =
        std::lower_bound(observed_.begin(), observed_.end(), variable);
    if (found == observed_.end() || *found != variable)
      throw std::runtime_error("one-bit child-bound variable is unobserved");
    const size_t local = static_cast<size_t>(found - observed_.begin());
    if (parent.assignment.at(local))
      throw std::runtime_error("one-bit child-bound variable is assigned");

    std::vector<int8_t> child = parent.assignment;
    ChildUpperBounds result;
    const auto probe = [&](int8_t spin) {
      child[local] = spin;
      ExactSum exact = parent.exact_sum;
      for (const size_t group_index : incident_groups_.at(local)) {
        exact.add(parent.group_maxima.at(group_index), true);
        exact.add(certification_group_maximum(groups_.at(group_index), child));
      }
      const double upper = upward_exact_sum(
          std::move(exact), "O1C80 exact one-bit certified upper bound");
      child[local] = 0;
      return upper;
    };
    if (order == ChildProbeOrder::ZERO_THEN_ONE) {
      result.zero = probe(int8_t{-1});
      result.one = probe(int8_t{1});
    } else if (order == ChildProbeOrder::ONE_THEN_ZERO) {
      result.one = probe(int8_t{1});
      result.zero = probe(int8_t{-1});
    } else {
      throw std::runtime_error("one-bit child-bound probe order differs");
    }
    return result;
  }

  static ChildBoundSelection select(int variable, ChildUpperBounds bounds,
                                    double threshold) {
    if (variable <= 0 || !std::isfinite(bounds.zero) ||
        !std::isfinite(bounds.one) || !std::isfinite(threshold))
      throw std::runtime_error("one-bit child-bound selection input differs");
    const bool zero_dead = bounds.zero < threshold;
    const bool one_dead = bounds.one < threshold;
    ChildBoundSelection result;
    result.bounds = bounds;
    if (zero_dead && one_dead) {
      result.selection = ChildSelectionClass::BOTH_PRUNABLE;
      // Exact equality deliberately falls back to bit 0 / literal -v.
      result.losing_literal = bounds.one < bounds.zero ? variable : -variable;
    } else if (zero_dead) {
      result.selection = ChildSelectionClass::ZERO_PRUNABLE;
      result.losing_literal = -variable;
    } else if (one_dead) {
      result.selection = ChildSelectionClass::ONE_PRUNABLE;
      result.losing_literal = variable;
    } else {
      result.selection = ChildSelectionClass::NEITHER_PRUNABLE;
      result.losing_literal = 0;
    }
    return result;
  }

private:
  void validate_model() {
    if (!key_variable_count_ ||
        key_variable_count_ >
            static_cast<size_t>(std::numeric_limits<int>::max()) ||
        !std::isfinite(offset_) || observed_.empty() || groups_.empty())
      throw std::runtime_error("one-bit child-bound model differs");
    int previous = 0;
    for (const int variable : observed_) {
      if (variable <= previous)
        throw std::runtime_error(
            "one-bit child-bound observed order differs");
      previous = variable;
    }
    std::vector<bool> covered(observed_.size(), false);
    incident_groups_.assign(observed_.size(), {});
    for (size_t group_index = 0; group_index < groups_.size(); ++group_index) {
      const BoundCompatibilityGroup &group = groups_[group_index];
      if (group.local_indices.empty() ||
          group.local_indices.size() >=
              std::numeric_limits<size_t>::digits ||
          group.energies.size() !=
              (size_t{1} << group.local_indices.size()))
        throw std::runtime_error("one-bit child-bound group shape differs");
      size_t previous_local = std::numeric_limits<size_t>::max();
      for (const size_t local : group.local_indices) {
        if (local >= observed_.size() ||
            (previous_local != std::numeric_limits<size_t>::max() &&
             local <= previous_local))
          throw std::runtime_error(
              "one-bit child-bound group local order differs");
        covered[local] = true;
        incident_groups_[local].push_back(group_index);
        previous_local = local;
      }
      if (std::any_of(group.energies.begin(), group.energies.end(),
                      [](double energy) { return !std::isfinite(energy); }))
        throw std::runtime_error("one-bit child-bound group energy differs");
    }
    if (std::find(covered.begin(), covered.end(), false) != covered.end())
      throw std::runtime_error("one-bit child-bound observed coverage differs");
  }

  void validate_parent(const std::vector<int8_t> &parent) const {
    if (parent.size() != observed_.size())
      throw std::runtime_error("one-bit child-bound parent width differs");
    for (const int8_t spin : parent)
      if (spin < -1 || spin > 1)
        throw std::runtime_error("one-bit child-bound parent spin differs");
  }

  double certification_group_maximum(
      const BoundCompatibilityGroup &group,
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
          "one-bit child-bound has no consistent group row");
    return best;
  }

  std::vector<int> observed_;
  size_t key_variable_count_ = 0;
  double offset_ = 0.0;
  std::vector<BoundCompatibilityGroup> groups_;
  std::vector<std::vector<size_t>> incident_groups_;
};

} // namespace o1c80

#endif
