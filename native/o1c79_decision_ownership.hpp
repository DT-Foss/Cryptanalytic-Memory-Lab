#ifndef O1_CRYPTO_LAB_O1C79_DECISION_OWNERSHIP_HPP
#define O1_CRYPTO_LAB_O1C79_DECISION_OWNERSHIP_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace o1c79 {

enum class DecisionOrigin : uint8_t {
  NONE = 0,
  PREFIX = 1,
  RANK_ORIGINAL = 2,
  RANK_CONTRAST = 3,
  FRONTIER_INITIAL = 4,
  FRONTIER_CONTRAST = 5,
};

inline const char *origin_name(DecisionOrigin origin) {
  switch (origin) {
  case DecisionOrigin::NONE:
    return "NONE";
  case DecisionOrigin::PREFIX:
    return "PREFIX";
  case DecisionOrigin::RANK_ORIGINAL:
    return "RANK_ORIGINAL";
  case DecisionOrigin::RANK_CONTRAST:
    return "RANK_CONTRAST";
  case DecisionOrigin::FRONTIER_INITIAL:
    return "FRONTIER_INITIAL";
  case DecisionOrigin::FRONTIER_CONTRAST:
    return "FRONTIER_CONTRAST";
  }
  throw std::runtime_error("decision ownership origin differs");
}

inline size_t origin_index(DecisionOrigin origin) {
  const size_t index = static_cast<size_t>(origin);
  if (!index || index >= 6U)
    throw std::runtime_error("decision ownership counted origin differs");
  return index;
}

enum class OwnershipEventKind : uint8_t {
  PROPOSED = 1,
  LEVEL_BOUND = 2,
  CONFIRMED = 3,
  OPPOSITE_ASSIGNMENT = 4,
  FOREIGN_ASSIGNMENT = 5,
  RENOTIFIED = 6,
  RELEASED = 7,
  LEVEL_BOUND_UNOBSERVED_RELEASE = 8,
};

inline const char *event_name(OwnershipEventKind kind) {
  switch (kind) {
  case OwnershipEventKind::PROPOSED:
    return "PROPOSED";
  case OwnershipEventKind::LEVEL_BOUND:
    return "LEVEL_BOUND";
  case OwnershipEventKind::CONFIRMED:
    return "CONFIRMED";
  case OwnershipEventKind::OPPOSITE_ASSIGNMENT:
    return "OPPOSITE_ASSIGNMENT";
  case OwnershipEventKind::FOREIGN_ASSIGNMENT:
    return "FOREIGN_ASSIGNMENT";
  case OwnershipEventKind::RENOTIFIED:
    return "RENOTIFIED";
  case OwnershipEventKind::RELEASED:
    return "RELEASED";
  case OwnershipEventKind::LEVEL_BOUND_UNOBSERVED_RELEASE:
    return "LEVEL_BOUND_UNOBSERVED_RELEASE";
  }
  throw std::runtime_error("decision ownership event kind differs");
}

struct DecisionToken {
  uint64_t token = 0;
  uint64_t callback = 0;
  DecisionOrigin origin = DecisionOrigin::PREFIX;
  uint32_t row = 0;
  int literal = 0;
  uint32_t bound_level = 0;
  bool confirmed = false;
};

struct OwnershipEvent {
  uint64_t sequence = 0;
  OwnershipEventKind kind = OwnershipEventKind::PROPOSED;
  uint64_t token = 0;
  uint64_t callback = 0;
  DecisionOrigin origin = DecisionOrigin::PREFIX;
  uint32_t row = 0;
  int literal = 0;
  uint32_t level = 0;
  int observed_literal = 0;
};

// A callback proposal is pending until CaDiCaL opens the corresponding
// decision level.  Bound tokens can coexist at nested levels.  Retirement is
// driven only by token level and origin, never by a historical variable/sign
// bit.  This is intentional: assignment notifications are not guaranteed to
// arrive eagerly.
class DecisionOwnershipLedger final {
public:
  static constexpr size_t kMaximumTokens = 4194304U;
  static constexpr size_t kMaximumRecordedEvents = 65536U;

  uint64_t propose(DecisionOrigin origin, uint32_t row, int literal,
                   uint64_t callback) {
    const size_t counted_origin = origin_index(origin);
    if (!literal || literal == std::numeric_limits<int32_t>::min() ||
        !callback)
      throw std::runtime_error("decision ownership proposal differs");
    if (pending_.token)
      throw std::runtime_error("decision ownership proposal already pending");
    if (has_live_variable(std::abs(literal)))
      throw std::runtime_error(
          "decision ownership variable already has a live token");
    if (tokens_created_ >= kMaximumTokens)
      throw std::runtime_error("decision ownership token cap exceeded");
    require_event_capacity(1U);
    DecisionToken token;
    token.token = ++tokens_created_;
    token.callback = callback;
    token.origin = origin;
    token.row = row;
    token.literal = literal;
    pending_ = token;
    append_event(OwnershipEventKind::PROPOSED, pending_, current_level_, 0);
    ++proposals_;
    ++origin_proposals_.at(counted_origin);
    return token.token;
  }

  void notify_new_decision_level(uint32_t new_level) {
    if (new_level != current_level_ + 1U)
      throw std::runtime_error("decision ownership new level differs");
    if (!pending_.token) {
      current_level_ = new_level;
      return;
    }
    require_event_capacity(1U);
    current_level_ = new_level;
    pending_.bound_level = new_level;
    active_.push_back(pending_);
    append_event(OwnershipEventKind::LEVEL_BOUND, active_.back(), new_level, 0);
    pending_ = DecisionToken{};
    ++level_bound_;
    ++origin_level_bound_.at(origin_index(active_.back().origin));
    maximum_live_tokens_ = std::max(maximum_live_tokens_, active_.size());
  }

  void notify_assignment(int literal) {
    if (!literal || literal == std::numeric_limits<int32_t>::min())
      throw std::runtime_error("decision ownership assignment differs");
    DecisionToken *candidate = nullptr;
    for (DecisionToken &token : active_) {
      if (std::abs(token.literal) != std::abs(literal) ||
          token.bound_level > current_level_)
        continue;
      if (!candidate || token.bound_level > candidate->bound_level ||
          (token.bound_level == candidate->bound_level &&
           token.token > candidate->token))
        candidate = &token;
    }
    if (!candidate) {
      append_foreign_assignment(literal);
      return;
    }
    require_event_capacity(1U);
    if (candidate->literal != literal) {
      append_event(OwnershipEventKind::OPPOSITE_ASSIGNMENT, *candidate,
                   current_level_, literal);
      ++opposite_assignments_;
      return;
    }
    if (candidate->confirmed) {
      append_event(OwnershipEventKind::RENOTIFIED, *candidate, current_level_,
                   literal);
      ++renotifications_;
      return;
    }
    candidate->confirmed = true;
    append_event(OwnershipEventKind::CONFIRMED, *candidate, current_level_,
                 literal);
    ++confirmed_;
    ++origin_confirmed_.at(origin_index(candidate->origin));
  }

  std::vector<DecisionToken> notify_backtrack(uint32_t new_level) {
    if (new_level > current_level_)
      throw std::runtime_error("decision ownership backtrack level differs");
    if (pending_.token)
      throw std::runtime_error(
          "decision ownership backtrack overlaps pending proposal");
    std::vector<DecisionToken> released;
    released.reserve(active_.size());
    for (auto iterator = active_.rbegin(); iterator != active_.rend(); ++iterator)
      if (iterator->bound_level > new_level)
        released.push_back(*iterator);

    // Validate the complete transition before mutating the live set.  The
    // subsequent erase and event append therefore retire the batch atomically.
    for (const DecisionToken &token : released)
      if (!token.token || !token.bound_level || token.bound_level > current_level_)
        throw std::runtime_error("decision ownership release token differs");
    require_event_capacity(released.size());
    active_.erase(std::remove_if(active_.begin(), active_.end(),
                                 [new_level](const DecisionToken &token) {
                                   return token.bound_level > new_level;
                                 }),
                  active_.end());
    current_level_ = new_level;
    for (const DecisionToken &token : released) {
      const OwnershipEventKind kind =
          token.confirmed
              ? OwnershipEventKind::RELEASED
              : OwnershipEventKind::LEVEL_BOUND_UNOBSERVED_RELEASE;
      append_event(kind, token, new_level, 0);
      if (token.confirmed)
        ++confirmed_releases_;
      else
        ++unobserved_releases_;
      ++origin_releases_.at(origin_index(token.origin));
    }
    releases_ += released.size();
    return released;
  }

  void validate_solve_end() const {
    if (pending_.token)
      throw std::runtime_error(
          "decision ownership solve end overlaps pending proposal");
    validate();
  }

  const std::vector<OwnershipEvent> &events() const { return events_; }
  const std::vector<DecisionToken> &active_tokens() const { return active_; }
  uint32_t current_level() const { return current_level_; }
  uint64_t proposals() const { return proposals_; }
  uint64_t level_bound() const { return level_bound_; }
  uint64_t confirmed() const { return confirmed_; }
  uint64_t releases() const { return releases_; }
  uint64_t confirmed_releases() const { return confirmed_releases_; }
  uint64_t unobserved_releases() const { return unobserved_releases_; }
  uint64_t opposite_assignments() const { return opposite_assignments_; }
  uint64_t foreign_assignments() const { return foreign_assignments_; }
  uint64_t renotifications() const { return renotifications_; }
  size_t maximum_live_tokens() const { return maximum_live_tokens_; }
  uint64_t origin_proposals(DecisionOrigin origin) const {
    return origin_proposals_.at(origin_index(origin));
  }
  uint64_t origin_level_bound(DecisionOrigin origin) const {
    return origin_level_bound_.at(origin_index(origin));
  }
  uint64_t origin_confirmed(DecisionOrigin origin) const {
    return origin_confirmed_.at(origin_index(origin));
  }
  uint64_t origin_releases(DecisionOrigin origin) const {
    return origin_releases_.at(origin_index(origin));
  }
  bool has_pending() const { return pending_.token != 0; }
  bool has_live_variable(int variable) const {
    if (variable <= 0)
      throw std::runtime_error("decision ownership live variable differs");
    return std::any_of(active_.begin(), active_.end(),
                       [variable](const DecisionToken &token) {
                         return std::abs(token.literal) == variable;
                       });
  }

  void write_json(std::ostream &out) const {
    validate();
    out << "\"schema\":\"o1-256-central-decision-ownership-v1\""
        << ",\"lifecycle\":\"PROPOSED->LEVEL_BOUND->optional-CONFIRMED->"
           "RELEASED-or-LEVEL_BOUND_UNOBSERVED_RELEASE\""
        << ",\"eligibility_rule\":\"origin-row-level-token;never-returned-"
           "ever-plus-variable-sign\""
        << ",\"assignment_notification_rule\":\"confirmation-is-evidence-"
           "not-release-precondition;opposite-and-foreign-never-claim-token\""
        << ",\"current_level\":" << current_level_
        << ",\"proposals\":" << proposals_
        << ",\"level_bound_interventions\":" << level_bound_
        << ",\"confirmed_interventions\":" << confirmed_
        << ",\"releases\":" << releases_
        << ",\"confirmed_releases\":" << confirmed_releases_
        << ",\"level_bound_unobserved_releases\":"
        << unobserved_releases_
        << ",\"opposite_assignments\":" << opposite_assignments_
        << ",\"foreign_assignments\":" << foreign_assignments_
        << ",\"renotifications\":" << renotifications_
        << ",\"live_tokens\":" << active_.size()
        << ",\"maximum_live_tokens\":" << maximum_live_tokens_
        << ",\"event_count\":"
        << events_.size()
        << ",\"recorded_event_count\":" << events_.size()
        << ",\"omitted_event_count\":0"
        << ",\"proposal_activated\":" << (proposals_ ? "true" : "false")
        << ",\"level_bound_activated\":"
        << (level_bound_ ? "true" : "false")
        << ",\"confirmed_activated\":"
        << (confirmed_ ? "true" : "false") << ",\"events\":[";
    for (size_t index = 0; index < events_.size(); ++index) {
      if (index)
        out << ',';
      const OwnershipEvent &event = events_[index];
      out << "{\"sequence\":" << event.sequence << ",\"kind\":\""
          << event_name(event.kind) << "\",\"token\":" << event.token
          << ",\"callback\":" << event.callback << ",\"origin\":\""
          << origin_name(event.origin) << "\",\"row\":" << event.row
          << ",\"literal\":" << event.literal << ",\"level\":"
          << event.level << ",\"observed_literal\":"
          << event.observed_literal << '}';
    }
    out << "],\"origin_counts\":{";
    bool first_origin = true;
    for (const DecisionOrigin origin : {
             DecisionOrigin::PREFIX, DecisionOrigin::RANK_ORIGINAL,
             DecisionOrigin::RANK_CONTRAST, DecisionOrigin::FRONTIER_INITIAL,
             DecisionOrigin::FRONTIER_CONTRAST}) {
      if (!first_origin)
        out << ',';
      first_origin = false;
      const size_t index = origin_index(origin);
      out << '\"' << origin_name(origin) << "\":{\"proposals\":"
          << origin_proposals_[index] << ",\"level_bound\":"
          << origin_level_bound_[index] << ",\"confirmed\":"
          << origin_confirmed_[index] << ",\"releases\":"
          << origin_releases_[index] << '}';
    }
    out << '}';
  }

private:
  void append_foreign_assignment(int literal) {
    require_event_capacity(1U);
    DecisionToken synthetic;
    synthetic.origin = DecisionOrigin::NONE;
    synthetic.literal = literal;
    append_event(OwnershipEventKind::FOREIGN_ASSIGNMENT, synthetic,
                 current_level_, literal);
    ++foreign_assignments_;
  }

  void append_event(OwnershipEventKind kind, const DecisionToken &token,
                    uint32_t level, int observed_literal) {
    require_event_capacity(1U);
    OwnershipEvent event;
    event.sequence = events_.size() + 1U;
    event.kind = kind;
    event.token = token.token;
    event.callback = token.callback;
    event.origin = token.origin;
    event.row = token.row;
    event.literal = token.literal;
    event.level = level;
    event.observed_literal = observed_literal;
    events_.push_back(event);
  }

  void validate() const {
    if (proposals_ != tokens_created_ || level_bound_ > proposals_ ||
        confirmed_ > level_bound_ || releases_ > level_bound_ ||
        releases_ != confirmed_releases_ + unobserved_releases_ ||
        active_.size() + releases_ != level_bound_ ||
        maximum_live_tokens_ < active_.size() ||
        events_.size() !=
            proposals_ + level_bound_ + confirmed_ + releases_ +
                opposite_assignments_ + foreign_assignments_ +
                renotifications_)
      throw std::runtime_error("decision ownership telemetry differs");
    uint64_t prior_token = 0;
    std::vector<int> live_variables;
    live_variables.reserve(active_.size());
    for (const DecisionToken &token : active_) {
      if (!token.token || token.token <= prior_token || !token.bound_level ||
          token.bound_level > current_level_)
        throw std::runtime_error("decision ownership live token differs");
      prior_token = token.token;
      live_variables.push_back(std::abs(token.literal));
    }
    std::sort(live_variables.begin(), live_variables.end());
    if (std::adjacent_find(live_variables.begin(), live_variables.end()) !=
        live_variables.end())
      throw std::runtime_error("decision ownership live variable repeats");
    for (size_t index = 0; index < events_.size(); ++index)
      if (events_[index].sequence != index + 1U)
        throw std::runtime_error("decision ownership event sequence differs");
    uint64_t origin_proposals = 0;
    uint64_t origin_level_bound = 0;
    uint64_t origin_confirmed = 0;
    uint64_t origin_releases = 0;
    for (size_t index = 1; index < 6U; ++index) {
      origin_proposals += origin_proposals_[index];
      origin_level_bound += origin_level_bound_[index];
      origin_confirmed += origin_confirmed_[index];
      origin_releases += origin_releases_[index];
    }
    if (origin_proposals != proposals_ || origin_level_bound != level_bound_ ||
        origin_confirmed != confirmed_ || origin_releases != releases_)
      throw std::runtime_error("decision ownership origin counts differ");
  }

  void require_event_capacity(size_t additional) const {
    if (additional > kMaximumRecordedEvents - events_.size())
      throw std::runtime_error("decision ownership event cap exceeded");
  }

  uint32_t current_level_ = 0;
  uint64_t tokens_created_ = 0;
  uint64_t proposals_ = 0;
  uint64_t level_bound_ = 0;
  uint64_t confirmed_ = 0;
  uint64_t releases_ = 0;
  uint64_t confirmed_releases_ = 0;
  uint64_t unobserved_releases_ = 0;
  uint64_t opposite_assignments_ = 0;
  uint64_t foreign_assignments_ = 0;
  uint64_t renotifications_ = 0;
  size_t maximum_live_tokens_ = 0;
  DecisionToken pending_;
  std::vector<DecisionToken> active_;
  std::vector<OwnershipEvent> events_;
  std::array<uint64_t, 6> origin_proposals_{};
  std::array<uint64_t, 6> origin_level_bound_{};
  std::array<uint64_t, 6> origin_confirmed_{};
  std::array<uint64_t, 6> origin_releases_{};
};

} // namespace o1c79

#endif
