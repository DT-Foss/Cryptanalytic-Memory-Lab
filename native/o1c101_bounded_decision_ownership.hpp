#ifndef O1_CRYPTO_LAB_O1C101_BOUNDED_DECISION_OWNERSHIP_HPP
#define O1_CRYPTO_LAB_O1C101_BOUNDED_DECISION_OWNERSHIP_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace o1c101 {

// The public drop-in API intentionally keeps CaDiCaL's native `int` literal
// type.  Lock it to the serialized i32le ABI so JSON values and digest bytes
// can never describe different integer domains on a new platform.
static_assert(sizeof(int) == sizeof(int32_t),
              "decision ownership requires 32-bit int literals");
static_assert(std::numeric_limits<int>::is_signed &&
                  std::numeric_limits<int>::digits ==
                      std::numeric_limits<int32_t>::digits &&
                  std::numeric_limits<int>::min() ==
                      std::numeric_limits<int32_t>::min() &&
                  std::numeric_limits<int>::max() ==
                      std::numeric_limits<int32_t>::max(),
              "decision ownership int and i32 ranges differ");

enum class DecisionOrigin : uint8_t {
  NONE = 0,
  PREFIX = 1,
  RANK_ORIGINAL = 2,
  RANK_CONTRAST = 3,
  FRONTIER_INITIAL = 4,
  FRONTIER_CONTRAST = 5,
  BOUND_LOSING_CHILD = 6,
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
  case DecisionOrigin::BOUND_LOSING_CHILD:
    return "BOUND_LOSING_CHILD";
  }
  throw std::runtime_error("decision ownership origin differs");
}

inline size_t origin_index(DecisionOrigin origin) {
  const size_t index = static_cast<size_t>(origin);
  if (!index || index >= 7U)
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

namespace detail {

// Small, allocation-free SHA-256 state.  It is intentionally included here so
// the ownership ledger remains a standalone header and does not acquire an
// OpenSSL or platform-crypto dependency merely to compact telemetry.
class Sha256 final {
public:
  Sha256()
      : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
               0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

  void update(const uint8_t *data, size_t size) noexcept {
    for (size_t index = 0; index < size; ++index) {
      block_[block_size_++] = data[index];
      ++total_bytes_;
      if (block_size_ == block_.size()) {
        transform(block_.data());
        block_size_ = 0;
      }
    }
  }

  std::array<uint8_t, 32> digest() const noexcept {
    Sha256 copy = *this;
    const uint64_t message_bits = copy.total_bytes_ * 8U;
    const uint8_t marker = 0x80U;
    copy.update(&marker, 1U);
    const uint8_t zero = 0;
    while (copy.block_size_ != 56U)
      copy.update(&zero, 1U);
    std::array<uint8_t, 8> length{};
    for (size_t index = 0; index < length.size(); ++index)
      length[7U - index] =
          static_cast<uint8_t>(message_bits >> (index * 8U));
    copy.update(length.data(), length.size());

    std::array<uint8_t, 32> result{};
    for (size_t word = 0; word < copy.state_.size(); ++word)
      for (size_t byte = 0; byte < 4U; ++byte)
        result[word * 4U + byte] = static_cast<uint8_t>(
            copy.state_[word] >> ((3U - byte) * 8U));
    return result;
  }

  uint64_t total_bytes() const noexcept { return total_bytes_; }

private:
  static uint32_t rotate_right(uint32_t value, uint32_t count) noexcept {
    return (value >> count) | (value << (32U - count));
  }

  void transform(const uint8_t *block) noexcept {
    static constexpr std::array<uint32_t, 64> constants = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    };

    std::array<uint32_t, 64> words{};
    for (size_t index = 0; index < 16U; ++index) {
      const size_t offset = index * 4U;
      words[index] = (static_cast<uint32_t>(block[offset]) << 24U) |
                     (static_cast<uint32_t>(block[offset + 1U]) << 16U) |
                     (static_cast<uint32_t>(block[offset + 2U]) << 8U) |
                     static_cast<uint32_t>(block[offset + 3U]);
    }
    for (size_t index = 16U; index < words.size(); ++index) {
      const uint32_t a = words[index - 15U];
      const uint32_t b = words[index - 2U];
      const uint32_t sigma0 =
          rotate_right(a, 7U) ^ rotate_right(a, 18U) ^ (a >> 3U);
      const uint32_t sigma1 =
          rotate_right(b, 17U) ^ rotate_right(b, 19U) ^ (b >> 10U);
      words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
    }

    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];
    for (size_t index = 0; index < words.size(); ++index) {
      const uint32_t sum1 =
          rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
      const uint32_t choose = (e & f) ^ ((~e) & g);
      const uint32_t temporary1 =
          h + sum1 + choose + constants[index] + words[index];
      const uint32_t sum0 =
          rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
      const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temporary2 = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temporary1;
      d = c;
      c = b;
      b = a;
      a = temporary1 + temporary2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<uint32_t, 8> state_{};
  std::array<uint8_t, 64> block_{};
  size_t block_size_ = 0;
  uint64_t total_bytes_ = 0;
};

inline std::string hex_digest(const std::array<uint8_t, 32> &digest) {
  static constexpr char hexadecimal[] = "0123456789abcdef";
  std::string result(64U, '0');
  for (size_t index = 0; index < digest.size(); ++index) {
    result[index * 2U] = hexadecimal[digest[index] >> 4U];
    result[index * 2U + 1U] = hexadecimal[digest[index] & 0x0fU];
  }
  return result;
}

} // namespace detail

// A proposal remains pending until CaDiCaL opens its decision level.  Only
// state-bearing lifecycle events are retained.  High-volume observations that
// cannot change ownership are counted and committed into a fixed-state digest.
class DecisionOwnershipLedger final {
public:
  static constexpr size_t kMaximumTokens = 256U;
  static constexpr size_t kMaximumRecordedEvents = 4U * kMaximumTokens;
  static constexpr size_t kNonclaimRecordBytes = 42U;

  DecisionOwnershipLedger() {
    active_.reserve(kMaximumTokens);
    events_.reserve(kMaximumRecordedEvents);
  }

  uint64_t propose(DecisionOrigin origin, uint32_t row, int literal,
                   uint64_t callback) {
    const size_t counted_origin = origin_index(origin);
    validate_literal(literal, "proposal");
    if (!callback)
      throw std::runtime_error("decision ownership proposal differs");
    if (pending_.token)
      throw std::runtime_error("decision ownership proposal already pending");
    if (has_live_variable(std::abs(literal)))
      throw std::runtime_error(
          "decision ownership variable already has a live token");
    if (tokens_created_ >= kMaximumTokens)
      throw std::runtime_error("decision ownership token cap exceeded");
    require_lifecycle_capacity(1U);

    DecisionToken token;
    token.token = tokens_created_ + 1U;
    token.callback = callback;
    token.origin = origin;
    token.row = row;
    token.literal = literal;
    append_lifecycle(OwnershipEventKind::PROPOSED, token, current_level_, 0);
    pending_ = token;
    ++tokens_created_;
    ++proposals_;
    ++origin_proposals_[counted_origin];
    return token.token;
  }

  void notify_new_decision_level(uint32_t new_level) {
    if (current_level_ == std::numeric_limits<uint32_t>::max() ||
        new_level != current_level_ + 1U)
      throw std::runtime_error("decision ownership new level differs");
    if (!pending_.token) {
      current_level_ = new_level;
      return;
    }
    if (active_.size() >= kMaximumTokens)
      throw std::runtime_error("decision ownership live token cap exceeded");
    require_lifecycle_capacity(1U);

    DecisionToken bound = pending_;
    bound.bound_level = new_level;
    append_lifecycle(OwnershipEventKind::LEVEL_BOUND, bound, new_level, 0);
    current_level_ = new_level;
    active_.push_back(bound);
    pending_ = DecisionToken{};
    ++level_bound_;
    ++origin_level_bound_[origin_index(bound.origin)];
    maximum_live_tokens_ = std::max(maximum_live_tokens_, active_.size());
  }

  void notify_assignment(int literal) {
    validate_literal(literal, "assignment");
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
      DecisionToken synthetic;
      synthetic.origin = DecisionOrigin::NONE;
      synthetic.literal = literal;
      append_nonclaim(OwnershipEventKind::FOREIGN_ASSIGNMENT, synthetic,
                      current_level_, literal);
      ++foreign_assignments_;
      return;
    }
    if (candidate->literal != literal) {
      append_nonclaim(OwnershipEventKind::OPPOSITE_ASSIGNMENT, *candidate,
                      current_level_, literal);
      ++opposite_assignments_;
      return;
    }
    if (candidate->confirmed) {
      append_nonclaim(OwnershipEventKind::RENOTIFIED, *candidate,
                      current_level_, literal);
      ++renotifications_;
      return;
    }

    require_lifecycle_capacity(1U);
    append_lifecycle(OwnershipEventKind::CONFIRMED, *candidate, current_level_,
                     literal);
    candidate->confirmed = true;
    ++confirmed_;
    ++origin_confirmed_[origin_index(candidate->origin)];
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
    for (const DecisionToken &token : released)
      if (!token.token || !token.bound_level ||
          token.bound_level > current_level_)
        throw std::runtime_error("decision ownership release token differs");
    require_lifecycle_capacity(released.size());

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
      append_lifecycle(kind, token, new_level, 0);
      if (token.confirmed)
        ++confirmed_releases_;
      else
        ++unobserved_releases_;
      ++origin_releases_[origin_index(token.origin)];
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
  uint64_t total_event_count() const { return total_events_; }
  uint64_t lifecycle_event_count() const { return events_.size(); }
  uint64_t nonclaim_observation_count() const {
    return opposite_assignments_ + foreign_assignments_ + renotifications_;
  }
  std::string nonclaim_digest_sha256() const {
    return detail::hex_digest(nonclaim_digest_.digest());
  }
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
    const std::string digest = nonclaim_digest_sha256();
    out << "\"schema\":\"o1-256-bounded-decision-ownership-v3\""
        << ",\"lifecycle\":\"PROPOSED->LEVEL_BOUND->optional-CONFIRMED->"
           "RELEASED-or-LEVEL_BOUND_UNOBSERVED_RELEASE\""
        << ",\"event_retention\":\"state-bearing-lifecycle-only;nonclaim-"
           "observations-counted-and-sha256-committed\""
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
        << ",\"level_bound_unobserved_releases\":" << unobserved_releases_
        << ",\"opposite_assignments\":" << opposite_assignments_
        << ",\"foreign_assignments\":" << foreign_assignments_
        << ",\"renotifications\":" << renotifications_
        << ",\"live_tokens\":" << active_.size()
        << ",\"pending_tokens\":" << (pending_.token ? 1 : 0)
        << ",\"maximum_live_tokens\":" << maximum_live_tokens_
        << ",\"maximum_tokens\":" << kMaximumTokens
        << ",\"maximum_recorded_lifecycle_events\":"
        << kMaximumRecordedEvents
        << ",\"event_count\":" << total_events_
        << ",\"total_event_count\":" << total_events_
        << ",\"lifecycle_event_count\":" << events_.size()
        << ",\"recorded_event_count\":" << events_.size()
        << ",\"recorded_lifecycle_event_count\":" << events_.size()
        << ",\"omitted_event_count\":" << nonclaim_observation_count()
        << ",\"compacted_nonclaim_count\":" << nonclaim_observation_count()
        << ",\"events_are_lifecycle_only\":true"
        << ",\"events_have_global_sequence\":true"
        << ",\"proposal_activated\":" << (proposals_ ? "true" : "false")
        << ",\"level_bound_activated\":" << (level_bound_ ? "true" : "false")
        << ",\"confirmed_activated\":" << (confirmed_ ? "true" : "false")
        << ",\"nonclaim_kind_counts\":{\"OPPOSITE_ASSIGNMENT\":"
        << opposite_assignments_ << ",\"FOREIGN_ASSIGNMENT\":"
        << foreign_assignments_ << ",\"RENOTIFIED\":" << renotifications_
        << "},\"nonclaim_stream_digest\":{\"algorithm\":\"SHA-256\""
        << ",\"encoding\":\"o1c101-nonclaim-canonical-le-v1\""
        << ",\"record_bytes\":" << kNonclaimRecordBytes
        << ",\"field_layout\":\"sequence:u64le,kind:u8,token:u64le,"
           "callback:u64le,origin:u8,row:u32le,literal:i32le,level:u32le,"
           "observed_literal:i32le\""
        << ",\"record_count\":" << nonclaim_observation_count()
        << ",\"sha256\":\"" << digest << "\"},\"events\":[";
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
             DecisionOrigin::FRONTIER_CONTRAST,
             DecisionOrigin::BOUND_LOSING_CHILD}) {
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
  struct ValidationToken {
    bool present = false;
    uint8_t state = 0;
    uint64_t callback = 0;
    DecisionOrigin origin = DecisionOrigin::NONE;
    uint32_t row = 0;
    int literal = 0;
    uint32_t bound_level = 0;
  };

  static bool is_lifecycle_kind(OwnershipEventKind kind) {
    return kind == OwnershipEventKind::PROPOSED ||
           kind == OwnershipEventKind::LEVEL_BOUND ||
           kind == OwnershipEventKind::CONFIRMED ||
           kind == OwnershipEventKind::RELEASED ||
           kind == OwnershipEventKind::LEVEL_BOUND_UNOBSERVED_RELEASE;
  }

  static bool is_nonclaim_kind(OwnershipEventKind kind) {
    return kind == OwnershipEventKind::OPPOSITE_ASSIGNMENT ||
           kind == OwnershipEventKind::FOREIGN_ASSIGNMENT ||
           kind == OwnershipEventKind::RENOTIFIED;
  }

  static void validate_literal(int literal, const char *context) {
    if (!literal || literal == std::numeric_limits<int32_t>::min())
      throw std::runtime_error(std::string("decision ownership ") + context +
                               " differs");
  }

  static void put_u32_le(std::array<uint8_t, kNonclaimRecordBytes> &record,
                         size_t &offset, uint32_t value) noexcept {
    for (size_t byte = 0; byte < 4U; ++byte)
      record[offset++] = static_cast<uint8_t>(value >> (byte * 8U));
  }

  static void put_u64_le(std::array<uint8_t, kNonclaimRecordBytes> &record,
                         size_t &offset, uint64_t value) noexcept {
    for (size_t byte = 0; byte < 8U; ++byte)
      record[offset++] = static_cast<uint8_t>(value >> (byte * 8U));
  }

  void append_lifecycle(OwnershipEventKind kind, const DecisionToken &token,
                        uint32_t level, int observed_literal) {
    if (!is_lifecycle_kind(kind))
      throw std::runtime_error("decision ownership lifecycle kind differs");
    require_lifecycle_capacity(1U);
    OwnershipEvent event;
    event.sequence = total_events_ + 1U;
    event.kind = kind;
    event.token = token.token;
    event.callback = token.callback;
    event.origin = token.origin;
    event.row = token.row;
    event.literal = token.literal;
    event.level = level;
    event.observed_literal = observed_literal;
    events_.push_back(event);
    ++total_events_;
  }

  void append_nonclaim(OwnershipEventKind kind, const DecisionToken &token,
                       uint32_t level, int observed_literal) noexcept {
    std::array<uint8_t, kNonclaimRecordBytes> record{};
    size_t offset = 0;
    put_u64_le(record, offset, total_events_ + 1U);
    record[offset++] = static_cast<uint8_t>(kind);
    put_u64_le(record, offset, token.token);
    put_u64_le(record, offset, token.callback);
    record[offset++] = static_cast<uint8_t>(token.origin);
    put_u32_le(record, offset, token.row);
    put_u32_le(record, offset,
               static_cast<uint32_t>(static_cast<int32_t>(token.literal)));
    put_u32_le(record, offset, level);
    put_u32_le(
        record, offset,
        static_cast<uint32_t>(static_cast<int32_t>(observed_literal)));
    nonclaim_digest_.update(record.data(), record.size());
    ++total_events_;
  }

  void validate() const {
    const uint64_t nonclaims = nonclaim_observation_count();
    if (tokens_created_ > kMaximumTokens || proposals_ != tokens_created_ ||
        level_bound_ > proposals_ || confirmed_ > level_bound_ ||
        releases_ > level_bound_ ||
        proposals_ != level_bound_ + (pending_.token ? 1U : 0U) ||
        releases_ != confirmed_releases_ + unobserved_releases_ ||
        active_.size() + releases_ != level_bound_ ||
        maximum_live_tokens_ < active_.size() ||
        maximum_live_tokens_ > kMaximumTokens ||
        events_.size() > kMaximumRecordedEvents ||
        events_.size() != proposals_ + level_bound_ + confirmed_ + releases_ ||
        total_events_ != events_.size() + nonclaims ||
        nonclaim_digest_.total_bytes() != nonclaims * kNonclaimRecordBytes)
      throw std::runtime_error("decision ownership telemetry differs");

    size_t active_confirmed = 0;
    uint64_t prior_token = 0;
    std::vector<int> live_variables;
    live_variables.reserve(active_.size());
    for (const DecisionToken &token : active_) {
      if (!token.token || token.token <= prior_token ||
          token.token > tokens_created_ || !token.callback ||
          token.origin == DecisionOrigin::NONE || !token.literal ||
          !token.bound_level || token.bound_level > current_level_)
        throw std::runtime_error("decision ownership live token differs");
      prior_token = token.token;
      live_variables.push_back(std::abs(token.literal));
      active_confirmed += token.confirmed ? 1U : 0U;
    }
    if (active_confirmed + confirmed_releases_ != confirmed_)
      throw std::runtime_error("decision ownership confirmation differs");
    std::sort(live_variables.begin(), live_variables.end());
    if (std::adjacent_find(live_variables.begin(), live_variables.end()) !=
        live_variables.end())
      throw std::runtime_error("decision ownership live variable repeats");
    if (pending_.token &&
        (pending_.token != tokens_created_ || !pending_.callback ||
         pending_.origin == DecisionOrigin::NONE || !pending_.literal ||
         pending_.bound_level || pending_.confirmed ||
         std::binary_search(live_variables.begin(), live_variables.end(),
                            std::abs(pending_.literal))))
      throw std::runtime_error("decision ownership pending token differs");

    std::array<ValidationToken, kMaximumTokens + 1U> transcript{};
    std::array<uint64_t, 7> event_origin_proposals{};
    std::array<uint64_t, 7> event_origin_level_bound{};
    std::array<uint64_t, 7> event_origin_confirmed{};
    std::array<uint64_t, 7> event_origin_releases{};
    uint64_t counted_proposals = 0;
    uint64_t counted_level_bound = 0;
    uint64_t counted_confirmed = 0;
    uint64_t counted_releases = 0;
    uint64_t prior_sequence = 0;
    for (const OwnershipEvent &event : events_) {
      if (!is_lifecycle_kind(event.kind) || !event.sequence ||
          event.sequence <= prior_sequence || event.sequence > total_events_ ||
          !event.token || event.token > tokens_created_ ||
          event.origin == DecisionOrigin::NONE || !event.callback ||
          !event.literal)
        throw std::runtime_error("decision ownership lifecycle event differs");
      prior_sequence = event.sequence;
      const size_t origin = origin_index(event.origin);
      ValidationToken &token = transcript[static_cast<size_t>(event.token)];
      if (event.kind == OwnershipEventKind::PROPOSED) {
        if (token.present || event.observed_literal)
          throw std::runtime_error("decision ownership proposal event differs");
        token.present = true;
        token.state = 1U;
        token.callback = event.callback;
        token.origin = event.origin;
        token.row = event.row;
        token.literal = event.literal;
        ++counted_proposals;
        ++event_origin_proposals[origin];
        continue;
      }
      if (!token.present || token.callback != event.callback ||
          token.origin != event.origin || token.row != event.row ||
          token.literal != event.literal)
        throw std::runtime_error("decision ownership token transcript differs");
      if (event.kind == OwnershipEventKind::LEVEL_BOUND) {
        if (token.state != 1U || !event.level || event.observed_literal)
          throw std::runtime_error("decision ownership level event differs");
        token.state = 2U;
        token.bound_level = event.level;
        ++counted_level_bound;
        ++event_origin_level_bound[origin];
      } else if (event.kind == OwnershipEventKind::CONFIRMED) {
        if (token.state != 2U || event.level < token.bound_level ||
            event.observed_literal != event.literal)
          throw std::runtime_error("decision ownership confirmed event differs");
        token.state = 3U;
        ++counted_confirmed;
        ++event_origin_confirmed[origin];
      } else {
        const bool confirmed_release = event.kind == OwnershipEventKind::RELEASED;
        if ((confirmed_release && token.state != 3U) ||
            (!confirmed_release && token.state != 2U) ||
            event.level >= token.bound_level || event.observed_literal)
          throw std::runtime_error("decision ownership release event differs");
        token.state = 4U;
        ++counted_releases;
        ++event_origin_releases[origin];
      }
    }
    if (counted_proposals != proposals_ ||
        counted_level_bound != level_bound_ ||
        counted_confirmed != confirmed_ || counted_releases != releases_)
      throw std::runtime_error("decision ownership lifecycle counts differ");

    std::array<bool, kMaximumTokens + 1U> live{};
    if (pending_.token) {
      const ValidationToken &entry = transcript[pending_.token];
      if (entry.state != 1U || entry.callback != pending_.callback ||
          entry.origin != pending_.origin || entry.row != pending_.row ||
          entry.literal != pending_.literal)
        throw std::runtime_error("decision ownership pending transcript differs");
      live[pending_.token] = true;
    }
    for (const DecisionToken &token : active_) {
      const ValidationToken &entry = transcript[token.token];
      const uint8_t expected_state = token.confirmed ? 3U : 2U;
      if (entry.state != expected_state || entry.callback != token.callback ||
          entry.origin != token.origin || entry.row != token.row ||
          entry.literal != token.literal ||
          entry.bound_level != token.bound_level || live[token.token])
        throw std::runtime_error("decision ownership active transcript differs");
      live[token.token] = true;
    }
    for (size_t token = 1; token <= tokens_created_; ++token)
      if (!transcript[token].present ||
          (!live[token] && transcript[token].state != 4U))
        throw std::runtime_error("decision ownership terminal transcript differs");

    uint64_t origin_proposals = 0;
    uint64_t origin_level_bound = 0;
    uint64_t origin_confirmed = 0;
    uint64_t origin_releases = 0;
    for (size_t index = 1; index < 7U; ++index) {
      origin_proposals += origin_proposals_[index];
      origin_level_bound += origin_level_bound_[index];
      origin_confirmed += origin_confirmed_[index];
      origin_releases += origin_releases_[index];
      if (event_origin_proposals[index] != origin_proposals_[index] ||
          event_origin_level_bound[index] != origin_level_bound_[index] ||
          event_origin_confirmed[index] != origin_confirmed_[index] ||
          event_origin_releases[index] != origin_releases_[index])
        throw std::runtime_error("decision ownership event origin differs");
    }
    if (origin_proposals != proposals_ || origin_level_bound != level_bound_ ||
        origin_confirmed != confirmed_ || origin_releases != releases_)
      throw std::runtime_error("decision ownership origin counts differ");

    const std::string digest = nonclaim_digest_sha256();
    if (digest.size() != 64U ||
        !std::all_of(digest.begin(), digest.end(), [](char character) {
          return (character >= '0' && character <= '9') ||
                 (character >= 'a' && character <= 'f');
        }))
      throw std::runtime_error("decision ownership digest differs");
  }

  void require_lifecycle_capacity(size_t additional) const {
    if (additional > kMaximumRecordedEvents - events_.size())
      throw std::runtime_error("decision ownership lifecycle cap exceeded");
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
  uint64_t total_events_ = 0;
  size_t maximum_live_tokens_ = 0;
  DecisionToken pending_;
  std::vector<DecisionToken> active_;
  std::vector<OwnershipEvent> events_;
  detail::Sha256 nonclaim_digest_;
  std::array<uint64_t, 7> origin_proposals_{};
  std::array<uint64_t, 7> origin_level_bound_{};
  std::array<uint64_t, 7> origin_confirmed_{};
  std::array<uint64_t, 7> origin_releases_{};
};

} // namespace o1c101

#endif
