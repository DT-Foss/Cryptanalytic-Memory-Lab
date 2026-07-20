// O1C-0077 residual-polarity staging over the complete O1C-0076 reader.
//
// Native v14 remains frozen.  This translation unit parses and production-
// validates the immutable rank first, applies exactly two in-memory sign
// overlays without changing row order or rank evidence, and only then builds
// the embedded v14/v12 reader stack.  The outer observer never replaces a
// parent callback return.

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

#ifdef O1_CRYPTO_LAB_O1C77_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C76_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C77_UNDEF_O1C76_FIXTURE
#endif
namespace o1c77_embedded_v14 {
#include "cadical_o1_joint_score_sieve_v14.cpp"
} // namespace o1c77_embedded_v14
#ifdef O1_CRYPTO_LAB_O1C77_UNDEF_O1C76_FIXTURE
#undef O1_CRYPTO_LAB_O1C76_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C77_UNDEF_O1C76_FIXTURE
#endif

using namespace o1c77_embedded_v14;

namespace {

constexpr const char *kV15ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v15";
constexpr const char *kV15ReleaseParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v14";
constexpr const char *kReaderRankRole = "effective-derived-order";
constexpr const char *kStagingSchema =
    "o1-256-cadical-residual-polarity-staging-reader-v1";
constexpr const char *kStagingOperator =
    "parse-source-rank-then-two-row-polarity-overlay-before-v14";
constexpr const char *kStagingDecisionRule =
    "embedded-v14-return-unchanged;effective-original-sign-first;embedded-"
    "v12-release-contrast-opposite-of-effective-original";
constexpr const char *kStagingCallbackRule =
    "one-v14-call-per-callback;never-override-or-discard-parent-return;"
    "finalize-assignment-burst-at-next-callback-or-solve-end";
constexpr const char *kStagingStateEncoding =
    "two-overlay-bits-lsb-first-by-overlay-index";
constexpr const char *kStagingSequenceEncoding =
    "one-signed-i32le-literal-per-cb-decide-including-zero";
constexpr const char *kStagingTraceEncoding =
    "records:u64le-call;i32le-return;u64le-assignment-burst;u8-completion-"
    "one-next-callback-two-solve-end";
constexpr const char *kStagingBoundedStateRule =
    "observed-i8-assignment;bounded-observed-u32-local,u32-level-trail;"
    "two-overlay-bitsets;bounded-4194304-callback-records;bounded-four-"
    "overlay-events;exact-return-and-callback-trace-bytes";

constexpr std::string_view kStagingMagic(
    "O1-RESIDUAL-POLARITY-STAGING-V1\0", 32U);
constexpr uint32_t kStagingVersion = 1U;
constexpr uint32_t kMaximumStagingPayloadBytes = 16777216U;
constexpr uint32_t kMaximumStagingAssignments = 1600000U;
constexpr uint32_t kMaximumStagingRankRows = 512U;
constexpr uint32_t kStagingIntersectionRows = 5U;
constexpr uint32_t kStagingOverlayRows = 2U;
constexpr size_t kStagingChecksumBytes = 32U;
constexpr size_t kMaximumCallbackRecords = 4194304U;

constexpr const char *kProductionSourceResultSha256 =
    "5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198";
constexpr const char *kProductionSourceAssignmentSha256 =
    "c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2";
constexpr const char *kProductionActiveVaultSha256 =
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33";
constexpr const char *kProductionParentFrontierPlanSha256 =
    "83dbfbddd51bdbacb95a892cf3bc7e3c3953bc3e62b674d1f8388de7de53db30";
constexpr const char *kProductionSelectedClauseSha256 =
    "c4a9c471f9eb45829764a841fb8c6971eecdc8b9a9e251732d65875647f25322";
constexpr const char *kProductionSourceRankPayloadSha256 =
    "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae";
constexpr const char *kProductionSourceRankOrderSha256 =
    "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5";
constexpr const char *kProductionEffectiveRankOrderSha256 =
    "6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086";
constexpr uint32_t kProductionSelectedActiveIndex = 232U;
constexpr uint32_t kProductionSelectedUnionIndex = 526U;
constexpr uint32_t kProductionSelectedClauseLiteralCount = 2438U;

struct StagingIntersection {
  uint32_t rank_index = 0;
  int clause_literal = 0;
  int source_literal = 0;
  int effective_literal = 0;
};

struct StagingOverlay {
  uint32_t rank_index = 0;
  int source_literal = 0;
  int effective_literal = 0;
};

struct StagingPlan {
  std::string payload_sha256;
  std::string source_result_sha256;
  std::string source_assignment_sha256;
  std::string active_vault_sha256;
  std::string parent_frontier_plan_sha256;
  std::string selected_clause_sha256;
  std::string source_rank_payload_sha256;
  std::string source_rank_order_sha256;
  std::string effective_rank_order_sha256;
  uint32_t selected_active_index = 0;
  uint32_t selected_union_index = 0;
  uint32_t selected_clause_literal_count = 0;
  std::vector<int8_t> source_assignment;
  std::vector<int> source_rank_literals;
  std::vector<StagingIntersection> intersections;
  std::vector<StagingOverlay> overlays;
};

std::string read_bounded_staging_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input)
    throw std::runtime_error("cannot open residual-polarity staging plan");
  const std::streampos end = input.tellg();
  if (end < 0 || static_cast<uint64_t>(end) > kMaximumStagingPayloadBytes)
    throw std::runtime_error("residual-polarity staging plan exceeds hard cap");
  const size_t size = static_cast<size_t>(end);
  std::string payload(size, '\0');
  input.seekg(0, std::ios::beg);
  if (size && !input.read(payload.data(), static_cast<std::streamsize>(size)))
    throw std::runtime_error("cannot read residual-polarity staging plan");
  char trailing = 0;
  if (input.get(trailing))
    throw std::runtime_error("residual-polarity staging plan grew while reading");
  if (!input.eof() && input.fail())
    throw std::runtime_error("cannot finish residual-polarity staging plan");
  return payload;
}

void require_staging_literal(int literal, const char *field) {
  if (!literal || literal == std::numeric_limits<int32_t>::min())
    throw std::runtime_error(std::string(field) + " differs");
}

void staging_append_i32(std::string &payload, int literal) {
  append_u32_le(payload,
                static_cast<uint32_t>(static_cast<int32_t>(literal)));
}

void staging_append_u64(std::string &payload, uint64_t value) {
  for (unsigned shift = 0; shift < 64U; shift += 8U)
    payload.push_back(static_cast<char>((value >> shift) & 0xffU));
}

std::string rank_order_bytes(const std::vector<int> &literals) {
  std::string result;
  result.reserve(4U * literals.size());
  std::set<int> variables;
  for (const int literal : literals) {
    require_staging_literal(literal, "staging rank literal");
    if (!variables.insert(std::abs(literal)).second)
      throw std::runtime_error("staging rank variable repeats");
    staging_append_i32(result, literal);
  }
  return result;
}

StagingPlan parse_staging_plan(const std::string &payload) {
  if (payload.size() <= kStagingMagic.size() + kStagingChecksumBytes ||
      payload.size() > kMaximumStagingPayloadBytes)
    throw std::runtime_error("residual-polarity staging plan size differs");
  const size_t body_size = payload.size() - kStagingChecksumBytes;
  const std::string body = payload.substr(0, body_size);
  if (sha256(body) != bytes_hex(payload.substr(body_size)))
    throw std::runtime_error("residual-polarity staging checksum differs");
  size_t cursor = 0;
  if (body.size() < kStagingMagic.size() ||
      body.compare(0, kStagingMagic.size(), kStagingMagic.data(),
                   kStagingMagic.size()) != 0)
    throw std::runtime_error("residual-polarity staging magic differs");
  cursor += kStagingMagic.size();
  const std::array<uint32_t, 6> expected_header = {
      kStagingVersion,
      kMaximumStagingPayloadBytes,
      kMaximumStagingAssignments,
      kMaximumStagingRankRows,
      kStagingIntersectionRows,
      kStagingOverlayRows,
  };
  for (const uint32_t expected : expected_header)
    if (read_u32_le(body, cursor, "staging header") != expected)
      throw std::runtime_error("residual-polarity staging header differs");

  StagingPlan plan;
  plan.payload_sha256 = sha256(payload);
  plan.source_result_sha256 =
      read_digest_hex(body, cursor, "staging source result digest");
  plan.source_assignment_sha256 =
      read_digest_hex(body, cursor, "staging source assignment digest");
  plan.active_vault_sha256 =
      read_digest_hex(body, cursor, "staging active vault digest");
  plan.parent_frontier_plan_sha256 =
      read_digest_hex(body, cursor, "staging parent frontier plan digest");
  plan.selected_clause_sha256 =
      read_digest_hex(body, cursor, "staging selected clause digest");
  plan.source_rank_payload_sha256 =
      read_digest_hex(body, cursor, "staging source rank payload digest");
  plan.source_rank_order_sha256 =
      read_digest_hex(body, cursor, "staging source rank order digest");
  plan.effective_rank_order_sha256 =
      read_digest_hex(body, cursor, "staging effective rank order digest");
  plan.selected_active_index =
      read_u32_le(body, cursor, "staging selected active index");
  plan.selected_union_index =
      read_u32_le(body, cursor, "staging selected union index");
  plan.selected_clause_literal_count =
      read_u32_le(body, cursor, "staging selected clause literal count");
  if (!plan.selected_clause_literal_count)
    throw std::runtime_error("staging selected clause length differs");

  const uint32_t assignment_count =
      read_u32_le(body, cursor, "staging assignment count");
  if (assignment_count > kMaximumStagingAssignments || cursor > body.size() ||
      body.size() - cursor < assignment_count)
    throw std::runtime_error("staging assignment count differs");
  const std::string assignment_payload = body.substr(cursor, assignment_count);
  cursor += assignment_count;
  plan.source_assignment.reserve(assignment_count);
  for (const unsigned char byte : assignment_payload) {
    if (byte != 0U && byte != 1U && byte != 255U)
      throw std::runtime_error("staging assignment differs");
    plan.source_assignment.push_back(byte == 255U ? int8_t{-1}
                                                   : static_cast<int8_t>(byte));
  }
  if (sha256(assignment_payload) != plan.source_assignment_sha256)
    throw std::runtime_error("staging assignment digest differs");

  const uint32_t rank_count =
      read_u32_le(body, cursor, "staging rank row count");
  if (!rank_count || rank_count > kMaximumStagingRankRows)
    throw std::runtime_error("staging rank row count differs");
  plan.source_rank_literals.reserve(rank_count);
  for (uint32_t index = 0; index < rank_count; ++index) {
    const int literal = read_i32_le(body, cursor, "staging rank literal");
    require_staging_literal(literal, "staging rank literal");
    plan.source_rank_literals.push_back(literal);
  }
  if (sha256(rank_order_bytes(plan.source_rank_literals)) !=
      plan.source_rank_order_sha256)
    throw std::runtime_error("staging source rank order differs");

  const uint32_t intersection_count =
      read_u32_le(body, cursor, "staging intersection count");
  if (intersection_count != kStagingIntersectionRows)
    throw std::runtime_error("staging intersection count differs");
  plan.intersections.reserve(intersection_count);
  uint32_t previous_intersection = 0;
  for (uint32_t ordinal = 0; ordinal < intersection_count; ++ordinal) {
    StagingIntersection row;
    row.rank_index =
        read_u32_le(body, cursor, "staging intersection rank index");
    row.clause_literal =
        read_i32_le(body, cursor, "staging intersection clause literal");
    row.source_literal =
        read_i32_le(body, cursor, "staging intersection source literal");
    row.effective_literal =
        read_i32_le(body, cursor, "staging intersection effective literal");
    require_staging_literal(row.clause_literal,
                            "staging intersection clause literal");
    require_staging_literal(row.source_literal,
                            "staging intersection source literal");
    require_staging_literal(row.effective_literal,
                            "staging intersection effective literal");
    if (row.rank_index >= rank_count ||
        (ordinal && row.rank_index <= previous_intersection) ||
        std::abs(row.clause_literal) != std::abs(row.source_literal) ||
        std::abs(row.source_literal) != std::abs(row.effective_literal) ||
        plan.source_rank_literals[row.rank_index] != row.source_literal)
      throw std::runtime_error("staging intersection row differs");
    previous_intersection = row.rank_index;
    plan.intersections.push_back(row);
  }

  const uint32_t overlay_count =
      read_u32_le(body, cursor, "staging overlay count");
  if (overlay_count != kStagingOverlayRows)
    throw std::runtime_error("staging overlay count differs");
  plan.overlays.reserve(overlay_count);
  uint32_t previous_overlay = 0;
  for (uint32_t ordinal = 0; ordinal < overlay_count; ++ordinal) {
    StagingOverlay row;
    row.rank_index =
        read_u32_le(body, cursor, "staging overlay rank index");
    row.source_literal =
        read_i32_le(body, cursor, "staging overlay source literal");
    row.effective_literal =
        read_i32_le(body, cursor, "staging overlay effective literal");
    require_staging_literal(row.source_literal,
                            "staging overlay source literal");
    require_staging_literal(row.effective_literal,
                            "staging overlay effective literal");
    if (row.rank_index >= rank_count ||
        (ordinal && row.rank_index <= previous_overlay) ||
        row.source_literal != -row.effective_literal ||
        plan.source_rank_literals[row.rank_index] != row.source_literal)
      throw std::runtime_error("staging overlay row differs");
    previous_overlay = row.rank_index;
    plan.overlays.push_back(row);
  }
  if (cursor != body.size())
    throw std::runtime_error("staging plan trailing bytes differ");

  std::vector<int> effective = plan.source_rank_literals;
  std::set<uint32_t> overlay_indices;
  for (const StagingOverlay &overlay : plan.overlays) {
    overlay_indices.insert(overlay.rank_index);
    effective[overlay.rank_index] = overlay.effective_literal;
  }
  for (const StagingIntersection &intersection : plan.intersections) {
    const bool overlaid = overlay_indices.count(intersection.rank_index);
    if (intersection.effective_literal !=
        (overlaid ? -intersection.source_literal
                  : intersection.source_literal))
      throw std::runtime_error("staging intersection overlay differs");
  }
  if (sha256(rank_order_bytes(effective)) !=
      plan.effective_rank_order_sha256)
    throw std::runtime_error("staging effective rank order differs");
  return plan;
}

bool same_intersection(const StagingIntersection &row, uint32_t rank_index,
                       int clause_literal, int source_literal,
                       int effective_literal) {
  return row.rank_index == rank_index &&
         row.clause_literal == clause_literal &&
         row.source_literal == source_literal &&
         row.effective_literal == effective_literal;
}

bool same_overlay(const StagingOverlay &row, uint32_t rank_index,
                  int source_literal, int effective_literal) {
  return row.rank_index == rank_index && row.source_literal == source_literal &&
         row.effective_literal == effective_literal;
}

void validate_production_staging_plan(const StagingPlan &plan,
                                      bool production_seal) {
  if (!production_seal)
    return;
  if (plan.source_result_sha256 != kProductionSourceResultSha256 ||
      plan.source_assignment_sha256 != kProductionSourceAssignmentSha256 ||
      plan.active_vault_sha256 != kProductionActiveVaultSha256 ||
      plan.parent_frontier_plan_sha256 !=
          kProductionParentFrontierPlanSha256 ||
      plan.selected_active_index != kProductionSelectedActiveIndex ||
      plan.selected_union_index != kProductionSelectedUnionIndex ||
      plan.selected_clause_sha256 != kProductionSelectedClauseSha256 ||
      plan.selected_clause_literal_count !=
          kProductionSelectedClauseLiteralCount ||
      plan.source_rank_payload_sha256 !=
          kProductionSourceRankPayloadSha256 ||
      plan.source_rank_order_sha256 != kProductionSourceRankOrderSha256 ||
      plan.effective_rank_order_sha256 !=
          kProductionEffectiveRankOrderSha256 ||
      plan.intersections.size() != kStagingIntersectionRows ||
      !same_intersection(plan.intersections[0], 28U, 105, -105, -105) ||
      !same_intersection(plan.intersections[1], 131U, -106, 106, 106) ||
      !same_intersection(plan.intersections[2], 224U, 131, 131, -131) ||
      !same_intersection(plan.intersections[3], 226U, -130, -130, 130) ||
      !same_intersection(plan.intersections[4], 235U, -129, 129, 129) ||
      plan.overlays.size() != kStagingOverlayRows ||
      !same_overlay(plan.overlays[0], 224U, 131, -131) ||
      !same_overlay(plan.overlays[1], 226U, -130, 130))
    throw std::runtime_error("sealed O1C77 staging plan differs");
}

std::vector<int> observed_from_field(const PotentialField &field) {
  std::vector<int> observed;
  for (const PotentialFactor &factor : field.factors)
    observed.insert(observed.end(), factor.variables.begin(),
                    factor.variables.end());
  std::sort(observed.begin(), observed.end());
  observed.erase(std::unique(observed.begin(), observed.end()), observed.end());
  if (observed.empty())
    throw std::runtime_error("staging potential observes no variables");
  return observed;
}

size_t observed_local(const std::vector<int> &observed, int variable,
                      const char *field) {
  const auto iterator =
      std::lower_bound(observed.begin(), observed.end(), variable);
  if (iterator == observed.end() || *iterator != variable)
    throw std::runtime_error(std::string(field) + " is unobserved");
  return static_cast<size_t>(iterator - observed.begin());
}

void validate_and_apply_staging(
    StagingPlan &plan, RankTable &rank, const FrontierPlan &frontier_plan,
    const ScoreThresholdVault &active_vault,
    const std::vector<int> &observed, const std::string &parent_plan_sha256,
    bool production_seal) {
  validate_production_staging_plan(plan, production_seal);
  if (plan.active_vault_sha256 != active_vault.input_sha256 ||
      frontier_plan.active_vault_sha256 != active_vault.input_sha256 ||
      plan.parent_frontier_plan_sha256 != parent_plan_sha256 ||
      plan.parent_frontier_plan_sha256 != frontier_plan.payload_sha256 ||
      plan.source_result_sha256 != frontier_plan.source_result_sha256 ||
      plan.source_assignment_sha256 !=
          frontier_plan.source_assignment_sha256 ||
      plan.source_assignment != frontier_plan.prior_assignment ||
      plan.selected_active_index != frontier_plan.selected_active_index ||
      plan.selected_union_index != frontier_plan.selected_union_index ||
      plan.selected_clause_sha256 != frontier_plan.selected_clause_sha256 ||
      plan.selected_clause_literal_count !=
          frontier_plan.selected_clause_literal_count ||
      plan.selected_active_index >= active_vault.clauses.size())
    throw std::runtime_error("staging parent frontier binding differs");
  const std::vector<int> &clause =
      active_vault.clauses.at(plan.selected_active_index);
  if (clause.size() != plan.selected_clause_literal_count ||
      sha256(canonical_clause_bytes(clause)) != plan.selected_clause_sha256 ||
      plan.source_assignment.size() != observed.size())
    throw std::runtime_error("staging selected clause binding differs");
  if (rank.payload_sha256 != plan.source_rank_payload_sha256 ||
      rank.order_sha256 != plan.source_rank_order_sha256 ||
      rank.rows.size() != plan.source_rank_literals.size() ||
      rank.literals != plan.source_rank_literals)
    throw std::runtime_error("staging immutable source rank differs");

  std::map<int, int> residual_clause_by_variable;
  for (const int literal : clause) {
    const size_t local =
        observed_local(observed, std::abs(literal), "staging clause variable");
    if (!plan.source_assignment.at(local))
      residual_clause_by_variable.emplace(std::abs(literal), literal);
  }
  std::vector<StagingIntersection> expected_intersections;
  for (size_t index = 0; index < rank.rows.size(); ++index) {
    const RankRow &row = rank.rows[index];
    const auto clause_iterator =
        residual_clause_by_variable.find(row.variable);
    if (clause_iterator == residual_clause_by_variable.end())
      continue;
    int effective_literal = row.literal;
    for (const StagingOverlay &overlay : plan.overlays)
      if (overlay.rank_index == index)
        effective_literal = overlay.effective_literal;
    expected_intersections.push_back(
        {static_cast<uint32_t>(index), clause_iterator->second, row.literal,
         effective_literal});
  }
  if (expected_intersections.size() != plan.intersections.size())
    throw std::runtime_error("staging residual rank intersection differs");
  for (size_t index = 0; index < expected_intersections.size(); ++index) {
    const StagingIntersection &expected = expected_intersections[index];
    const StagingIntersection &actual = plan.intersections[index];
    if (!same_intersection(actual, expected.rank_index,
                           expected.clause_literal, expected.source_literal,
                           expected.effective_literal))
      throw std::runtime_error("staging residual rank intersection differs");
  }

  // This is the complete mutation surface: ranking evidence, payload, row
  // order, variables, deltas, bounds, and gaps stay byte-for-byte untouched.
  for (const StagingOverlay &overlay : plan.overlays) {
    RankRow &row = rank.rows.at(overlay.rank_index);
    if (row.literal != overlay.source_literal ||
        rank.literals.at(overlay.rank_index) != overlay.source_literal)
      throw std::runtime_error("staging overlay source row differs");
    row.literal = overlay.effective_literal;
    rank.literals.at(overlay.rank_index) = overlay.effective_literal;
  }
  rank.order_bytes = rank_order_bytes(rank.literals);
  rank.order_sha256 = sha256(rank.order_bytes);
  if (rank.order_sha256 != plan.effective_rank_order_sha256 ||
      rank.payload_sha256 != plan.source_rank_payload_sha256)
    throw std::runtime_error("staging effective rank projection differs");
}

struct StagingTrailEntry {
  size_t local = 0;
  size_t level = 0;
};

struct StagingCallbackRecord {
  uint64_t call = 0;
  int returned_literal = 0;
  uint64_t assignment_burst = 0;
  uint8_t completion = 0;
};

struct StagingOverlayEvent {
  uint64_t call = 0;
  size_t overlay_index = 0;
  uint32_t rank_index = 0;
  int source_literal = 0;
  int effective_literal = 0;
  int returned_literal = 0;
  bool effective_original = false;
};

class StagingDiscardingStreamBuffer final : public std::streambuf {
protected:
  std::streamsize xsputn(const char *, std::streamsize count) override {
    return count;
  }
  int_type overflow(int_type character) override {
    return traits_type::not_eof(character);
  }
};

class ResidualPolarityStagingGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  ResidualPolarityStagingGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold, RankTable rank,
      RankVoteField vote_field, std::string potential_source_sha256,
      FrontierPlan frontier_plan, StagingPlan staging_plan)
      : parent_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
                potential_sha256, threshold, RankTable(rank),
                std::move(vote_field), std::move(potential_source_sha256),
                std::move(frontier_plan)),
        plan_(std::move(staging_plan)), effective_rank_(std::move(rank)) {
    const std::vector<int> &observed = parent_.observed();
    assignment_.assign(observed.size(), 0);
    if (plan_.selected_active_index >= parent_.preloaded_clauses().size() ||
        plan_.source_assignment.size() != observed.size())
      throw std::runtime_error("staging runtime population differs");
    selected_clause_ =
        parent_.preloaded_clauses().at(plan_.selected_active_index);
    selected_clause_locals_.reserve(selected_clause_.size());
    for (const int literal : selected_clause_)
      selected_clause_locals_.push_back(local(std::abs(literal)));
    rank_locals_.reserve(effective_rank_.rows.size());
    for (const RankRow &row : effective_rank_.rows)
      rank_locals_.push_back(local(row.variable));
    rank_original_returned_.assign(effective_rank_.rows.size(), false);
    rank_original_released_.assign(effective_rank_.rows.size(), false);
    rank_contrast_returned_.assign(effective_rank_.rows.size(), false);
    rank_contrast_released_.assign(effective_rank_.rows.size(), false);
    update_live_counts();
  }

  void notify_assignment(const std::vector<int> &literals) override {
    parent_.notify_assignment(literals);
    for (const int literal : literals) {
      const size_t index = local(std::abs(literal));
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assignment_.at(index);
      if (!slot) {
        slot = value;
        trail_.push_back({index, current_level_});
        if (assignment_literals_since_callback_ ==
                std::numeric_limits<uint64_t>::max() ||
            assignment_literals_observed_ ==
                std::numeric_limits<uint64_t>::max())
          throw std::runtime_error("staging assignment count exceeds bound");
        ++assignment_literals_since_callback_;
        ++assignment_literals_observed_;
      } else if (slot != value) {
        throw std::runtime_error(
            "staging assignment changed without backtrack");
      }
    }
    update_live_counts();
  }

  void notify_new_decision_level() override {
    parent_.notify_new_decision_level();
    if (current_level_ == std::numeric_limits<size_t>::max())
      throw std::runtime_error("staging decision level exceeds bound");
    ++current_level_;
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_)
      throw std::runtime_error("staging backtrack level differs");
    const std::vector<int8_t> before = assignment_;
    parent_.notify_backtrack(new_level);
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t index = trail_.back().local;
      if (!assignment_.at(index))
        throw std::runtime_error("staging trail state differs");
      assignment_[index] = 0;
      trail_.pop_back();
    }
    current_level_ = new_level;
    for (size_t index = 0; index < effective_rank_.rows.size(); ++index) {
      const int8_t prior = before.at(rank_locals_.at(index));
      const int8_t after = assignment_.at(rank_locals_.at(index));
      const RankRow &row = effective_rank_.rows[index];
      const int prior_literal =
          prior > 0 ? row.variable : (prior < 0 ? -row.variable : 0);
      if (rank_original_returned_[index] &&
          !rank_original_released_[index] && prior && !after) {
        if (prior_literal != row.literal)
          throw std::runtime_error(
              "staging embedded v12 original release sign differs");
        rank_original_released_[index] = true;
        rank_release_order_.push_back(static_cast<uint32_t>(index));
      }
      if (rank_contrast_returned_[index] &&
          !rank_contrast_released_[index] && prior && !after) {
        if (prior_literal != -row.literal)
          throw std::runtime_error(
              "staging embedded v12 contrast release sign differs");
        rank_contrast_released_[index] = true;
      }
    }
    update_live_counts();
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return parent_.cb_check_found_model(model);
  }

  int cb_decide() override {
    if (solve_finalized_)
      throw std::runtime_error("staging callback occurred after solve end");
    finalize_prior_callback(1U);
    if (callback_records_.empty()) {
      assignments_before_first_callback_ = assignment_literals_since_callback_;
      assignment_literals_since_callback_ = 0;
    }
    if (callback_records_.size() >= kMaximumCallbackRecords)
      throw std::runtime_error("staging callback record cap exceeded");

    size_t expected_rank_index = effective_rank_.rows.size();
    int expected_original = 0;
    while (source_rank_cursor_ < effective_rank_.rows.size()) {
      const size_t index = source_rank_cursor_++;
      if (assignment_.at(rank_locals_.at(index)))
        continue;
      expected_rank_index = index;
      expected_original = effective_rank_.rows[index].literal;
      break;
    }
    size_t expected_contrast_index = effective_rank_.rows.size();
    int expected_contrast = 0;
    if (!expected_original) {
      for (const uint32_t encoded_index : rank_release_order_) {
        const size_t index = encoded_index;
        if (index >= effective_rank_.rows.size() ||
            rank_contrast_returned_[index] ||
            assignment_.at(rank_locals_.at(index)))
          continue;
        expected_contrast_index = index;
        expected_contrast = -effective_rank_.rows[index].literal;
        break;
      }
    }
    const int result = parent_.cb_decide();
    const uint64_t call = callback_records_.size() + 1U;
    callback_records_.push_back({call, result, 0U, 0U});
    staging_append_i32(returned_sequence_, result);
    if (result)
      ++nonzero_returns_;
    else
      ++zero_returns_;

    if (expected_original && result != expected_original)
      throw std::runtime_error("staging embedded v14 original return differs");
    if (expected_contrast && result != expected_contrast)
      throw std::runtime_error("staging embedded v14 contrast return differs");
    if (expected_original) {
      rank_original_returned_.at(expected_rank_index) = true;
      for (size_t overlay_index = 0; overlay_index < plan_.overlays.size();
           ++overlay_index) {
        const StagingOverlay &overlay = plan_.overlays[overlay_index];
        if (overlay.rank_index != expected_rank_index)
          continue;
        if (result != overlay.effective_literal)
          throw std::runtime_error("staging overlaid return sign differs");
        set_overlay_bit(effective_returned_state_, overlay_index);
        ++overlay_effective_returns_;
        overlay_events_.push_back(
            {call, overlay_index, overlay.rank_index, overlay.source_literal,
             overlay.effective_literal, result, true});
        if (!first_activation_call_) {
          first_activation_call_ = call;
          mechanism_activated_ = true;
          initialize_post_activation_minima();
        }
      }
    } else if (expected_contrast) {
      rank_contrast_returned_.at(expected_contrast_index) = true;
      for (size_t overlay_index = 0; overlay_index < plan_.overlays.size();
           ++overlay_index) {
        const StagingOverlay &overlay = plan_.overlays[overlay_index];
        if (overlay.rank_index != expected_contrast_index ||
            result != overlay.source_literal ||
            overlay_bit(contrast_observed_state_, overlay_index))
          continue;
        set_overlay_bit(contrast_observed_state_, overlay_index);
        ++overlay_contrast_returns_;
        overlay_events_.push_back(
            {call, overlay_index, overlay.rank_index, overlay.source_literal,
             overlay.effective_literal, result, false});
      }
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

  void finalize_after_solve() {
    if (solve_finalized_)
      throw std::runtime_error("staging solve end finalized twice");
    finalize_prior_callback(2U);
    if (callback_records_.empty())
      assignments_before_first_callback_ = assignment_literals_since_callback_;
    assignment_literals_since_callback_ = 0;
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
    validate_telemetry();
    out << "\"schema\":\"" << kStagingSchema << "\",\"operator\":\""
        << kStagingOperator << "\",\"plan_sha256\":\""
        << plan_.payload_sha256 << "\",\"source_result_sha256\":\""
        << plan_.source_result_sha256
        << "\",\"source_assignment_sha256\":\""
        << plan_.source_assignment_sha256
        << "\",\"active_vault_sha256\":\""
        << plan_.active_vault_sha256
        << "\",\"parent_frontier_plan_sha256\":\""
        << plan_.parent_frontier_plan_sha256
        << "\",\"selected_active_index\":"
        << plan_.selected_active_index << ",\"selected_union_index\":"
        << plan_.selected_union_index
        << ",\"selected_clause_sha256\":\""
        << plan_.selected_clause_sha256
        << "\",\"selected_clause_literal_count\":"
        << plan_.selected_clause_literal_count
        << ",\"source_rank_payload_sha256\":\""
        << plan_.source_rank_payload_sha256
        << "\",\"source_rank_order_sha256\":\""
        << plan_.source_rank_order_sha256
        << "\",\"effective_rank_order_sha256\":\""
        << plan_.effective_rank_order_sha256
        << "\",\"reader_rank_role\":\"" << kReaderRankRole
        << "\",\"decision_rule\":\"" << kStagingDecisionRule
        << "\",\"callback_rule\":\"" << kStagingCallbackRule
        << "\",\"intersections\":[";
    for (size_t index = 0; index < plan_.intersections.size(); ++index) {
      if (index)
        out << ',';
      const StagingIntersection &row = plan_.intersections[index];
      out << "{\"rank_index\":" << row.rank_index
          << ",\"clause_literal\":" << row.clause_literal
          << ",\"source_literal\":" << row.source_literal
          << ",\"effective_literal\":" << row.effective_literal << '}';
    }
    out << "],\"overlays\":[";
    for (size_t index = 0; index < plan_.overlays.size(); ++index) {
      if (index)
        out << ',';
      const StagingOverlay &row = plan_.overlays[index];
      out << "{\"rank_index\":" << row.rank_index
          << ",\"source_literal\":" << row.source_literal
          << ",\"effective_literal\":" << row.effective_literal << '}';
    }
    out << "],\"mechanism_activated\":"
        << (mechanism_activated_ ? "true" : "false")
        << ",\"first_activation_call\":";
    write_nullable_u64(out, first_activation_call_);
    out << ",\"overlay_effective_returns\":"
        << overlay_effective_returns_
        << ",\"overlay_contrast_returns\":"
        << overlay_contrast_returns_ << ",\"unit_activation\":"
        << (unit_activation_ ? "true" : "false")
        << ",\"source_rank_cursor\":" << source_rank_cursor_
        << ",\"cb_decide_calls\":" << callback_records_.size()
        << ",\"nonzero_returns\":" << nonzero_returns_
        << ",\"zero_returns\":" << zero_returns_
        << ",\"assignments_before_first_callback\":"
        << assignments_before_first_callback_
        << ",\"assignment_literals_observed\":"
        << assignment_literals_observed_
        << ",\"live_false_literal_count\":" << live_false_literal_count_
        << ",\"live_true_literal_count\":" << live_true_literal_count_
        << ",\"live_unassigned_literal_count\":"
        << live_unassigned_literal_count_
        << ",\"post_activation_minimum_false_literal_count\":";
    write_nullable_size(out, mechanism_activated_,
                        post_activation_minimum_false_literal_count_);
    out << ",\"post_activation_minimum_true_literal_count\":";
    write_nullable_size(out, mechanism_activated_,
                        post_activation_minimum_true_literal_count_);
    out << ",\"post_activation_minimum_unassigned_literal_count\":";
    write_nullable_size(out, mechanism_activated_,
                        post_activation_minimum_unassigned_literal_count_);
    write_overlay_state(out, "effective_returned_state",
                        effective_returned_state_);
    write_overlay_state(out, "contrast_observed_state",
                        contrast_observed_state_);
    out << ",\"returned_sequence_encoding\":\""
        << kStagingSequenceEncoding << "\",\"returned_sequence_count\":"
        << callback_records_.size() << ",\"returned_sequence_bytes\":"
        << returned_sequence_.size() << ",\"returned_sequence_hex\":\""
        << bytes_hex(returned_sequence_)
        << "\",\"returned_sequence_sha256\":\""
        << sha256(returned_sequence_) << "\",\"callback_trace_encoding\":\""
        << kStagingTraceEncoding << "\",\"callback_trace_count\":"
        << callback_records_.size() << ",\"callback_trace_bytes\":"
        << callback_trace_.size() << ",\"callback_trace_hex\":\""
        << bytes_hex(callback_trace_)
        << "\",\"callback_trace_sha256\":\""
        << sha256(callback_trace_) << "\",\"callback_records\":[";
    for (size_t index = 0; index < callback_records_.size(); ++index) {
      if (index)
        out << ',';
      const StagingCallbackRecord &record = callback_records_[index];
      out << "{\"call\":" << record.call
          << ",\"returned_literal\":" << record.returned_literal
          << ",\"assignment_burst_after_callback\":"
          << record.assignment_burst << ",\"completion\":\""
          << (record.completion == 1U ? "next-callback" : "solve-end")
          << "\"}";
    }
    out << "],\"overlay_return_events\":[";
    for (size_t index = 0; index < overlay_events_.size(); ++index) {
      if (index)
        out << ',';
      const StagingOverlayEvent &event = overlay_events_[index];
      out << "{\"call\":" << event.call
          << ",\"rank_index\":" << event.rank_index
          << ",\"source_literal\":" << event.source_literal
          << ",\"effective_literal\":" << event.effective_literal
          << ",\"returned_literal\":" << event.returned_literal
          << ",\"kind\":\""
          << (event.effective_original ? "effective-original"
                                       : "source-contrast")
          << "\"}";
    }
    out << "],\"bounded_state_rule\":\"" << kStagingBoundedStateRule
        << "\",\"bounded_guidance_state_bytes\":"
        << bounded_guidance_state_bytes()
        << ",\"live_guidance_state_bytes\":"
        << live_guidance_state_bytes()
        << ",\"bounded_telemetry_state_bytes\":"
        << bounded_telemetry_state_bytes();
  }

private:
  size_t local(int variable) const {
    const std::vector<int> &values = parent_.observed();
    const auto iterator =
        std::lower_bound(values.begin(), values.end(), variable);
    if (iterator == values.end() || *iterator != variable)
      throw std::runtime_error("staging variable is unobserved");
    return static_cast<size_t>(iterator - values.begin());
  }

  static bool literal_true(int literal, int8_t sign) {
    return sign && ((literal > 0) == (sign > 0));
  }

  void update_live_counts() {
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
    if (mechanism_activated_) {
      post_activation_minimum_false_literal_count_ =
          std::min(post_activation_minimum_false_literal_count_, false_count);
      post_activation_minimum_true_literal_count_ =
          std::min(post_activation_minimum_true_literal_count_, true_count);
      post_activation_minimum_unassigned_literal_count_ =
          std::min(post_activation_minimum_unassigned_literal_count_,
                   unassigned_count);
      if (!true_count && unassigned_count <= 1U)
        unit_activation_ = true;
    }
  }

  void initialize_post_activation_minima() {
    post_activation_minimum_false_literal_count_ =
        live_false_literal_count_;
    post_activation_minimum_true_literal_count_ = live_true_literal_count_;
    post_activation_minimum_unassigned_literal_count_ =
        live_unassigned_literal_count_;
    if (!live_true_literal_count_ && live_unassigned_literal_count_ <= 1U)
      unit_activation_ = true;
  }

  static bool overlay_bit(const std::string &state, size_t index) {
    if (state.size() != 1U || index >= kStagingOverlayRows)
      throw std::runtime_error("staging overlay state index differs");
    return (static_cast<unsigned char>(state[0]) >> index) & 1U;
  }

  static void set_overlay_bit(std::string &state, size_t index) {
    if (overlay_bit(state, index))
      throw std::runtime_error("staging overlay state bit repeats");
    state[0] = static_cast<char>(static_cast<unsigned char>(state[0]) |
                                 (1U << index));
  }

  static size_t count_overlay_bits(const std::string &state) {
    size_t count = 0;
    for (size_t index = 0; index < kStagingOverlayRows; ++index)
      if (overlay_bit(state, index))
        ++count;
    return count;
  }

  void finalize_prior_callback(uint8_t completion) {
    if (callback_records_.empty())
      return;
    StagingCallbackRecord &record = callback_records_.back();
    if (record.completion)
      return;
    record.assignment_burst = assignment_literals_since_callback_;
    record.completion = completion;
    staging_append_u64(callback_trace_, record.call);
    staging_append_i32(callback_trace_, record.returned_literal);
    staging_append_u64(callback_trace_, record.assignment_burst);
    callback_trace_.push_back(static_cast<char>(record.completion));
    assignment_literals_since_callback_ = 0;
  }

  static void write_nullable_u64(std::ostream &out, uint64_t value) {
    if (value)
      out << value;
    else
      out << "null";
  }

  static void write_nullable_size(std::ostream &out, bool present,
                                  size_t value) {
    if (present)
      out << value;
    else
      out << "null";
  }

  static void write_overlay_state(std::ostream &out, const char *prefix,
                                  const std::string &state) {
    out << ",\"" << prefix << "_bits\":" << kStagingOverlayRows
        << ",\"" << prefix << "_bytes\":" << state.size() << ",\""
        << prefix << "_encoding\":\"" << kStagingStateEncoding << "\",\""
        << prefix << "_hex\":\"" << bytes_hex(state) << "\",\""
        << prefix << "_sha256\":\"" << sha256(state) << '"';
  }

  size_t bounded_guidance_state_bytes() const {
    return 4U + assignment_.size() + 8U * assignment_.size() +
           4U * effective_rank_.rows.size() + 2U;
  }

  size_t live_guidance_state_bytes() const {
    return 4U + assignment_.size() + 8U * trail_.size() +
           4U * effective_rank_.rows.size() + 2U;
  }

  size_t bounded_telemetry_state_bytes() const {
    return bounded_guidance_state_bytes() +
           kMaximumCallbackRecords * sizeof(StagingCallbackRecord) +
           4U * sizeof(StagingOverlayEvent) +
           25U * kMaximumCallbackRecords;
  }

  void validate_telemetry() const {
    StagingDiscardingStreamBuffer parent_buffer;
    std::ostream parent_sink(&parent_buffer);
    parent_.write_reader_json(parent_sink);
    parent_.write_frontier_json(parent_sink);
    if (!parent_sink || !solve_finalized_ ||
        callback_records_.size() != nonzero_returns_ + zero_returns_ ||
        returned_sequence_.size() != 4U * callback_records_.size() ||
        callback_trace_.size() != 21U * callback_records_.size() ||
        source_rank_cursor_ > effective_rank_.rows.size() ||
        overlay_effective_returns_ !=
            count_overlay_bits(effective_returned_state_) ||
        overlay_contrast_returns_ !=
            count_overlay_bits(contrast_observed_state_) ||
        mechanism_activated_ != static_cast<bool>(overlay_effective_returns_) ||
        mechanism_activated_ != static_cast<bool>(first_activation_call_) ||
        overlay_events_.size() !=
            overlay_effective_returns_ + overlay_contrast_returns_ ||
        live_false_literal_count_ + live_true_literal_count_ +
                live_unassigned_literal_count_ !=
            selected_clause_.size())
      throw std::runtime_error("staging telemetry differs");
    uint64_t burst_sum = assignments_before_first_callback_;
    std::string expected_returns;
    std::string expected_trace;
    for (size_t index = 0; index < callback_records_.size(); ++index) {
      const StagingCallbackRecord &record = callback_records_[index];
      const uint8_t expected_completion =
          index + 1U == callback_records_.size() ? 2U : 1U;
      if (record.call != index + 1U ||
          record.completion != expected_completion)
        throw std::runtime_error("staging callback chronology differs");
      burst_sum += record.assignment_burst;
      staging_append_i32(expected_returns, record.returned_literal);
      staging_append_u64(expected_trace, record.call);
      staging_append_i32(expected_trace, record.returned_literal);
      staging_append_u64(expected_trace, record.assignment_burst);
      expected_trace.push_back(static_cast<char>(record.completion));
    }
    if (expected_returns != returned_sequence_ ||
        expected_trace != callback_trace_ ||
        burst_sum != assignment_literals_observed_)
      throw std::runtime_error("staging callback trace differs");
    uint64_t prior_call = 0;
    for (const StagingOverlayEvent &event : overlay_events_) {
      if (!event.call || event.call > callback_records_.size() ||
          event.call <= prior_call || event.overlay_index >= plan_.overlays.size())
        throw std::runtime_error("staging overlay event chronology differs");
      prior_call = event.call;
      const StagingOverlay &overlay = plan_.overlays[event.overlay_index];
      if (event.rank_index != overlay.rank_index ||
          event.source_literal != overlay.source_literal ||
          event.effective_literal != overlay.effective_literal ||
          event.returned_literal !=
              (event.effective_original ? overlay.effective_literal
                                        : overlay.source_literal) ||
          callback_records_[event.call - 1U].returned_literal !=
              event.returned_literal)
        throw std::runtime_error("staging overlay event payload differs");
    }
    if (first_activation_call_ &&
        (first_activation_call_ > callback_records_.size() ||
         callback_records_[first_activation_call_ - 1U].returned_literal == 0))
      throw std::runtime_error("staging first activation differs");
  }

  CausalFrontierGroupedJointScoreSieve parent_;
  StagingPlan plan_;
  RankTable effective_rank_;
  std::vector<int8_t> assignment_;
  std::vector<StagingTrailEntry> trail_;
  size_t current_level_ = 0;
  std::vector<int> selected_clause_;
  std::vector<size_t> selected_clause_locals_;
  std::vector<size_t> rank_locals_;
  std::vector<bool> rank_original_returned_;
  std::vector<bool> rank_original_released_;
  std::vector<bool> rank_contrast_returned_;
  std::vector<bool> rank_contrast_released_;
  std::vector<uint32_t> rank_release_order_;
  size_t source_rank_cursor_ = 0;
  uint64_t assignments_before_first_callback_ = 0;
  uint64_t assignment_literals_since_callback_ = 0;
  uint64_t assignment_literals_observed_ = 0;
  size_t nonzero_returns_ = 0;
  size_t zero_returns_ = 0;
  size_t overlay_effective_returns_ = 0;
  size_t overlay_contrast_returns_ = 0;
  bool mechanism_activated_ = false;
  uint64_t first_activation_call_ = 0;
  bool unit_activation_ = false;
  bool solve_finalized_ = false;
  size_t live_false_literal_count_ = 0;
  size_t live_true_literal_count_ = 0;
  size_t live_unassigned_literal_count_ = 0;
  size_t post_activation_minimum_false_literal_count_ =
      std::numeric_limits<size_t>::max();
  size_t post_activation_minimum_true_literal_count_ =
      std::numeric_limits<size_t>::max();
  size_t post_activation_minimum_unassigned_literal_count_ =
      std::numeric_limits<size_t>::max();
  std::string effective_returned_state_ = std::string(1U, '\0');
  std::string contrast_observed_state_ = std::string(1U, '\0');
  std::string returned_sequence_;
  std::string callback_trace_;
  std::vector<StagingCallbackRecord> callback_records_;
  std::vector<StagingOverlayEvent> overlay_events_;
};

struct StagingArguments {
  FrontierArguments frontier;
  std::string staging_plan_path;
};

StagingArguments parse_staging_arguments(int argc, char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string staging_plan_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("staging arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--staging-plan") {
      if (!staging_plan_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("staging-plan argument differs");
      staging_plan_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (staging_plan_path.empty())
    throw std::runtime_error("staging-plan argument is missing");
  return {parse_frontier_arguments(static_cast<int>(filtered.size()),
                                   filtered.data()),
          std::move(staging_plan_path)};
}

void print_v15_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v15 --cnf PATH "
               "--potential PATH --grouping PATH --rank-vault PATH "
               "--vault-in PATH --rank-table PATH --frontier-plan PATH "
               "--staging-plan PATH --threshold FLOAT --conflict-limit N "
               "[--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v15_usage();
      return 0;
    }
    const StagingArguments staging_arguments =
        parse_staging_arguments(argc, argv);
    const FrontierArguments &frontier_arguments = staging_arguments.frontier;
    const SplitRankedArguments &split_arguments = frontier_arguments.split;
    const RankedArguments &ranked_arguments = split_arguments.ranked;
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("residual-polarity staging requires seed zero");
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
    const std::string staging_plan_payload =
        read_bounded_staging_file(staging_arguments.staging_plan_path);
    StagingPlan staging_plan = parse_staging_plan(staging_plan_payload);
    const std::string rank_payload =
        read_binary_file(ranked_arguments.rank_table_path, "rank table");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);
    const std::string rank_source_vault_sha256 = sha256(rank_vault_payload);

#ifdef O1_CRYPTO_LAB_O1C77_PUBLIC_FIXTURE
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
    // The immutable table is completely parsed and production-sealed before
    // any staging field can influence it.
    RankTable rank = parse_rank_table(rank_payload, vote_field, production_seal);

    std::unique_ptr<ResidualPolarityStagingGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
          !solver.set("quiet", 1) || !solver.set("factor", 0) ||
          !solver.set("lucky", 0) || !solver.set("walk", 0) ||
          !solver.set("rephase", 0) || !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic residual-polarity options");
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
      validate_and_apply_staging(
          staging_plan, rank, frontier_plan, active_vault, observed,
          sha256(frontier_plan_payload), production_seal);

      propagator =
          std::make_unique<ResidualPolarityStagingGroupedJointScoreSieve>(
              std::move(field), grouping_payload, active_vault_payload,
              cnf_sha256, potential_sha256, arguments.threshold,
              std::move(rank), std::move(vote_field), potential_source_sha256,
              std::move(frontier_plan), std::move(staging_plan));
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
      std::ostringstream out;
      out << std::setprecision(std::numeric_limits<double>::max_digits10)
          << "{\"schema\":\"" << kV15ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV12ImplementationParentSchema
          << "\",\"implementation_release_parent_schema\":\""
          << kV15ReleaseParentSchema
          << "\",\"rank_source_vault_sha256\":\""
          << rank_source_vault_sha256
          << "\",\"frontier_plan_sha256\":\""
          << sha256(frontier_plan_payload)
          << "\",\"frontier_source_result_sha256\":\""
          << output_frontier.source_result_sha256
          << "\",\"staging_plan_sha256\":\""
          << sha256(staging_plan_payload)
          << "\",\"staging_source_result_sha256\":\""
          << output_staging.source_result_sha256
          << "\",\"reader_rank_role\":\"" << kReaderRankRole
          << "\",\"reader\":{";
      propagator->write_reader_json(out);
      out << "},\"frontier\":{";
      propagator->write_frontier_json(out);
      out << "},\"staging\":{";
      propagator->write_staging_json(out);
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
    std::cerr << "cadical_o1_joint_score_sieve_v15: " << error.what() << '\n';
    return 1;
  }
}
