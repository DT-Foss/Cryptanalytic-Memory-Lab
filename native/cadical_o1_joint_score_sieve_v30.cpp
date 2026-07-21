// O1C-0103 live-bank continuation parent-centered failure-first proof-mining operator.
//
// The frozen v18 translation unit supplies its exact one-bit reader builder and
// the unchanged v6 grouped score/vault implementation.  This wrapper owns only
// an exact assignment shadow, the fixed O(256) parent-centered state, a fixed
// one-shot coordinate mask, fixed action telemetry, and digest/counter probe
// telemetry.  BOUND_LOSING_CHILD remains the legacy ownership transport name;
// it is never used as the semantic name of a failure-first proof-mining action.

#ifdef O1_CRYPTO_LAB_O1C103_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C80_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C103_UNDEF_O1C80_FIXTURE
#endif
#define O1_CRYPTO_LAB_O1C80_NO_MAIN
#include "cadical_o1_joint_score_sieve_v18.cpp"
#undef O1_CRYPTO_LAB_O1C80_NO_MAIN
#ifdef O1_CRYPTO_LAB_O1C103_UNDEF_O1C80_FIXTURE
#undef O1_CRYPTO_LAB_O1C80_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C103_UNDEF_O1C80_FIXTURE
#endif

#include "o1c82_parent_centered_priority.hpp"
#include "o1c101_bounded_decision_ownership.hpp"

namespace {

constexpr const char *kV30ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v30";
constexpr const char *kV30ImplementationParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v6";
constexpr const char *kPriorityStateSchema =
    "o1-256-o1c103-live-parent-centered-continuation-priority-state-v1";
constexpr const char *kPriorityActionSchema =
    "o1-256-o1c103-failure-first-proof-mining-actions-v1";
constexpr const char *kLiveContinuationBankSha256 =
    "a8e137b1546076f32902acbb97163ae419ad45e61c4b311a3d8c9c941ba58f01";
constexpr const char *kLiveContinuationBankSource =
    "sealed-live-continuation-bank";
constexpr const char *kO1C102PreparationManifestSha256 =
    "9e3e2dd88c5688b88ff2f7673f161577f3b5cafc36bf2c060cc4388d5dfdaad0";
constexpr size_t kO1C102PreparationManifestBytes = 8012U;
constexpr const char *kO1C101PriorityStateReceiptSha256 =
    "30d25ec825241ab79fae1f704e698fe5d14b535bdb9121a3d6ce891bd3fb1f36";
constexpr size_t kO1C101PriorityStateReceiptBytes = 52013U;
constexpr const char *kO1C102DerivedResolutionReceiptSha256 =
    "3eade7d3e6e195b4b5aeac098969d85a93fae34ac1246f6868ddd6f7afdb345c";
constexpr size_t kO1C102DerivedResolutionReceiptBytes = 326232U;
constexpr size_t kProductionLineageOrdinal = 32U;
constexpr size_t kProductionActiveLimit = 248U;
constexpr size_t kProductionActiveClauseCount = 248U;
constexpr size_t kProductionActiveLiteralCount = 702343U;
constexpr size_t kGlobalNoveltyBaselineClauseCount = 2343U;
constexpr size_t kProductionClauseHeadroom = 264U;
constexpr const char *kProductionPage19ActiveVaultSha256 =
    "3857519d4a384333d576ec1fe11939ef2a46d82d9ce7c585bc989792c0ceb3e6";
constexpr size_t kProductionPage19ActiveVaultBytes = 2810555U;
constexpr const char *kBurnedPage18ActiveVaultSha256 =
    "5d89bbe07c8b988b4f1ce5dc2a31b860ab59192d3efc02854e27b8f779de417c";
constexpr size_t kBurnedPage18ActiveVaultBytes = 2680827U;
constexpr const char *kBurnedPage17ActiveVaultSha256 =
    "0c25ce470df0945fb05914bab107ecea05531166575ec88ebf7d15bb9a22fbfd";
constexpr size_t kBurnedPage17ActiveVaultBytes = 2773919U;
constexpr const char *kBurnedPage16ActiveVaultSha256 =
    "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5";
constexpr size_t kBurnedPage16ActiveVaultBytes = 2831459U;
constexpr const char *kBurnedPage15ActiveVaultSha256 =
    "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2";
constexpr size_t kBurnedPage15ActiveVaultBytes = 2843047U;
constexpr const char *kBurnedPage14ActiveVaultSha256 =
    "00a5a4a7b33f1c09c8df24162709b17994bad5825d92476a5f5283a3bf025c7e";
constexpr size_t kBurnedPage14ActiveVaultBytes = 2817779U;
constexpr const char *kBurnedPage13ActiveVaultSha256 =
    "4c1b7d5a6d40fad9439d95433bcc7a60ff3e7ddc0e4542b0cf003cdf4581e546";
constexpr size_t kBurnedPage13ActiveVaultBytes = 2846623U;
constexpr const char *kBurnedPage12ActiveVaultSha256 =
    "44205f81322d526c1cf7b7c96f28a3baf02b6b9bcb08a04f0bab2e66651fa660";
constexpr size_t kBurnedPage12ActiveVaultBytes = 2725423U;
constexpr const char *kBurnedPage11ActiveVaultSha256 =
    "9853f06bc882bfbb6312207bc8c20e0e9ca1500e49aad14594f6d7c66b62a04d";
constexpr size_t kBurnedPage11ActiveVaultBytes = 2876731U;
constexpr const char *kBurnedPage10ActiveVaultSha256 =
    "bf1fd3e3938bc4125e672ee94ee599e5f21881b4fc87e2bc81e8fc57fc4d3556";
constexpr size_t kBurnedPage10ActiveVaultBytes = 2874387U;
constexpr const char *kBurnedPage9ActiveVaultSha256 =
    "8c3b8cc33badd4aa23920caabc5ea3fc5006675d93805578b74b2b20788c8204";
constexpr size_t kBurnedPage9ActiveVaultBytes = 2885959U;
constexpr size_t kExpectedProductionCandidateCount = 255U;
constexpr size_t kMaximumPriorityActions = o1c82::kCoordinateCount;
constexpr size_t kProbeTraceRecordBytes = 57U;
constexpr const char *kTransportOriginName = "BOUND_LOSING_CHILD";
constexpr const char *kProofMiningSemantic = "FAILURE_FIRST_PROOF_MINING";
constexpr const char *kCertifiedCrossingSemantic =
    "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE";
constexpr const char *kProofMiningMachineAction =
    "FAILURE_FIRST_PROOF_MINING";
constexpr const char *kCertifiedCrossingMachineAction =
    "CERTIFIED_STRICT_BOUND_CROSSING";
constexpr const char *kCandidateOrderRule =
    "observed-key-variables-ascending;currently-unassigned-and-no-live-token";
constexpr const char *kActionOrderRule =
    "certified-strict-U-less-than-tau-crossing-first;otherwise-highest-"
    "persistent-priority-unconsumed-current-coordinate";
constexpr const char *kOneShotRule =
    "coordinate-consumed-on-first-return;release-does-not-rearm";

static_assert(std::string_view(kO1C102PreparationManifestSha256).size() == 64U);
static_assert(kO1C102PreparationManifestBytes == 8012U);
static_assert(std::string_view(kO1C101PriorityStateReceiptSha256).size() == 64U);
static_assert(kO1C101PriorityStateReceiptBytes == 52013U);
static_assert(
    std::string_view(kO1C102DerivedResolutionReceiptSha256).size() == 64U);
static_assert(kO1C102DerivedResolutionReceiptBytes == 326232U);
static_assert(kProductionLineageOrdinal == 32U);
static_assert(kProductionActiveLimit == kProductionActiveClauseCount);
static_assert(kProductionActiveLimit + kProductionClauseHeadroom ==
              kMaximumVaultClauses);
static_assert(kProductionActiveLimit + kProductionClauseHeadroom == 512U);
static_assert(kProductionActiveLimit == 248U);
static_assert(kProductionActiveLiteralCount == 702343U);
static_assert(kProductionClauseHeadroom == 264U);
static_assert(kGlobalNoveltyBaselineClauseCount == 2343U);

enum class PriorityActionSemantic : uint8_t {
  NONE = 0,
  FAILURE_FIRST_PROOF_MINING = 1,
  CERTIFIED_STRICT_BOUND_CROSSING = 2,
};

const char *semantic_name(PriorityActionSemantic semantic) {
  switch (semantic) {
  case PriorityActionSemantic::NONE:
    return "NONE";
  case PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING:
    return kProofMiningSemantic;
  case PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING:
    return kCertifiedCrossingSemantic;
  }
  throw std::runtime_error("O1C103 action semantic differs");
}

const char *machine_action_name(PriorityActionSemantic semantic) {
  switch (semantic) {
  case PriorityActionSemantic::NONE:
    return "NONE";
  case PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING:
    return kProofMiningMachineAction;
  case PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING:
    return kCertifiedCrossingMachineAction;
  }
  throw std::runtime_error("O1C103 machine action differs");
}

struct PriorityArguments {
  GroupedArguments grouped;
  std::string priority_seed_path;
};

[[maybe_unused]] PriorityArguments parse_priority_arguments(int argc,
                                                            char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string priority_seed_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--priority-seed") {
      if (!priority_seed_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("priority-seed argument differs");
      priority_seed_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (priority_seed_path.empty())
    throw std::runtime_error("required priority-seed argument is missing");
  return {parse_grouped_arguments(static_cast<int>(filtered.size()),
                                  filtered.data()),
          priority_seed_path};
}

struct PriorityTrailEntry {
  uint32_t local = 0;
  uint32_t level = 0;
};

struct PriorityActionEvent {
  uint64_t token = 0;
  uint64_t call = 0;
  uint64_t first_probe = 0;
  uint64_t parent_probe_count = 0;
  uint32_t coordinate = 0;
  uint32_t parent_level = 0;
  uint32_t bound_level = 0;
  int variable = 0;
  int literal = 0;
  double upper_zero = 0.0;
  double upper_one = 0.0;
  double lower_upper_bound = 0.0;
  double current_differential = 0.0;
  double priority = 0.0;
  uint64_t accumulated_count = 0;
  PriorityActionSemantic semantic = PriorityActionSemantic::NONE;
  bool confirmed = false;
  bool coincident_v6_pending = false;
  bool released = false;
  bool unobserved_release = false;
  std::array<char, 65> parent_assignment_sha256{};
};

struct CrossingCandidate {
  bool available = false;
  size_t coordinate = 0;
  int variable = 0;
  int literal = 0;
  o1c80::ChildUpperBounds bounds;
};

class ParentCenteredGroupedJointScoreSieve final
    : public CaDiCaL::ExternalPropagator,
      public CaDiCaL::Terminator {
public:
  ParentCenteredGroupedJointScoreSieve(
      PotentialField field, const std::string &grouping_payload,
      const std::string &vault_payload, const std::string &cnf_sha256,
      const std::string &potential_sha256, double threshold,
      const std::string &seed_payload, const std::string &seed_sha256,
      bool production_seal)
      : one_bit_reader_(build_one_bit_bound_reader(
            field, grouping_payload, potential_sha256)),
        base_(std::move(field), grouping_payload, vault_payload, cnf_sha256,
              potential_sha256, threshold),
        threshold_(threshold), seed_sha256_(seed_sha256),
        production_seal_(production_seal) {
    const std::vector<int> &observed = base_.observed();
    assignment_.assign(observed.size(), 0);
    trail_.reserve(observed.size());
    for (const int variable : observed)
      if (variable >= 1 &&
          variable <= static_cast<int>(o1c82::kCoordinateCount))
        candidates_.push_back(variable);
    if (candidates_.empty())
      throw std::runtime_error("O1C103 potential observes no key coordinate");
    if (production_seal_ &&
        (candidates_.size() != kExpectedProductionCandidateCount ||
         std::binary_search(candidates_.begin(), candidates_.end(), 241)))
      throw std::runtime_error("sealed O1C103 key-coordinate population differs");
    for (const int variable : candidates_)
      append_u32_le(candidate_order_payload_,
                    static_cast<uint32_t>(variable));

    if (seed_payload.size() != o1c82::kCoordinateBankBytes)
      throw std::runtime_error("O1C103 priority seed byte count differs");
    if (seed_sha256_ != sha256(seed_payload))
      throw std::runtime_error("O1C103 priority seed payload digest differs");
    if (production_seal_ && seed_sha256_ != kLiveContinuationBankSha256)
      throw std::runtime_error("sealed O1C103 priority seed differs");
    o1c82::SeedImage image;
    image.magic = std::string(o1c82::kSeedMagic);
    image.schema = std::string(o1c82::kSeedSchema);
    image.payload_sha256 = seed_sha256_;
    std::transform(seed_payload.begin(), seed_payload.end(),
                   image.records.begin(), [](char value) {
                     return static_cast<uint8_t>(
                         static_cast<unsigned char>(value));
                   });
    priority_.import_seed(image);
    if (priority_.export_seed().records != image.records ||
        priority_.export_seed().payload_sha256 != seed_sha256_)
      throw std::runtime_error("O1C103 priority seed import round trip differs");
    initial_eligible_coordinate_count_ = priority_.eligible_coordinate_count();
    if (production_seal_ && initial_eligible_coordinate_count_ !=
                                kExpectedProductionCandidateCount)
      throw std::runtime_error(
          "sealed O1C103 live-bank eligibility population differs");
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
            "O1C103 shadow assignment changed without backtrack");
      }
      ownership_.notify_assignment(literal);
      observe_action_assignment(literal);
    }
    require_shadow_identity();
  }

  void notify_new_decision_level() override {
    if (current_level_ == std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("O1C103 decision level exceeds bound");
    base_.notify_new_decision_level();
    ++current_level_;
    ownership_.notify_new_decision_level(current_level_);
    if (pending_action_index_ != no_action()) {
      PriorityActionEvent &action = actions_.at(pending_action_index_);
      if (action.bound_level)
        throw std::runtime_error("O1C103 action bound twice");
      action.bound_level = current_level_;
      pending_action_index_ = no_action();
      ++level_bindings_;
    }
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_ ||
        new_level > std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("O1C103 backtrack level differs");
    base_.notify_backtrack(new_level);
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t index = trail_.back().local;
      if (!assignment_.at(index))
        throw std::runtime_error("O1C103 shadow trail state differs");
      assignment_[index] = 0;
      trail_.pop_back();
    }
    const std::vector<o1c101::DecisionToken> released =
        ownership_.notify_backtrack(static_cast<uint32_t>(new_level));
    for (const o1c101::DecisionToken &token : released)
      apply_release(token);
    current_level_ = static_cast<uint32_t>(new_level);
    require_shadow_identity();
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    return base_.cb_check_found_model(model);
  }

  int cb_decide() override {
    if (solve_finalized_)
      throw std::runtime_error("O1C103 callback after solve end");
    if (ownership_.has_pending())
      throw std::runtime_error("O1C103 callback overlaps pending proposal");
    if (base_.cb_decide() != 0)
      throw std::runtime_error("O1C103 unchanged v6 callback differs");
    const uint64_t call = ++callback_calls_;
    const int result = scan_and_select(call);
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
      throw std::runtime_error("O1C103 solve end finalized twice");
    ownership_.validate_solve_end();
    solve_finalized_ = true;
  }

  size_t action_count() const { return action_count_; }
  const PriorityActionEvent &action(size_t index) const {
    if (index >= action_count_)
      throw std::runtime_error("O1C103 action index differs");
    return actions_[index];
  }
  const o1c82::SelectionResult &last_priority_selection() const {
    return last_priority_selection_;
  }
  uint64_t probe_count() const { return probe_count_; }
  bool consumed(int variable) const {
    return consumed_.at(static_cast<size_t>(variable - 1));
  }
  std::string current_priority_bank_sha256() const {
    return o1c82::ParentCenteredPriority::seed_payload_sha256(
        priority_.export_packed_bank());
  }
  o1c82::SeedImage export_priority_seed() const {
    return priority_.export_seed();
  }

  void write_base_json(std::ostream &out) const { base_.write_json(out); }
  void write_vault_json(std::ostream &out) const {
    base_.write_vault_json(out);
  }
  void write_ownership_json(std::ostream &out) const {
    ownership_.write_json(out);
  }

  void write_priority_seed_json(std::ostream &out) const {
    out << "\"magic\":\"" << o1c82::kSeedMagic
        << "\",\"schema\":\"" << o1c82::kSeedSchema
        << "\",\"payload_bytes\":" << o1c82::kCoordinateBankBytes
        << ",\"payload_sha256\":\"" << seed_sha256_
        << "\",\"production_seal_enforced\":"
        << (production_seal_ ? "true" : "false")
        << ",\"expected_production_sha256\":\""
        << kLiveContinuationBankSha256
        << "\",\"source_priority_state_receipt_sha256\":\""
        << kO1C101PriorityStateReceiptSha256
        << "\",\"source_priority_state_receipt_bytes\":"
        << kO1C101PriorityStateReceiptBytes
        << ",\"source_preparation_manifest_sha256\":\""
        << kO1C102PreparationManifestSha256
        << "\",\"source_preparation_manifest_bytes\":"
        << kO1C102PreparationManifestBytes
        << ",\"source_derived_resolution_receipt_sha256\":\""
        << kO1C102DerivedResolutionReceiptSha256
        << "\",\"source_derived_resolution_receipt_bytes\":"
        << kO1C102DerivedResolutionReceiptBytes
        << ",\"seed_source\":\""
        << (seed_sha256_ == kLiveContinuationBankSha256
                ? kLiveContinuationBankSource
                : "public-fixture-bank")
        << "\",\"live_continuation_bank_identity\":"
        << (seed_sha256_ == kLiveContinuationBankSha256 ? "true" : "false")
        << ",\"fresh_seed_parser_used\":false"
        << ",\"import_roundtrip_exact\":true"
        << ",\"initial_eligible_coordinate_count\":"
        << initial_eligible_coordinate_count_;
  }

  void write_priority_state_json(std::ostream &out) const {
    validate_telemetry();
    const o1c82::PackedCoordinateBank packed = priority_.export_packed_bank();
    const std::string packed_payload(
        reinterpret_cast<const char *>(packed.data()), packed.size());
    out << "\"schema\":\"" << kPriorityStateSchema
        << "\",\"operator\":";
    priority_.write_json(out);
    out << ",\"candidate_population\":" << candidates_.size()
        << ",\"candidate_order_rule\":\"" << kCandidateOrderRule
        << "\",\"candidate_order_sha256\":\""
        << sha256(candidate_order_payload_)
        << "\",\"parent_scans\":" << parent_scans_
        << ",\"last_parent_candidate_count\":"
        << last_parent_candidate_count_
        << ",\"callback_calls\":" << callback_calls_
        << ",\"nonzero_returns\":" << nonzero_returns_
        << ",\"zero_returns\":" << zero_returns_
        << ",\"assignment_literals_observed\":"
        << assignment_literals_observed_
        << ",\"consumed_coordinate_count\":" << consumed_count()
        << ",\"one_shot_rule\":\"" << kOneShotRule
        << "\",\"bank_encoding\":\"256-variable-ordered-96-byte-records-"
           "little-endian\",\"bank_bytes\":"
        << packed.size() << ",\"bank_hex\":\"" << bytes_hex(packed_payload)
        << "\",\"current_bank_sha256\":\"" << sha256(packed_payload)
        << "\",\"probe_trace\":{\"encoding\":\"u64le-call;u64le-"
           "probe;u32le-candidate-index;u32le-parent-level;i32le-variable;"
           "f64le-U0;f64le-U1;f64le-tau;u8-selection;i32le-certified-"
           "literal\",\"record_bytes\":"
        << kProbeTraceRecordBytes << ",\"count\":" << probe_count_
        << ",\"bytes\":" << probe_trace_bytes_
        << ",\"sha256\":\"" << probe_trace_.hex_digest()
        << "\"},\"probe_counters\":{\"child_bound_evaluations\":"
        << child_bound_evaluations_
        << ",\"NEITHER_PRUNABLE\":" << class_counts_[0]
        << ",\"ZERO_PRUNABLE\":" << class_counts_[1]
        << ",\"ONE_PRUNABLE\":" << class_counts_[2]
        << ",\"BOTH_PRUNABLE\":" << class_counts_[3]
        << "},\"state_accounting\":{\"priority_bank_bytes\":"
        << o1c82::kCoordinateBankBytes
        << ",\"parent_scratch_bytes\":" << o1c82::kParentScratchBytes
        << ",\"priority_live_state_bytes\":" << o1c82::kLiveStateBytes
        << ",\"consumed_mask_bytes\":" << sizeof(consumed_)
        << ",\"action_capacity\":" << actions_.size()
        << ",\"action_record_bytes\":" << sizeof(PriorityActionEvent)
        << ",\"action_state_bytes\":" << sizeof(actions_)
        << ",\"growing_parent_history_bytes\":0}";
  }

  void write_priority_actions_json(std::ostream &out) const {
    validate_telemetry();
    out << "\"schema\":\"" << kPriorityActionSchema
        << "\",\"transport_origin\":\"" << kTransportOriginName
        << "\",\"transport_is_semantic_name\":false"
        << ",\"action_order_rule\":\"" << kActionOrderRule
        << "\",\"one_shot_rule\":\"" << kOneShotRule
        << "\",\"proof_mining_semantic\":\"" << kProofMiningSemantic
        << "\",\"certified_crossing_semantic\":\""
        << kCertifiedCrossingSemantic
        << "\",\"belief_orientation_authorized\":false"
        << ",\"posterior_emitted\":false,\"prune_claim_for_failure_first\":false"
        << ",\"action_count\":" << action_count_
        << ",\"failure_first_count\":" << failure_first_actions_
        << ",\"certified_crossing_count\":" << certified_crossing_actions_
        << ",\"level_bindings\":" << level_bindings_
        << ",\"confirmed_actions\":" << confirmed_actions_
        << ",\"coincident_v6_pending_actions\":"
        << coincident_v6_pending_actions_
        << ",\"releases\":" << releases_
        << ",\"unobserved_releases\":" << unobserved_releases_
        << ",\"action_trace_bytes\":" << action_trace_bytes_
        << ",\"action_trace_sha256\":\""
        << action_trace_.hex_digest() << "\",\"actions\":[";
    for (size_t index = 0; index < action_count_; ++index) {
      if (index)
        out << ',';
      const PriorityActionEvent &event = actions_[index];
      out << "{\"sequence\":" << index + 1U
          << ",\"token\":" << event.token << ",\"call\":"
          << event.call << ",\"first_probe\":" << event.first_probe
          << ",\"parent_probe_count\":" << event.parent_probe_count
          << ",\"coordinate_index\":" << event.coordinate
          << ",\"variable\":" << event.variable
          << ",\"literal\":" << event.literal
          << ",\"transport_origin\":\"" << kTransportOriginName
          << "\",\"semantic\":\"" << semantic_name(event.semantic)
          << "\",\"machine_action\":\""
          << machine_action_name(event.semantic)
          << "\",\"certified_threshold_action\":"
          << (event.semantic ==
                      PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING
                  ? "true"
                  : "false")
          << ",\"proof_mining_action\":"
          << (event.semantic ==
                      PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING
                  ? "true"
                  : "false")
          << ",\"belief_orientation_authorized\":false"
          << ",\"parent_level\":" << event.parent_level
          << ",\"bound_level\":";
      if (event.bound_level)
        out << event.bound_level;
      else
        out << "null";
      out << ",\"parent_assignment_sha256\":\""
          << event.parent_assignment_sha256.data()
          << "\",\"upper_zero\":" << event.upper_zero
          << ",\"upper_one\":" << event.upper_one
          << ",\"current_lower_upper_bound\":"
          << event.lower_upper_bound
          << ",\"current_differential\":" << event.current_differential
          << ",\"persistent_priority\":" << event.priority
          << ",\"accumulated_count\":" << event.accumulated_count
          << ",\"confirmed\":" << (event.confirmed ? "true" : "false")
          << ",\"coincident_v6_pending\":"
          << (event.coincident_v6_pending ? "true" : "false")
          << ",\"released\":" << (event.released ? "true" : "false")
          << ",\"unobserved_release\":"
          << (event.unobserved_release ? "true" : "false") << '}';
    }
    out << ']';
  }

private:
  static size_t no_action() {
    return std::numeric_limits<size_t>::max();
  }

  size_t local(int variable) const {
    const std::vector<int> &observed = base_.observed();
    const auto iterator =
        std::lower_bound(observed.begin(), observed.end(), variable);
    if (iterator == observed.end() || *iterator != variable)
      throw std::runtime_error("O1C103 variable is unobserved");
    return static_cast<size_t>(iterator - observed.begin());
  }

  void require_shadow_identity() const {
    const std::string shadow(
        reinterpret_cast<const char *>(assignment_.data()),
        assignment_.size());
    if (shadow != base_.assignment_state())
      throw std::runtime_error("O1C103 shadow assignment differs from v6");
  }

  size_t consumed_count() const {
    return static_cast<size_t>(
        std::count(consumed_.begin(), consumed_.end(), true));
  }

  void append_probe_trace(uint64_t call, uint64_t probe,
                          size_t candidate_index, int variable,
                          const o1c80::ChildUpperBounds &bounds,
                          o1c80::ChildSelectionClass selection,
                          int certified_literal) {
    std::string record;
    record.reserve(kProbeTraceRecordBytes);
    append_u64_le(record, call);
    append_u64_le(record, probe);
    append_u32_le(record, static_cast<uint32_t>(candidate_index));
    append_u32_le(record, current_level_);
    central_append_i32(record, variable);
    append_u64_le(record, f64_bits(bounds.zero));
    append_u64_le(record, f64_bits(bounds.one));
    append_u64_le(record, f64_bits(threshold_));
    record.push_back(static_cast<char>(selection));
    central_append_i32(record, certified_literal);
    if (record.size() != kProbeTraceRecordBytes)
      throw std::runtime_error("O1C103 probe trace width differs");
    probe_trace_.update(record);
    probe_trace_bytes_ += record.size();
  }

  int scan_and_select(uint64_t call) {
    ++parent_scans_;
    require_shadow_identity();
    if (!pending_clause_literals(base_.pending_state()).empty())
      throw std::runtime_error("O1C103 selector overlaps pending v6 clause");
    const std::string assignment_before = base_.assignment_state();
    const std::string trail_before = base_.trail_state();
    const std::string pending_before = base_.pending_state();
    const std::string cache_before = base_.group_cache_state();
    const std::string parent_assignment_sha256 = sha256(assignment_before);
    const o1c80::ExactOneBitParentCache<ExactDoubleSum> parent_cache =
        one_bit_reader_.prepare_parent<ExactDoubleSum>(assignment_);
    const auto upward = [](ExactDoubleSum exact, const char *field) {
      return upward_exact_sum(std::move(exact), field);
    };

    current_present_ = {};
    size_t batch_size = 0;
    CrossingCandidate crossing;
    const uint64_t first_probe = probe_count_ + 1U;
    for (size_t candidate_index = 0; candidate_index < candidates_.size();
         ++candidate_index) {
      const int variable = candidates_[candidate_index];
      if (assignment_.at(local(variable)) ||
          ownership_.has_live_variable(variable))
        continue;
      const o1c80::ChildUpperBounds bounds =
          one_bit_reader_.child_upper_bounds<ExactDoubleSum>(
              parent_cache, variable, upward);
      const o1c80::ChildBoundSelection selection =
          o1c80::ExactOneBitBoundReader::select(variable, bounds, threshold_);
      parent_batch_[batch_size] = {variable, bounds.zero, bounds.one};
      parent_expected_[batch_size] = variable;
      ++batch_size;
      const size_t coordinate = static_cast<size_t>(variable - 1);
      current_bounds_[coordinate] = bounds;
      current_present_[coordinate] = true;
      const uint64_t probe = ++probe_count_;
      child_bound_evaluations_ += 2U;
      ++class_counts_.at(static_cast<size_t>(selection.selection));
      append_probe_trace(call, probe, candidate_index, variable, bounds,
                         selection.selection, selection.losing_literal);
      if (!crossing.available && selection.losing_literal &&
          !consumed_[coordinate]) {
        crossing.available = true;
        crossing.coordinate = coordinate;
        crossing.variable = variable;
        crossing.literal = selection.losing_literal;
        crossing.bounds = bounds;
      }
    }
    last_parent_candidate_count_ = batch_size;
    if (batch_size) {
      const o1c82::ParentUpdateResult update = priority_.observe_parent(
          parent_batch_.data(), batch_size, parent_expected_.data(),
          batch_size);
      last_parent_median_ = update.parent_median;
      last_parent_mad_ = update.parent_mad;
      last_robust_scale_ = update.robust_scale;
      last_priority_selection_ = priority_.select_current_parent(consumed_);
    } else {
      priority_.clear_current_parent();
      last_priority_selection_ = {};
    }

    if (assignment_before != base_.assignment_state() ||
        trail_before != base_.trail_state() ||
        pending_before != base_.pending_state() ||
        cache_before != base_.group_cache_state())
      throw std::runtime_error(
          "O1C103 probes mutated authoritative v6 state");

    const uint64_t parent_probe_count = batch_size;
    if (crossing.available) {
      const o1c82::CoordinateReport report =
          priority_.coordinate_report(crossing.variable);
      return propose_action(
          call, first_probe, parent_probe_count, crossing.coordinate,
          crossing.variable, crossing.literal, crossing.bounds,
          report.priority, report.count,
          PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING,
          parent_assignment_sha256);
    }
    if (!last_priority_selection_.available)
      return 0;
    const int variable = last_priority_selection_.variable;
    const size_t coordinate = static_cast<size_t>(variable - 1);
    if (!current_present_[coordinate])
      throw std::runtime_error("O1C103 priority winner lacks current bounds");
    const o1c80::ChildUpperBounds bounds = current_bounds_[coordinate];
    const int literal =
        o1c82::ParentCenteredPriority::lower_upper_bound_action_literal(
            variable, bounds.zero, bounds.one);
    if (literal != last_priority_selection_.action_literal)
      throw std::runtime_error("O1C103 current lower-bound mapping differs");
    return propose_action(
        call, first_probe, parent_probe_count, coordinate, variable, literal,
        bounds, last_priority_selection_.coordinate.priority,
        last_priority_selection_.coordinate.count,
        PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING,
        parent_assignment_sha256);
  }

  int propose_action(uint64_t call, uint64_t first_probe,
                     uint64_t parent_probe_count, size_t coordinate,
                     int variable, int literal,
                     const o1c80::ChildUpperBounds &bounds, double priority,
                     uint64_t accumulated_count,
                     PriorityActionSemantic semantic,
                     const std::string &parent_assignment_sha256) {
    if (action_count_ >= actions_.size() || coordinate >= consumed_.size() ||
        variable != static_cast<int>(coordinate + 1U) ||
        consumed_[coordinate] || pending_action_index_ != no_action())
      throw std::runtime_error("O1C103 one-shot action capacity differs");
    const int expected =
        o1c82::ParentCenteredPriority::lower_upper_bound_action_literal(
            variable, bounds.zero, bounds.one);
    if (literal != expected)
      throw std::runtime_error("O1C103 action is not current lower-UB child");
    const double lower = std::min(bounds.zero, bounds.one);
    if ((semantic == PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING &&
         lower < threshold_) ||
        (semantic ==
             PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING &&
         !(lower < threshold_)))
      throw std::runtime_error("O1C103 action certification differs");
    const uint64_t token = ownership_.propose(
        o1c101::DecisionOrigin::BOUND_LOSING_CHILD,
        static_cast<uint32_t>(coordinate), literal, call);
    PriorityActionEvent &event = actions_[action_count_];
    event.token = token;
    event.call = call;
    event.first_probe = first_probe;
    event.parent_probe_count = parent_probe_count;
    event.coordinate = static_cast<uint32_t>(coordinate);
    event.parent_level = current_level_;
    event.variable = variable;
    event.literal = literal;
    event.upper_zero = bounds.zero;
    event.upper_one = bounds.one;
    event.lower_upper_bound = lower;
    event.current_differential = bounds.zero - bounds.one;
    event.priority = priority;
    event.accumulated_count = accumulated_count;
    event.semantic = semantic;
    if (parent_assignment_sha256.size() != 64U)
      throw std::runtime_error("O1C103 parent assignment digest differs");
    std::copy(parent_assignment_sha256.begin(), parent_assignment_sha256.end(),
              event.parent_assignment_sha256.begin());
    event.parent_assignment_sha256[64] = '\0';
    consumed_[coordinate] = true;
    pending_action_index_ = action_count_++;
    if (semantic == PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING)
      ++failure_first_actions_;
    else
      ++certified_crossing_actions_;
    append_action_trace(event);
    return literal;
  }

  void append_action_trace(const PriorityActionEvent &event) {
    std::string record;
    append_u64_le(record, event.token);
    append_u64_le(record, event.call);
    append_u32_le(record, event.coordinate);
    central_append_i32(record, event.variable);
    central_append_i32(record, event.literal);
    append_u64_le(record, f64_bits(event.upper_zero));
    append_u64_le(record, f64_bits(event.upper_one));
    record.push_back(static_cast<char>(event.semantic));
    action_trace_.update(record);
    action_trace_bytes_ += record.size();
  }

  void observe_action_assignment(int literal) {
    for (size_t reverse = action_count_; reverse > 0; --reverse) {
      PriorityActionEvent &event = actions_[reverse - 1U];
      if (event.released || !event.bound_level || event.confirmed ||
          event.literal != literal || event.bound_level > current_level_)
        continue;
      event.confirmed = true;
      ++confirmed_actions_;
      const bool pending =
          !pending_clause_literals(base_.pending_state()).empty();
      if (event.semantic ==
              PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING &&
          pending) {
        // A batched notification can cross tau only after other simultaneous
        // literals are added.  This action remains proof-mining-only and does
        // not claim ownership or certification of that coincident v6 prune.
        event.coincident_v6_pending = true;
        ++coincident_v6_pending_actions_;
      }
      if (event.semantic ==
              PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING &&
          !pending)
        throw std::runtime_error(
            "certified strict crossing lacked v6 threshold prune");
      return;
    }
  }

  void apply_release(const o1c101::DecisionToken &token) {
    const auto found = std::find_if(
        actions_.begin(), actions_.begin() + static_cast<ptrdiff_t>(action_count_),
        [&token](const PriorityActionEvent &event) {
          return event.token == token.token;
        });
    if (found == actions_.begin() + static_cast<ptrdiff_t>(action_count_) ||
        found->released || found->coordinate != token.row ||
        found->literal != token.literal ||
        found->bound_level != token.bound_level ||
        found->confirmed != token.confirmed)
      throw std::runtime_error("O1C103 action release lifecycle differs");
    found->released = true;
    found->unobserved_release = !token.confirmed;
    ++releases_;
    if (!token.confirmed)
      ++unobserved_releases_;
  }

  void validate_telemetry() const {
    const uint64_t class_total = class_counts_[0] + class_counts_[1] +
                                 class_counts_[2] + class_counts_[3];
    if (!solve_finalized_ || callback_calls_ != parent_scans_ ||
        callback_calls_ != nonzero_returns_ + zero_returns_ ||
        probe_trace_bytes_ != probe_count_ * kProbeTraceRecordBytes ||
        child_bound_evaluations_ != 2U * probe_count_ ||
        class_total != probe_count_ || action_count_ > actions_.size() ||
        action_count_ != consumed_count() ||
        action_count_ != failure_first_actions_ + certified_crossing_actions_ ||
        ownership_.proposals() != action_count_ ||
        ownership_.origin_proposals(
            o1c101::DecisionOrigin::BOUND_LOSING_CHILD) != action_count_ ||
        ownership_.origin_level_bound(
            o1c101::DecisionOrigin::BOUND_LOSING_CHILD) != level_bindings_ ||
        ownership_.origin_confirmed(
            o1c101::DecisionOrigin::BOUND_LOSING_CHILD) != confirmed_actions_ ||
        ownership_.origin_releases(
            o1c101::DecisionOrigin::BOUND_LOSING_CHILD) != releases_ ||
        seed_sha256_.size() != 64U ||
        (production_seal_ && seed_sha256_ != kLiveContinuationBankSha256))
      throw std::runtime_error("O1C103 priority telemetry differs");
    size_t counted_releases = 0;
    size_t counted_unobserved = 0;
    size_t counted_coincident = 0;
    for (size_t index = 0; index < action_count_; ++index) {
      const PriorityActionEvent &event = actions_[index];
      if (event.token != index + 1U || !event.call || !event.first_probe ||
          !event.parent_probe_count || event.variable <= 0 || !event.literal ||
          event.coordinate != static_cast<uint32_t>(event.variable - 1) ||
          event.lower_upper_bound !=
              std::min(event.upper_zero, event.upper_one) ||
          event.literal !=
              o1c82::ParentCenteredPriority::lower_upper_bound_action_literal(
                  event.variable, event.upper_zero, event.upper_one) ||
          (event.semantic ==
               PriorityActionSemantic::FAILURE_FIRST_PROOF_MINING &&
           event.lower_upper_bound < threshold_) ||
          (event.semantic ==
               PriorityActionSemantic::CERTIFIED_STRICT_BOUND_CROSSING &&
           !(event.lower_upper_bound < threshold_)) ||
          event.unobserved_release != (event.released && !event.confirmed))
        throw std::runtime_error("O1C103 priority action telemetry differs");
      counted_releases += event.released ? 1U : 0U;
      counted_unobserved += event.unobserved_release ? 1U : 0U;
      counted_coincident += event.coincident_v6_pending ? 1U : 0U;
    }
    if (counted_releases != releases_ ||
        counted_unobserved != unobserved_releases_ ||
        counted_coincident != coincident_v6_pending_actions_)
      throw std::runtime_error("O1C103 priority release telemetry differs");
    require_shadow_identity();
  }

  o1c80::ExactOneBitBoundReader one_bit_reader_;
  GroupedJointScoreSieveV6 base_;
  o1c82::ParentCenteredPriority priority_;
  double threshold_ = 0.0;
  std::string seed_sha256_;
  bool production_seal_ = true;
  std::vector<int8_t> assignment_;
  std::vector<PriorityTrailEntry> trail_;
  std::vector<int> candidates_;
  std::string candidate_order_payload_;
  uint32_t current_level_ = 0;
  o1c101::DecisionOwnershipLedger ownership_;
  std::array<bool, o1c82::kCoordinateCount> consumed_{};
  std::array<bool, o1c82::kCoordinateCount> current_present_{};
  std::array<o1c80::ChildUpperBounds, o1c82::kCoordinateCount>
      current_bounds_{};
  std::array<o1c82::BoundPair, o1c82::kCoordinateCount> parent_batch_{};
  std::array<int, o1c82::kCoordinateCount> parent_expected_{};
  std::array<PriorityActionEvent, kMaximumPriorityActions> actions_{};
  size_t action_count_ = 0;
  size_t pending_action_index_ = no_action();
  size_t initial_eligible_coordinate_count_ = 0;
  size_t last_parent_candidate_count_ = 0;
  double last_parent_median_ = 0.0;
  double last_parent_mad_ = 0.0;
  double last_robust_scale_ = o1c82::kRobustScaleFloor;
  o1c82::SelectionResult last_priority_selection_;
  uint64_t callback_calls_ = 0;
  uint64_t parent_scans_ = 0;
  uint64_t probe_count_ = 0;
  uint64_t child_bound_evaluations_ = 0;
  uint64_t probe_trace_bytes_ = 0;
  std::array<uint64_t, 4> class_counts_{};
  uint64_t nonzero_returns_ = 0;
  uint64_t zero_returns_ = 0;
  uint64_t assignment_literals_observed_ = 0;
  uint64_t failure_first_actions_ = 0;
  uint64_t certified_crossing_actions_ = 0;
  uint64_t level_bindings_ = 0;
  uint64_t confirmed_actions_ = 0;
  uint64_t coincident_v6_pending_actions_ = 0;
  uint64_t releases_ = 0;
  uint64_t unobserved_releases_ = 0;
  uint64_t action_trace_bytes_ = 0;
  Sha256 probe_trace_;
  Sha256 action_trace_;
  bool solve_finalized_ = false;
};

[[maybe_unused]] void print_v30_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v30 --cnf PATH "
               "--potential PATH --grouping PATH --vault-in PATH "
               "--priority-seed PATH --threshold FLOAT --conflict-limit N "
               "[--seed N]\n";
}

} // namespace

#ifndef O1_CRYPTO_LAB_O1C103_NO_MAIN
int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v30_usage();
      return 0;
    }
    const PriorityArguments priority_arguments =
        parse_priority_arguments(argc, argv);
    const GroupedArguments &grouped_arguments = priority_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("O1C103 priority operator requires seed zero");
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
    const std::string seed_payload =
        read_binary_file(priority_arguments.priority_seed_path,
                         "priority seed");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);
    const std::string vault_sha256 = sha256(vault_payload);
    const std::string seed_sha256 = sha256(seed_payload);

#ifdef O1_CRYPTO_LAB_O1C103_PUBLIC_FIXTURE
    constexpr bool production_seal = false;
#else
    constexpr bool production_seal = true;
#endif
    if (production_seal &&
        (seed_payload.size() != o1c82::kCoordinateBankBytes ||
         seed_sha256 != kLiveContinuationBankSha256))
      throw std::runtime_error("sealed O1C103 priority seed differs");
    if (production_seal &&
        vault_payload.size() == kBurnedPage18ActiveVaultBytes &&
        vault_sha256 == kBurnedPage18ActiveVaultSha256)
      throw std::runtime_error("burned O1C101 Page-18 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage17ActiveVaultBytes &&
        vault_sha256 == kBurnedPage17ActiveVaultSha256)
      throw std::runtime_error("burned O1C99 Page-17 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage16ActiveVaultBytes &&
        vault_sha256 == kBurnedPage16ActiveVaultSha256)
      throw std::runtime_error("burned O1C97 Page-16 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage15ActiveVaultBytes &&
        vault_sha256 == kBurnedPage15ActiveVaultSha256)
      throw std::runtime_error("burned O1C95 Page-15 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage14ActiveVaultBytes &&
        vault_sha256 == kBurnedPage14ActiveVaultSha256)
      throw std::runtime_error("burned O1C92 Page-14 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage13ActiveVaultBytes &&
        vault_sha256 == kBurnedPage13ActiveVaultSha256)
      throw std::runtime_error("burned O1C90 Page-13 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage12ActiveVaultBytes &&
        vault_sha256 == kBurnedPage12ActiveVaultSha256)
      throw std::runtime_error("burned O1C88 Page-12 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage11ActiveVaultBytes &&
        vault_sha256 == kBurnedPage11ActiveVaultSha256)
      throw std::runtime_error("burned O1C86 Page-11 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage10ActiveVaultBytes &&
        vault_sha256 == kBurnedPage10ActiveVaultSha256)
      throw std::runtime_error("burned O1C85 Page-10 active vault rejected");
    if (production_seal &&
        vault_payload.size() == kBurnedPage9ActiveVaultBytes &&
        vault_sha256 == kBurnedPage9ActiveVaultSha256)
      throw std::runtime_error("burned O1C84 Page-9 active vault rejected");
    if (production_seal &&
        (vault_payload.size() != kProductionPage19ActiveVaultBytes ||
         vault_sha256 != kProductionPage19ActiveVaultSha256))
      throw std::runtime_error("sealed O1C103 Page-19 active vault differs");

    std::unique_ptr<ParentCenteredGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") || !solver.set("seed", arguments.seed) ||
          !solver.set("quiet", 1) || !solver.set("factor", 0) ||
          !solver.set("lucky", 0) || !solver.set("walk", 0) ||
          !solver.set("rephase", 0) || !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic O1C103 options");
      int variables = 0;
      if (const char *error =
              solver.read_dimacs(arguments.cnf_path.c_str(), variables, 2))
        throw std::runtime_error(std::string("DIMACS read failed: ") + error);
      if (variables < static_cast<int>(kKeyBits) ||
          variables > kMaximumVariables)
        throw std::runtime_error("DIMACS variable count differs");

      PotentialField field = parse_potential(potential_payload, variables);
      propagator = std::make_unique<ParentCenteredGroupedJointScoreSieve>(
          std::move(field), grouping_payload, vault_payload, cnf_sha256,
          potential_sha256, arguments.threshold, seed_payload, seed_sha256,
          production_seal);
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
          << "{\"schema\":\"" << kV30ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV30ImplementationParentSchema
          << "\",\"operator_semantics\":\"failure-first-proof-mining-"
             "with-certified-crossing-precedence\",\"priority_seed\":{";
      propagator->write_priority_seed_json(out);
      out << "},\"priority_state\":{";
      propagator->write_priority_state_json(out);
      out << "},\"priority_actions\":{";
      propagator->write_priority_actions_json(out);
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
          << "\",\"active_vault_sha256\":\"" << vault_sha256
          << "\",\"stats\":{\"conflicts\":" << conflicts
          << ",\"conflicts_before_solve\":" << conflicts_before_solve
          << ",\"solve_conflicts\":" << solve_conflicts
          << ",\"decisions\":" << decisions
          << ",\"propagations\":" << propagations
          << "},\"base_sieve\":{";
      propagator->write_base_json(out);
      out << "},\"vault\":{";
      propagator->write_vault_json(out);
      out << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
          << ",\"cpu_microseconds\":" << cpu_microseconds()
          << ",\"peak_rss_bytes\":" << peak_rss_bytes()
          << "}}\n";
      result_json = out.str();
    }

    propagator.reset();
    std::cout << result_json;
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_joint_score_sieve_v30: " << error.what() << '\n';
    return 1;
  }
}
#endif
