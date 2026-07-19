// Sealed vault-suffix phase-field reader successor to native v8/v6.
//
// The production binary accepts no phase-selection argument.  It verifies the
// exact 202-clause public vault, reconstructs the exact 12-clause base prefix,
// derives sign majorities only from suffix clause indices [12, 202), validates
// every frozen field projection, and calls Solver::phase once per nonzero key
// coordinate before the single solve.  Parsing, grouping, propagation,
// accounting, and teardown remain compiled directly from frozen native v6.
#define O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN
#include "cadical_o1_joint_score_sieve_v6.cpp"
#undef O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN

namespace {

constexpr const char *kV9ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v9";
constexpr const char *kV9ImplementationParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v6";
constexpr const char *kVaultPhaseReaderSchema =
    "o1-256-cadical-vault-phase-field-reader-v1";
constexpr const char *kVaultPhaseOperator =
    "vault-suffix-cut-literal-majority-phase";
constexpr const char *kVaultPhaseVoteRule =
    "delta=count(+v)-count(-v);+v-if-positive;-v-if-negative;0-if-tie";
constexpr const char *kVaultPhaseFieldEncoding =
    "256-signed-i32le-phase-literals-variable-ascending";
constexpr const char *kEffectiveBitpackEncoding =
    "256-bits-lsb-first-variable-ascending;1=positive-phase;"
    "ties=fallback-phase-one";
constexpr int kVaultPhaseFallback = 1;
constexpr size_t kProductionSourceClauses = 202U;
constexpr size_t kProductionPrefixClauses = 12U;
constexpr size_t kProductionSuffixClauses = 190U;
constexpr size_t kProductionSuffixLiterals = 564667U;
constexpr size_t kProductionPositivePhases = 139U;
constexpr size_t kProductionNegativePhases = 116U;
constexpr size_t kProductionUnphased = 1U;
constexpr size_t kProductionPhaseCalls = 255U;
constexpr int kProductionUnphasedVariable = 241;
constexpr const char *kProductionVaultSha256 =
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858";
constexpr const char *kProductionBaseVaultSha256 =
    "371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a";
constexpr const char *kProductionSuffixRecordsSha256 =
    "cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521";
constexpr const char *kProductionFieldSha256 =
    "5d7fd1cfca56c1ab29f9e1490d28e16d3f5def611dad2f52c4ea4015678605fe";
constexpr const char *kProductionEffectiveBitpackHex =
    "ec6d45759effd185e9a6c163d47659ea2557df6f22bb9a017361f3f6d20c3955";
constexpr const char *kProductionEffectiveBitpackSha256 =
    "6381f90ee279a8075d4279ecfec5a3560e910afc12c891cb0bd86dac0ad511ec";
constexpr const char *kExpectedReaderSpecSha256 =
    "3dba50d3a376c2c025e2edbcc47215f19610547ad5bd6260221c82a1641df075";
constexpr std::string_view kVaultPhaseReaderSpec =
    "o1-vault-conditioned-key-phase-v1\n"
    "input-vault-sha256="
    "371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a\n"
    "output-vault-sha256="
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858\n"
    "population=output-clauses-after-exact-input-clause-prefix\n"
    "population-clause-count=190\n"
    "population-literal-count=564667\n"
    "population-clause-records-sha256="
    "cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521\n"
    "key-variables=1..256\n"
    "delta(v)=count(+v)-count(-v)\n"
    "phase-literal(v)=+v if delta(v)>0;-v if delta(v)<0;0 if delta(v)=0\n"
    "orientation=satisfy-majority-cut-literal-and-oppose-majority-excluded-"
    "witness-spin\n"
    "field-encoding=256-signed-i32le-phase-literals-in-variable-order;"
    "zero-means-no-vote\n"
    "apply=Solver::phase(phase-literal(v)) only when nonzero\n"
    "effective-default-phase=1\n"
    "bitpack=effective-true-at-little-endian-bit-(v-1)-of-32-bytes\n";

struct VaultPhaseField {
  std::array<int64_t, kKeyBits> positive_occurrences{};
  std::array<int64_t, kKeyBits> negative_occurrences{};
  std::array<int64_t, kKeyBits> delta{};
  std::array<int, kKeyBits> literals{};
  std::string source_vault_sha256;
  size_t source_clause_count = 0;
  size_t base_prefix_clause_count = 0;
  std::string base_prefix_vault_sha256;
  size_t suffix_start_clause_index = 0;
  size_t suffix_stop_clause_index_exclusive = 0;
  size_t suffix_clause_count = 0;
  size_t suffix_literal_count = 0;
  std::string suffix_canonical_records_sha256;
  std::string field_bytes;
  std::string field_sha256;
  size_t positive_count = 0;
  size_t negative_count = 0;
  std::vector<int> unphased_variables;
  size_t applied_phase_calls = 0;
  std::string effective_bitpack;
  std::string effective_bitpack_sha256;
};

VaultPhaseField derive_vault_phase_field(const std::string &payload,
                                         size_t clause_start,
                                         size_t clause_stop,
                                         bool require_production_seal) {
  if (payload.size() < kVaultMinimumBytes ||
      std::string_view(payload.data(), kVaultMagic.size()) != kVaultMagic)
    throw std::runtime_error("vault phase-field header differs");
  if (require_production_seal && sha256(payload) != kProductionVaultSha256)
    throw std::runtime_error("vault phase-field source SHA-256 differs");

  size_t cursor = kVaultIdentityPrefixBytes;
  const uint32_t clause_count =
      read_u32_le(payload, cursor, "vault phase-field clause count");
  if (clause_count > kMaximumVaultClauses || clause_start > clause_stop ||
      clause_stop > clause_count)
    throw std::runtime_error("vault phase-field clause slice differs");

  VaultPhaseField result;
  result.source_vault_sha256 = sha256(payload);
  result.source_clause_count = clause_count;
  result.base_prefix_clause_count = clause_start;
  result.suffix_start_clause_index = clause_start;
  result.suffix_stop_clause_index_exclusive = clause_stop;
  result.suffix_clause_count = clause_stop - clause_start;
  std::string prefix_records;
  std::string suffix_records;
  std::set<std::string> seen;
  size_t total_literals = 0;
  for (size_t clause_index = 0; clause_index < clause_count; ++clause_index) {
    const size_t record_start = cursor;
    const uint32_t length =
        read_u32_le(payload, cursor, "vault phase-field clause length");
    if (!length || length > kMaximumVaultLiterals - total_literals ||
        cursor > payload.size() ||
        static_cast<size_t>(length) > (payload.size() - cursor) / 4U)
      throw std::runtime_error("vault phase-field clause length differs");
    int64_t previous_absolute = 0;
    for (uint32_t literal_index = 0; literal_index < length; ++literal_index) {
      const int32_t literal =
          read_i32_le(payload, cursor, "vault phase-field literal");
      if (!literal || literal == std::numeric_limits<int32_t>::min())
        throw std::runtime_error("vault phase-field literal differs");
      const int64_t absolute =
          literal < 0 ? -static_cast<int64_t>(literal) : literal;
      if (absolute <= previous_absolute || absolute > kMaximumVariables)
        throw std::runtime_error("vault phase-field literal order differs");
      previous_absolute = absolute;
      if (clause_index >= clause_start && clause_index < clause_stop &&
          absolute <= kKeyBits) {
        auto &counts = literal > 0 ? result.positive_occurrences
                                   : result.negative_occurrences;
        ++counts[static_cast<size_t>(absolute - 1)];
      }
    }
    const std::string record = payload.substr(record_start, cursor - record_start);
    if (!seen.insert(record).second)
      throw std::runtime_error("vault phase-field duplicate clause differs");
    if (clause_index < clause_start)
      prefix_records += record;
    if (clause_index >= clause_start && clause_index < clause_stop) {
      suffix_records += record;
      result.suffix_literal_count += length;
    }
    total_literals += length;
  }
  if (cursor != payload.size())
    throw std::runtime_error("vault phase-field trailing bytes differ");

  std::string base_payload = payload.substr(0, kVaultIdentityPrefixBytes);
  append_u32_le(base_payload, static_cast<uint32_t>(clause_start));
  base_payload += prefix_records;
  result.base_prefix_vault_sha256 = sha256(base_payload);
  result.suffix_canonical_records_sha256 = sha256(suffix_records);
  result.field_bytes.reserve(4U * kKeyBits);
  result.effective_bitpack.assign(kKeyBits / 8U, '\0');
  for (int variable = 1; variable <= kKeyBits; ++variable) {
    const size_t index = static_cast<size_t>(variable - 1);
    result.delta[index] = result.positive_occurrences[index] -
                          result.negative_occurrences[index];
    const int literal = result.delta[index] > 0
                            ? variable
                            : result.delta[index] < 0 ? -variable : 0;
    result.literals[index] = literal;
    append_u32_le(result.field_bytes,
                  static_cast<uint32_t>(static_cast<int32_t>(literal)));
    if (literal > 0) {
      ++result.positive_count;
    } else if (literal < 0) {
      ++result.negative_count;
    } else {
      result.unphased_variables.push_back(variable);
    }
    if (literal > 0 || (!literal && kVaultPhaseFallback == 1)) {
      const size_t byte_index = index / 8U;
      const unsigned bit = static_cast<unsigned>(index % 8U);
      result.effective_bitpack[byte_index] = static_cast<char>(
          static_cast<unsigned char>(result.effective_bitpack[byte_index]) |
          static_cast<unsigned char>(1U << bit));
    }
  }
  result.applied_phase_calls = result.positive_count + result.negative_count;
  result.field_sha256 = sha256(result.field_bytes);
  result.effective_bitpack_sha256 = sha256(result.effective_bitpack);

  if (require_production_seal &&
      (result.source_clause_count != kProductionSourceClauses ||
       result.base_prefix_clause_count != kProductionPrefixClauses ||
       result.base_prefix_vault_sha256 != kProductionBaseVaultSha256 ||
       result.suffix_clause_count != kProductionSuffixClauses ||
       result.suffix_literal_count != kProductionSuffixLiterals ||
       result.suffix_canonical_records_sha256 !=
           kProductionSuffixRecordsSha256 ||
       result.field_bytes.size() != 4U * kKeyBits ||
       result.field_sha256 != kProductionFieldSha256 ||
       result.positive_count != kProductionPositivePhases ||
       result.negative_count != kProductionNegativePhases ||
       result.unphased_variables.size() != kProductionUnphased ||
       result.unphased_variables.front() != kProductionUnphasedVariable ||
       result.applied_phase_calls != kProductionPhaseCalls ||
       bytes_hex(result.effective_bitpack) != kProductionEffectiveBitpackHex ||
       result.effective_bitpack_sha256 !=
           kProductionEffectiveBitpackSha256))
    throw std::runtime_error("sealed O1C70 vault phase field differs");
  return result;
}

void print_v9_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v9 --cnf PATH "
               "--potential PATH --grouping PATH --vault-in PATH "
               "--threshold FLOAT --conflict-limit N [--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v9_usage();
      return 0;
    }
    const GroupedArguments grouped_arguments =
        parse_grouped_arguments(argc, argv);
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("vault phase-field reader requires seed zero");
    if (kVaultPhaseReaderSpec.size() != 847U ||
        sha256(kVaultPhaseReaderSpec) != kExpectedReaderSpecSha256)
      throw std::runtime_error("vault phase-field reader specification differs");
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");
    const std::string cnf_payload = read_binary_file(arguments.cnf_path, "CNF");
    const std::string potential_payload =
        read_binary_file(arguments.potential_path, "potential");
    const std::string grouping_payload =
        read_binary_file(grouped_arguments.grouping_path, "grouping");
    const std::string vault_payload =
        read_bounded_vault_file(grouped_arguments.vault_path);
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);

#ifdef O1_CRYPTO_LAB_O1C70_PUBLIC_FIXTURE
    const size_t reader_clause_start = 0U;
    size_t reader_cursor = kVaultIdentityPrefixBytes;
    const size_t reader_clause_stop =
        read_u32_le(vault_payload, reader_cursor, "fixture vault clause count");
    constexpr bool require_production_seal = false;
#else
    constexpr size_t reader_clause_start = kProductionPrefixClauses;
    constexpr size_t reader_clause_stop = kProductionSourceClauses;
    constexpr bool require_production_seal = true;
#endif
    const VaultPhaseField reader_field = derive_vault_phase_field(
        vault_payload, reader_clause_start, reader_clause_stop,
        require_production_seal);

    std::unique_ptr<GroupedJointScoreSieveV6> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain"))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic plain configuration");
      if (solver.get("phase") != 1)
        throw std::runtime_error(
            "CaDiCaL default initial phase differs before reader override");
      if (!solver.set("phase", kVaultPhaseFallback) ||
          solver.get("phase") != kVaultPhaseFallback ||
          !solver.set("seed", arguments.seed) || !solver.set("quiet", 1) ||
          !solver.set("factor", 0) || !solver.set("lucky", 0) ||
          !solver.set("walk", 0) || !solver.set("rephase", 0) ||
          !solver.set("forcephase", 1) || solver.get("forcephase") != 1 ||
          solver.get("seed") != 0 || solver.get("quiet") != 1 ||
          solver.get("factor") != 0 || solver.get("rephase") != 0 ||
          solver.get("lucky") != 0 || solver.get("walk") != 0)
        throw std::runtime_error(
            "CaDiCaL rejected deterministic vault phase-field options");
      int variables = 0;
      if (const char *error =
              solver.read_dimacs(arguments.cnf_path.c_str(), variables, 2))
        throw std::runtime_error(std::string("DIMACS read failed: ") + error);
      if (variables < kKeyBits || variables > kMaximumVariables)
        throw std::runtime_error("DIMACS variable count differs");

      PotentialField field = parse_potential(potential_payload, variables);
      propagator = std::make_unique<GroupedJointScoreSieveV6>(
          std::move(field), grouping_payload, vault_payload, cnf_sha256,
          potential_sha256, arguments.threshold);
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
      size_t applied_phase_calls = 0;
      for (const int literal : reader_field.literals) {
        if (!literal)
          continue;
        if (std::abs(literal) > variables)
          throw std::runtime_error("vault phase-field literal exceeds DIMACS");
        solver.phase(literal);
        ++applied_phase_calls;
      }
      if (applied_phase_calls != reader_field.applied_phase_calls)
        throw std::runtime_error("vault phase-field applied call count differs");
      if (!solver.limit("conflicts", arguments.conflict_limit))
        throw std::runtime_error("CaDiCaL rejected conflict limit");

      const int64_t conflicts_before_solve = statistic(solver, "conflicts");
      const auto started = std::chrono::steady_clock::now();
      const int status = solver.solve();
      const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
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
          << "{\"schema\":\"" << kV9ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV9ImplementationParentSchema
          << "\",\"reader\":{\"schema\":\"" << kVaultPhaseReaderSchema
          << "\",\"operator\":\"" << kVaultPhaseOperator
          << "\",\"cadical_configuration\":\"plain\","
             "\"phase_before_override\":1,\"phase\":1,"
             "\"forcephase\":true,\"rephase\":0,\"lucky\":false,"
             "\"walk\":false,\"seed\":0,\"quiet\":1,\"factor\":0,"
             "\"source_vault_sha256\":\""
          << reader_field.source_vault_sha256
          << "\",\"source_clause_count\":" << reader_field.source_clause_count
          << ",\"base_prefix_clause_count\":"
          << reader_field.base_prefix_clause_count
          << ",\"base_prefix_vault_sha256\":\""
          << reader_field.base_prefix_vault_sha256
          << "\",\"suffix_start_clause_index\":"
          << reader_field.suffix_start_clause_index
          << ",\"suffix_stop_clause_index_exclusive\":"
          << reader_field.suffix_stop_clause_index_exclusive
          << ",\"suffix_clause_count\":" << reader_field.suffix_clause_count
          << ",\"suffix_literal_count\":" << reader_field.suffix_literal_count
          << ",\"suffix_canonical_records_sha256\":\""
          << reader_field.suffix_canonical_records_sha256
          << "\",\"key_variable_count\":" << kKeyBits
          << ",\"vote_rule\":\"" << kVaultPhaseVoteRule
          << "\",\"field_encoding\":\"" << kVaultPhaseFieldEncoding
          << "\",\"field_bytes\":" << reader_field.field_bytes.size()
          << ",\"field_sha256\":\"" << reader_field.field_sha256
          << "\",\"positive_count\":" << reader_field.positive_count
          << ",\"negative_count\":" << reader_field.negative_count
          << ",\"unphased_count\":"
          << reader_field.unphased_variables.size()
          << ",\"unphased_variables\":[";
      for (size_t index = 0; index < reader_field.unphased_variables.size();
           ++index) {
        if (index)
          out << ',';
        out << reader_field.unphased_variables[index];
      }
      out << "],\"applied_phase_calls\":" << applied_phase_calls
          << ",\"fallback_phase\":" << kVaultPhaseFallback
          << ",\"effective_bitpack_encoding\":\""
          << kEffectiveBitpackEncoding << "\",\"effective_bitpack_hex\":\""
          << bytes_hex(reader_field.effective_bitpack)
          << "\",\"effective_bitpack_sha256\":\""
          << reader_field.effective_bitpack_sha256
          << "\",\"reader_spec_sha256\":\"" << kExpectedReaderSpecSha256
          << "\"},\"cadical_version\":\"" << CaDiCaL::Solver::version()
          << "\",\"variables\":" << variables
          << ",\"conflict_limit\":" << arguments.conflict_limit
          << ",\"seed\":" << arguments.seed << ",\"threshold\":"
          << arguments.threshold << ",\"status\":" << status
          << ",\"post_solve_state\":" << static_cast<int>(post_solve_state)
          << ",\"post_solve_state_name\":\"" << state_name(post_solve_state)
          << "\",\"teardown_rule\":\"" << kTeardownRule
          << "\",\"pending_backtrack_rule\":\"" << kPendingBacktrackRule
          << "\",\"key_model_hex\":";
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
    std::cerr << "cadical_o1_joint_score_sieve_v9: " << error.what() << '\n';
    return 1;
  }
}
