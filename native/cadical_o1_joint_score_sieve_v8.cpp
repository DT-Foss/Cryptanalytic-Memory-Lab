// Explicit phase-one reader successor to the frozen native-v6 vault solver.
//
// All parsing, grouping, vault, propagation, accounting, and lifecycle logic is
// compiled directly from v6.  This wrapper changes only the result identity and
// makes CaDiCaL's phase-one reader choice immutable and auditable.  There is
// intentionally no phase-selection CLI surface.
#define O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN
#include "cadical_o1_joint_score_sieve_v6.cpp"
#undef O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN

namespace {

constexpr const char *kV8ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v8";
constexpr const char *kV8ImplementationParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v6";
constexpr const char *kForcedInitialPhaseReaderSchema =
    "o1-256-cadical-forced-initial-phase-reader-v1";
constexpr const char *kForcedInitialPhaseOperator = "forced-initial-phase";
constexpr const char *kForcedInitialPhaseComplementPairId =
    "forced-initial-phase-v1";
constexpr int kForcedInitialPhase = 1;
constexpr std::string_view kForcedInitialPhaseReaderSpec =
    "forced-initial-phase-v1\n"
    "cadical_configuration=plain\n"
    "phase_before_override=1\n"
    "seed=0\n"
    "quiet=1\n"
    "factor=0\n"
    "lucky=0\n"
    "walk=0\n"
    "rephase=0\n"
    "forcephase=1\n"
    "phase=1\n";
constexpr const char *kExpectedForcedInitialPhaseReaderSpecSha256 =
    "ce039b56a647cbc67deea1fa70db7e755ea00a6dd183015a43e94c032b5706cc";

void print_v8_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v8 --cnf PATH "
               "--potential PATH --grouping PATH --vault-in PATH "
               "--threshold FLOAT --conflict-limit N [--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v8_usage();
      return 0;
    }

    const GroupedArguments grouped_arguments =
        parse_grouped_arguments(argc, argv);
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("forced-phase reader requires seed zero");
    const std::string reader_spec_sha256 =
        sha256(kForcedInitialPhaseReaderSpec);
    if (reader_spec_sha256 != kExpectedForcedInitialPhaseReaderSpecSha256)
      throw std::runtime_error("forced-phase reader specification differs");
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
      if (!solver.set("phase", kForcedInitialPhase) ||
          solver.get("phase") != kForcedInitialPhase ||
          !solver.set("seed", arguments.seed) || !solver.set("quiet", 1) ||
          !solver.set("factor", 0) || !solver.set("lucky", 0) ||
          !solver.set("walk", 0) || !solver.set("rephase", 0) ||
          !solver.set("forcephase", 1) || solver.get("forcephase") != 1 ||
          solver.get("seed") != 0 || solver.get("quiet") != 1 ||
          solver.get("factor") != 0 || solver.get("rephase") != 0 ||
          solver.get("lucky") != 0 || solver.get("walk") != 0)
        throw std::runtime_error(
            "CaDiCaL rejected deterministic forced-phase reader options");
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
          << "{\"schema\":\"" << kV8ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV8ImplementationParentSchema
          << "\",\"reader\":{\"schema\":\""
          << kForcedInitialPhaseReaderSchema << "\",\"operator\":\""
          << kForcedInitialPhaseOperator
          << "\",\"cadical_configuration\":\"plain\","
             "\"phase_before_override\":1,\"seed\":0,\"quiet\":1,"
             "\"factor\":0,\"phase\":1,\"forcephase\":true,"
             "\"rephase\":0,\"lucky\":false,\"walk\":false,"
             "\"complement_pair_id\":\""
          << kForcedInitialPhaseComplementPairId
          << "\",\"reader_spec_sha256\":\"" << reader_spec_sha256
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
    std::cerr << "cadical_o1_joint_score_sieve_v8: " << error.what() << '\n';
    return 1;
  }
}
