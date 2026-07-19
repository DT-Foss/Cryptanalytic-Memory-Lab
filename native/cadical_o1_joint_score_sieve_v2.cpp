#define main cadical_o1_joint_score_sieve_v1_main
#include "cadical_o1_joint_score_sieve.cpp"
#undef main

namespace {

constexpr const char *kV2Schema =
    "o1-256-cadical-joint-score-sieve-result-v2";

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
    auto propagator =
        std::make_unique<JointScoreSieve>(std::move(field), arguments.threshold);
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
              << "{\"schema\":\"" << kV2Schema
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
    std::cerr << "cadical_o1_joint_score_sieve_v2: " << error.what() << '\n';
    return 1;
  }
}
