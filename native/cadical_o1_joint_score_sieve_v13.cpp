// O1C-0074 split rank-source / active-vault release-contrast reader.
//
// Native v12 remains frozen.  This translation unit embeds its exact reader
// and solve lifecycle, while separating the immutable vault used to derive the
// rank from the bounded active vault preloaded into CaDiCaL.

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
#include <utility>
#include <vector>

#ifdef O1_CRYPTO_LAB_O1C74_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE
#define O1_CRYPTO_LAB_O1C74_UNDEF_O1C73_FIXTURE
#endif
namespace o1c73_embedded_v12 {
#include "cadical_o1_joint_score_sieve_v12.cpp"
} // namespace o1c73_embedded_v12
#ifdef O1_CRYPTO_LAB_O1C74_UNDEF_O1C73_FIXTURE
#undef O1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE
#undef O1_CRYPTO_LAB_O1C74_UNDEF_O1C73_FIXTURE
#endif

using namespace o1c73_embedded_v12;

namespace {

constexpr const char *kV13ResultSchema =
    "o1-256-cadical-joint-score-sieve-result-v13";
constexpr const char *kV13ReleaseParentSchema =
    "o1-256-cadical-joint-score-sieve-result-v12";

struct SplitRankedArguments {
  RankedArguments ranked;
  std::string rank_vault_path;
};

SplitRankedArguments parse_split_ranked_arguments(int argc, char **argv) {
  std::vector<char *> filtered;
  filtered.reserve(static_cast<size_t>(argc));
  filtered.push_back(argv[0]);
  std::string rank_vault_path;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc)
      throw std::runtime_error("split-ranked arguments must be key-value pairs");
    if (std::string_view(argv[index]) == "--rank-vault") {
      if (!rank_vault_path.empty() || !argv[index + 1][0])
        throw std::runtime_error("rank-vault argument differs");
      rank_vault_path = argv[index + 1];
    } else {
      filtered.push_back(argv[index]);
      filtered.push_back(argv[index + 1]);
    }
  }
  if (rank_vault_path.empty())
    throw std::runtime_error("rank-vault argument is missing");
  return {parse_ranked_arguments(static_cast<int>(filtered.size()),
                                 filtered.data()),
          std::move(rank_vault_path)};
}

void print_v13_usage() {
  std::cout << "usage: cadical_o1_joint_score_sieve_v13 --cnf PATH "
               "--potential PATH --grouping PATH --rank-vault PATH "
               "--vault-in PATH --rank-table PATH --threshold FLOAT "
               "--conflict-limit N [--seed N]\n";
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
      print_v13_usage();
      return 0;
    }
    const SplitRankedArguments split_arguments =
        parse_split_ranked_arguments(argc, argv);
    const RankedArguments &ranked_arguments = split_arguments.ranked;
    const GroupedArguments &grouped_arguments = ranked_arguments.grouped;
    const Arguments &arguments = grouped_arguments.base;
    if (arguments.seed != 0)
      throw std::runtime_error("release-contrast reader requires seed zero");
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
    const std::string rank_payload =
        read_binary_file(ranked_arguments.rank_table_path, "rank table");
    const std::string cnf_sha256 = sha256(cnf_payload);
    const std::string potential_sha256 = sha256(potential_payload);
    const std::string rank_source_vault_sha256 = sha256(rank_vault_payload);

#ifdef O1_CRYPTO_LAB_O1C74_PUBLIC_FIXTURE
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
    RankTable rank =
        parse_rank_table(rank_payload, vote_field, production_seal);

    std::unique_ptr<ReleaseContrastGroupedJointScoreSieve> propagator;
    std::string result_json;
    {
      CaDiCaL::Solver solver;
      if (!solver.configure("plain") ||
          !solver.set("seed", arguments.seed) || !solver.set("quiet", 1) ||
          !solver.set("factor", 0) || !solver.set("lucky", 0) ||
          !solver.set("walk", 0) || !solver.set("rephase", 0) ||
          !solver.set("forcephase", 1))
        throw std::runtime_error(
            "CaDiCaL rejected deterministic release-contrast options");
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
      propagator =
          std::make_unique<ReleaseContrastGroupedJointScoreSieve>(
              std::move(field), grouping_payload, active_vault_payload,
              cnf_sha256, potential_sha256, arguments.threshold,
              std::move(rank), std::move(vote_field), potential_source_sha256);
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
          << "{\"schema\":\"" << kV13ResultSchema
          << "\",\"implementation_parent_schema\":\""
          << kV12ImplementationParentSchema
          << "\",\"implementation_release_parent_schema\":\""
          << kV13ReleaseParentSchema
          << "\",\"rank_source_vault_sha256\":\""
          << rank_source_vault_sha256 << "\",\"reader\":{";
      propagator->write_reader_json(out);
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
    std::cerr << "cadical_o1_joint_score_sieve_v13: " << error.what()
              << '\n';
    return 1;
  }
}
