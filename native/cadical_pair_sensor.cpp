#include <cadical.hpp>

#include "cadical_tracer_3_0_0.hpp"

#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr const char *kSchema = "o1-256-cadical-paired-proof-probe-v1";
constexpr const char *kHeaderSchema =
    "o1-256-cadical-paired-proof-stream-header-v1";
constexpr const char *kRequiredVersion = "3.0.0";

struct Snapshot {
  int64_t conflicts = -1;
  int64_t decisions = -1;
  int64_t propagations = -1;
  int64_t ticks = -1;
};

struct DerivedEvent {
  int64_t id = 0;
  bool redundant = false;
  int witness = 0;
  bool conclusion_phase = false;
  Snapshot snapshot;
  std::vector<int> clause;
  std::vector<int64_t> antecedents;
};

struct AssumptionClauseEvent {
  int64_t id = 0;
  std::vector<int> clause;
  std::vector<int64_t> antecedents;
};

int64_t statistic(CaDiCaL::Solver *solver, const char *name) {
  if (!solver)
    return -1;
  return solver->get_statistic_value(name);
}

Snapshot snapshot(CaDiCaL::Solver *solver) {
  return {
      statistic(solver, "conflicts"),
      statistic(solver, "decisions"),
      statistic(solver, "propagations"),
      statistic(solver, "ticks"),
  };
}

Snapshot subtract_snapshot(const Snapshot &value, const Snapshot &baseline) {
  return {
      value.conflicts - baseline.conflicts,
      value.decisions - baseline.decisions,
      value.propagations - baseline.propagations,
      value.ticks - baseline.ticks,
  };
}

class ProbeTracer final : public CaDiCaL::Tracer {
public:
  explicit ProbeTracer(CaDiCaL::Solver *solver) : solver_(solver) {}

  void add_original_clause(int64_t id, bool,
                           const std::vector<int> &clause,
                           bool restored) override {
    if (restored)
      throw std::runtime_error("restored original clause before probe");
    if (id <= last_original_id_)
      throw std::runtime_error("non-monotone original clause id");
    last_original_id_ = id;
    ++original_clause_count_;
    original_literal_count_ += clause.size();
  }

  void begin_proof(int64_t first_derived_id) override {
    reserved_original_ids_ = first_derived_id;
  }

  void solve_query() override { solve_query_seen_ = true; }

  void add_assumption(int literal) override {
    assumptions_.push_back(literal);
  }

  void add_derived_clause(int64_t id, bool redundant, int witness,
                          const std::vector<int> &clause,
                          const std::vector<int64_t> &antecedents) override {
    Snapshot current = snapshot(solver_);
    if (baseline_sealed_)
      current = subtract_snapshot(current, baseline_snapshot_);
    events_.push_back({id, redundant, witness, conclusion_phase_,
                       current, clause, antecedents});
  }

  void delete_clause(int64_t, bool, const std::vector<int> &) override {
    ++deleted_clause_count_;
  }

  void demote_clause(uint64_t, const std::vector<int> &) override {
    ++demoted_clause_count_;
  }

  void weaken_minus(int64_t, const std::vector<int> &) override {
    ++weakened_clause_count_;
  }

  void strengthen(int64_t) override { ++strengthened_clause_count_; }

  void report_status(int status, int64_t clause_id) override {
    reported_status_ = status;
    reported_status_clause_id_ = clause_id;
  }

  void reset_assumptions() override { ++assumption_reset_count_; }

  void add_assumption_clause(
      int64_t id, const std::vector<int> &clause,
      const std::vector<int64_t> &antecedents) override {
    assumption_clauses_.push_back({id, clause, antecedents});
  }

  void conclude_unsat(
      CaDiCaL::ConclusionType type,
      const std::vector<int64_t> &clause_ids) override {
    conclusion_type_ = static_cast<int>(type);
    conclusion_clause_ids_ = clause_ids;
  }

  void conclude_sat(const std::vector<int> &model) override {
    conclusion_model_size_ = model.size();
  }

  void conclude_unknown(const std::vector<int> &trail) override {
    conclusion_trail_size_ = trail.size();
  }

  void notify_equivalence(int, int) override { ++equivalence_count_; }

  void start_conclusion() { conclusion_phase_ = true; }

  void seal_public_baseline() {
    if (baseline_sealed_)
      throw std::runtime_error("public baseline already sealed");
    baseline_snapshot_ = snapshot(solver_);
    baseline_events_ = std::move(events_);
    events_.clear();
    deleted_clause_count_ = 0;
    demoted_clause_count_ = 0;
    weakened_clause_count_ = 0;
    strengthened_clause_count_ = 0;
    reported_status_ = -1;
    reported_status_clause_id_ = 0;
    assumption_reset_count_ = 0;
    assumption_clauses_.clear();
    conclusion_type_ = 0;
    conclusion_clause_ids_.clear();
    conclusion_model_size_ = -1;
    conclusion_trail_size_ = -1;
    equivalence_count_ = 0;
    solve_query_seen_ = false;
    conclusion_phase_ = false;
    assumptions_.clear();
    baseline_sealed_ = true;
  }

  int64_t original_clause_count() const { return original_clause_count_; }
  int64_t original_literal_count() const { return original_literal_count_; }
  int64_t last_original_id() const { return last_original_id_; }
  int64_t reserved_original_ids() const { return reserved_original_ids_; }
  const Snapshot &baseline_snapshot() const { return baseline_snapshot_; }
  const std::vector<DerivedEvent> &baseline_events() const {
    return baseline_events_;
  }
  bool solve_query_seen() const { return solve_query_seen_; }
  const std::vector<int> &assumptions() const { return assumptions_; }
  const std::vector<DerivedEvent> &events() const { return events_; }
  int64_t deleted_clause_count() const { return deleted_clause_count_; }
  int64_t demoted_clause_count() const { return demoted_clause_count_; }
  int64_t weakened_clause_count() const { return weakened_clause_count_; }
  int64_t strengthened_clause_count() const {
    return strengthened_clause_count_;
  }
  int reported_status() const { return reported_status_; }
  int64_t reported_status_clause_id() const {
    return reported_status_clause_id_;
  }
  int64_t assumption_reset_count() const { return assumption_reset_count_; }
  int conclusion_type() const { return conclusion_type_; }
  const std::vector<int64_t> &conclusion_clause_ids() const {
    return conclusion_clause_ids_;
  }
  const std::vector<AssumptionClauseEvent> &assumption_clauses() const {
    return assumption_clauses_;
  }
  int64_t conclusion_model_size() const { return conclusion_model_size_; }
  int64_t conclusion_trail_size() const { return conclusion_trail_size_; }
  int64_t equivalence_count() const { return equivalence_count_; }

private:
  CaDiCaL::Solver *solver_;
  int64_t original_clause_count_ = 0;
  int64_t original_literal_count_ = 0;
  int64_t last_original_id_ = 0;
  int64_t reserved_original_ids_ = 0;
  bool baseline_sealed_ = false;
  Snapshot baseline_snapshot_;
  std::vector<DerivedEvent> baseline_events_;
  bool solve_query_seen_ = false;
  bool conclusion_phase_ = false;
  std::vector<int> assumptions_;
  std::vector<DerivedEvent> events_;
  int64_t deleted_clause_count_ = 0;
  int64_t demoted_clause_count_ = 0;
  int64_t weakened_clause_count_ = 0;
  int64_t strengthened_clause_count_ = 0;
  int reported_status_ = -1;
  int64_t reported_status_clause_id_ = 0;
  int64_t assumption_reset_count_ = 0;
  std::vector<AssumptionClauseEvent> assumption_clauses_;
  int conclusion_type_ = 0;
  std::vector<int64_t> conclusion_clause_ids_;
  int64_t conclusion_model_size_ = -1;
  int64_t conclusion_trail_size_ = -1;
  int64_t equivalence_count_ = 0;
};

struct Arguments {
  std::string cnf_path;
  int first_bit = -1;
  int last_bit = -1;
  int conflict_limit = -1;
  int seed = 0;
};

int parse_integer(std::string_view value, const char *field, int minimum,
                  int maximum) {
  if (value.empty())
    throw std::runtime_error(std::string(field) + " is empty");
  const std::string owned(value);
  char *end = nullptr;
  errno = 0;
  const long parsed = std::strtol(owned.c_str(), &end, 10);
  if (errno || !end || *end || parsed < minimum || parsed > maximum)
    throw std::runtime_error(std::string(field) + " is invalid");
  return static_cast<int>(parsed);
}

Arguments parse_arguments(int argc, char **argv) {
  Arguments result;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help") {
      std::cout
          << "usage: cadical_pair_sensor --cnf PATH --first-bit 0 "
             "--last-bit 255 --conflict-limit N [--seed N]\n";
      std::exit(0);
    }
    if (index + 1 >= argc)
      throw std::runtime_error("missing value for " + argument);
    const std::string value = argv[++index];
    if (argument == "--cnf")
      result.cnf_path = value;
    else if (argument == "--first-bit")
      result.first_bit = parse_integer(value, "first-bit", 0, 255);
    else if (argument == "--last-bit")
      result.last_bit = parse_integer(value, "last-bit", 0, 255);
    else if (argument == "--conflict-limit")
      result.conflict_limit =
          parse_integer(value, "conflict-limit", 1, 1000000000);
    else if (argument == "--seed")
      result.seed = parse_integer(value, "seed", 0, 2000000000);
    else
      throw std::runtime_error("unknown argument " + argument);
  }
  if (result.cnf_path.empty() || result.first_bit < 0 ||
      result.last_bit < result.first_bit || result.conflict_limit < 1)
    throw std::runtime_error("required arguments are missing or inconsistent");
  return result;
}

template <typename T>
void append_array(std::ostringstream &out, const std::vector<T> &values) {
  out << '[';
  bool first = true;
  for (const auto value : values) {
    if (!first)
      out << ',';
    first = false;
    out << value;
  }
  out << ']';
}

int64_t peak_rss_bytes() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return -1;
#ifdef __APPLE__
  return static_cast<int64_t>(usage.ru_maxrss);
#else
  return static_cast<int64_t>(usage.ru_maxrss) * 1024;
#endif
}

int64_t cpu_microseconds() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return -1;
  return static_cast<int64_t>(usage.ru_utime.tv_sec) * 1000000 +
         usage.ru_utime.tv_usec +
         static_cast<int64_t>(usage.ru_stime.tv_sec) * 1000000 +
         usage.ru_stime.tv_usec;
}

void append_snapshot(std::ostringstream &out, const Snapshot &value) {
  out << "{\"conflicts\":" << value.conflicts
      << ",\"decisions\":" << value.decisions
      << ",\"propagations\":" << value.propagations
      << ",\"ticks\":" << value.ticks << '}';
}

void append_stats(std::ostringstream &out, CaDiCaL::Solver &solver,
                  const Snapshot &baseline) {
  const Snapshot delta = subtract_snapshot(snapshot(&solver), baseline);
  append_snapshot(out, delta);
}

void append_events(std::ostringstream &out,
                   const std::vector<DerivedEvent> &events,
                   int64_t maximum_conflicts = -1) {
  out << '[';
  bool first_event = true;
  for (const DerivedEvent &event : events) {
    if (maximum_conflicts >= 0 &&
        event.snapshot.conflicts > maximum_conflicts)
      continue;
    if (!first_event)
      out << ',';
    first_event = false;
    out << "{\"id\":" << event.id << ",\"redundant\":"
        << (event.redundant ? "true" : "false")
        << ",\"witness\":" << event.witness
        << ",\"conclusion_phase\":"
        << (event.conclusion_phase ? "true" : "false")
        << ",\"snapshot\":";
    append_snapshot(out, event.snapshot);
    out << ",\"clause\":";
    append_array(out, event.clause);
    out << ",\"antecedents\":";
    append_array(out, event.antecedents);
    out << '}';
  }
  out << ']';
}

void append_assumption_clauses(
    std::ostringstream &out,
    const std::vector<AssumptionClauseEvent> &events) {
  out << '[';
  bool first = true;
  for (const AssumptionClauseEvent &event : events) {
    if (!first)
      out << ',';
    first = false;
    out << "{\"id\":" << event.id << ",\"clause\":";
    append_array(out, event.clause);
    out << ",\"antecedents\":";
    append_array(out, event.antecedents);
    out << '}';
  }
  out << ']';
}

std::string render_probe(CaDiCaL::Solver &solver, const ProbeTracer &tracer,
                         int bit_index, int assumed_value,
                         int requested_conflict_limit, int status,
                         int64_t wall_microseconds) {
  std::ostringstream out;
  out << "{\"schema\":\"" << kSchema << "\",\"bit_index\":"
      << bit_index << ",\"assumed_value\":" << assumed_value
      << ",\"assumption_literal\":"
      << (assumed_value ? bit_index + 1 : -(bit_index + 1))
      << ",\"requested_conflict_horizon\":" << requested_conflict_limit
      << ",\"status\":" << status << ",\"reported_status\":"
      << tracer.reported_status()
      << ",\"reported_status_clause_id\":"
      << tracer.reported_status_clause_id()
      << ",\"solve_query_seen\":"
      << (tracer.solve_query_seen() ? "true" : "false")
      << ",\"assumptions\":";
  append_array(out, tracer.assumptions());
  out << ",\"original_clause_count\":" << tracer.original_clause_count()
      << ",\"original_literal_count\":" << tracer.original_literal_count()
      << ",\"last_original_id\":" << tracer.last_original_id()
      << ",\"reserved_original_ids\":" << tracer.reserved_original_ids()
      << ",\"stats\":";
  append_stats(out, solver, tracer.baseline_snapshot());
  const Snapshot final_work =
      subtract_snapshot(snapshot(&solver), tracer.baseline_snapshot());
  out << ",\"final_overshoot_conflicts\":"
      << (final_work.conflicts - requested_conflict_limit);
  out << ",\"proof_counters\":{\"deleted\":"
      << tracer.deleted_clause_count() << ",\"demoted\":"
      << tracer.demoted_clause_count() << ",\"weakened\":"
      << tracer.weakened_clause_count() << ",\"strengthened\":"
      << tracer.strengthened_clause_count() << ",\"equivalences\":"
      << tracer.equivalence_count() << ",\"assumption_resets\":"
      << tracer.assumption_reset_count() << "},\"conclusion\":{\"type\":"
      << tracer.conclusion_type() << ",\"clause_ids\":";
  append_array(out, tracer.conclusion_clause_ids());
  out << ",\"model_size\":" << tracer.conclusion_model_size()
      << ",\"trail_size\":" << tracer.conclusion_trail_size()
      << "},\"assumption_clauses\":";
  append_assumption_clauses(out, tracer.assumption_clauses());
  out << ",\"resources\":{\"solver_cpu_microseconds\":"
      << cpu_microseconds()
      << ",\"solver_wall_microseconds\":" << wall_microseconds
      << ",\"solver_peak_rss_bytes\":" << peak_rss_bytes()
      << "},\"events\":";
  append_events(out, tracer.events(), requested_conflict_limit);
  out << "}\n";
  return out.str();
}

void write_all(int descriptor, const std::string &value) {
  size_t offset = 0;
  while (offset < value.size()) {
    const ssize_t written =
        ::write(descriptor, value.data() + offset, value.size() - offset);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      throw std::runtime_error(std::string("write failed: ") +
                               std::strerror(errno));
    }
    offset += static_cast<size_t>(written);
  }
}

int run_probe_child(CaDiCaL::Solver &solver, ProbeTracer &tracer,
                    int bit_index, int assumed_value, int conflict_limit) {
  const int literal = assumed_value ? bit_index + 1 : -(bit_index + 1);
  const auto started = std::chrono::steady_clock::now();
  solver.assume(literal);
  if (!solver.limit("conflicts", conflict_limit))
    throw std::runtime_error("CaDiCaL rejected conflict limit");
  const int status = solver.solve();
  const Snapshot realized =
      subtract_snapshot(snapshot(&solver), tracer.baseline_snapshot());
  if (status == 0 && realized.conflicts < conflict_limit)
    throw std::runtime_error("CaDiCaL stopped before requested conflict horizon");
  tracer.start_conclusion();
  solver.conclude();
  const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - started);
  write_all(STDOUT_FILENO,
            render_probe(solver, tracer, bit_index, assumed_value,
                         conflict_limit, status, elapsed.count()));
  return 0;
}

std::string render_header(const Arguments &arguments, int variables,
                          const ProbeTracer &tracer) {
  std::ostringstream out;
  out << "{\"schema\":\"" << kHeaderSchema
      << "\",\"probe_schema\":\"" << kSchema
      << "\",\"cadical_version\":\"" << CaDiCaL::Solver::version()
      << "\",\"cnf_path\":\"";
  for (const char character : arguments.cnf_path) {
    if (character == '\\' || character == '"')
      out << '\\';
    out << character;
  }
  out << "\",\"variables\":" << variables
      << ",\"original_clause_count\":" << tracer.original_clause_count()
      << ",\"original_literal_count\":" << tracer.original_literal_count()
      << ",\"last_original_id\":" << tracer.last_original_id()
      << ",\"reserved_original_ids\":" << tracer.reserved_original_ids()
      << ",\"public_propagation_status\":0"
      << ",\"baseline_stats\":";
  append_snapshot(out, tracer.baseline_snapshot());
  out << ",\"baseline_events\":";
  append_events(out, tracer.baseline_events());
  out
      << ",\"first_bit\":" << arguments.first_bit
      << ",\"last_bit\":" << arguments.last_bit
      << ",\"conflict_horizon\":" << arguments.conflict_limit
      << ",\"seed\":" << arguments.seed
      << ",\"branch_isolation\":\"single-threaded-posix-fork-cow\"}\n";
  return out.str();
}

} // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    if (std::string(CaDiCaL::Solver::version()) != kRequiredVersion)
      throw std::runtime_error("CaDiCaL runtime must be exactly 3.0.0");

    CaDiCaL::Solver solver;
    if (!solver.configure("plain"))
      throw std::runtime_error("CaDiCaL rejected plain configuration");
    if (!solver.set("seed", arguments.seed) || !solver.set("quiet", 1) ||
        !solver.set("factor", 0) || !solver.set("lucky", 0) ||
        !solver.set("walk", 0))
      throw std::runtime_error("CaDiCaL rejected deterministic options");
    // CaDiCaL owns and deletes a connected tracer with the solver.  Keep it on
    // the heap in the pristine parent; forked children use _exit and therefore
    // never race or double-delete the inherited object.
    auto *tracer = new ProbeTracer(&solver);
    solver.connect_proof_tracer(tracer, true, false);
    int variables = 0;
    if (const char *error =
            solver.read_dimacs(arguments.cnf_path.c_str(), variables, 2))
      throw std::runtime_error(std::string("DIMACS read failed: ") + error);
    if (tracer->original_clause_count() != tracer->last_original_id())
      throw std::runtime_error("original clause IDs are not contiguous");
    if (tracer->reserved_original_ids() != tracer->last_original_id())
      throw std::runtime_error("reserved proof-ID boundary differs");
    const int propagation_status = solver.propagate();
    if (propagation_status != 0)
      throw std::runtime_error("public-only propagation reached terminal status");
    tracer->seal_public_baseline();

    write_all(STDOUT_FILENO, render_header(arguments, variables, *tracer));
    for (int bit = arguments.first_bit; bit <= arguments.last_bit; ++bit) {
      for (int value = 0; value <= 1; ++value) {
        const pid_t child = ::fork();
        if (child < 0)
          throw std::runtime_error(std::string("fork failed: ") +
                                   std::strerror(errno));
        if (!child) {
          try {
            const int result = run_probe_child(
                solver, *tracer, bit, value, arguments.conflict_limit);
            _exit(result);
          } catch (const std::exception &error) {
            std::ostringstream message;
            message << "{\"schema\":\"o1-256-cadical-paired-proof-error-v1\""
                    << ",\"bit_index\":" << bit
                    << ",\"assumed_value\":" << value
                    << ",\"error\":\"child probe failed\"}\n";
            try {
              write_all(STDOUT_FILENO, message.str());
              write_all(STDERR_FILENO,
                        std::string("probe child: ") + error.what() + "\n");
            } catch (...) {
            }
            _exit(2);
          }
        }
        int status = 0;
        while (::waitpid(child, &status, 0) < 0) {
          if (errno != EINTR)
            throw std::runtime_error(std::string("waitpid failed: ") +
                                     std::strerror(errno));
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
          throw std::runtime_error("probe child failed");
      }
    }
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_pair_sensor: " << error.what() << '\n';
    return 1;
  }
}
