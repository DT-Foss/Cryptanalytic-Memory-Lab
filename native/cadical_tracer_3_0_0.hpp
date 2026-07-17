#ifndef O1_CRYPTO_LAB_CADICAL_TRACER_3_0_0_HPP
#define O1_CRYPTO_LAB_CADICAL_TRACER_3_0_0_HPP

// ABI mirror of CaDiCaL 3.0.0's public Tracer interface.  Homebrew installs
// cadical.hpp but not tracer.hpp, even though cadical.hpp exposes
// Solver::connect_proof_tracer.  Keep this mirror version-pinned and reject any
// other runtime signature in the sensor before connecting it.
//
// Upstream: https://github.com/arminbiere/cadical, src/tracer.hpp, rel-3.0.0.
// CaDiCaL is distributed under the MIT license.

#include <cstdint>
#include <vector>

namespace CaDiCaL {

struct Internal;

enum ConclusionType { CONFLICT = 1, ASSUMPTIONS = 2, CONSTRAINT = 4 };

class Tracer {
public:
  Tracer() {}
  virtual ~Tracer() {}

  virtual void add_original_clause(int64_t, bool, const std::vector<int> &,
                                   bool = false) {}
  virtual void add_derived_clause(int64_t, bool, int,
                                  const std::vector<int> &,
                                  const std::vector<int64_t> &) {}
  virtual void delete_clause(int64_t, bool, const std::vector<int> &) {}
  virtual void demote_clause(uint64_t, const std::vector<int> &) {}
  virtual void weaken_minus(int64_t, const std::vector<int> &) {}
  virtual void strengthen(int64_t) {}
  virtual void report_status(int, int64_t) {}

  virtual void finalize_clause(int64_t, const std::vector<int> &) {}
  virtual void begin_proof(int64_t) {}

  virtual void solve_query() {}
  virtual void add_assumption(int) {}
  virtual void add_constraint(const std::vector<int> &) {}
  virtual void reset_assumptions() {}
  virtual void add_assumption_clause(int64_t, const std::vector<int> &,
                                     const std::vector<int64_t> &) {}
  virtual void conclude_unsat(ConclusionType,
                              const std::vector<int64_t> &) {}
  virtual void conclude_sat(const std::vector<int> &) {}
  virtual void conclude_unknown(const std::vector<int> &) {}
  virtual void notify_equivalence(int, int) {}
};

} // namespace CaDiCaL

#endif
