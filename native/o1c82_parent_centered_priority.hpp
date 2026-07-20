#ifndef O1_CRYPTO_LAB_O1C82_PARENT_CENTERED_PRIORITY_HPP
#define O1_CRYPTO_LAB_O1C82_PARENT_CENTERED_PRIORITY_HPP

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace o1c82 {

inline constexpr size_t kCoordinateCount = 256U;
inline constexpr uint64_t kMinimumEligibleCount = 37U;
inline constexpr double kNormalMadScale = 1.4826;
inline constexpr double kRobustScaleFloor = 0x1p-40;
inline constexpr size_t kPackedCoordinateBytes = 96U;
inline constexpr size_t kCoordinateBankBytes =
    kCoordinateCount * kPackedCoordinateBytes;
inline constexpr size_t kParentScratchEntryBytes = 16U;
inline constexpr size_t kParentScratchBytes =
    kCoordinateCount * kParentScratchEntryBytes;
inline constexpr size_t kLiveStateBytes =
    kCoordinateBankBytes + kParentScratchBytes;
inline constexpr std::string_view kSeedMagic = "O1C82-PCP-SEED1";
inline constexpr std::string_view kSeedSchema =
    "o1-256-o1c82-parent-centered-priority-seed-v1";
inline constexpr std::string_view kTelemetrySchema =
    "o1-256-o1c82-parent-centered-priority-telemetry-v1";

struct BoundPair {
  int variable = 0;
  double upper_zero = 0.0;
  double upper_one = 0.0;
};

// The order of these twelve binary64-width fields is the seed wire order.
// Integer counters deliberately occupy a full eight bytes, so every record is
// byte-for-byte compatible with O1C81's packed accounting.
struct CoordinateAccumulator {
  uint64_t count = 0;
  double raw_mean = 0.0;
  double raw_m2 = 0.0;
  uint64_t raw_positive_count = 0;
  uint64_t raw_zero_count = 0;
  double centered_mean = 0.0;
  double centered_m2 = 0.0;
  uint64_t centered_positive_count = 0;
  uint64_t centered_zero_count = 0;
  double robust_z_mean = 0.0;
  double robust_abs_z_mean = 0.0;
  double robust_abs_z_max = 0.0;
};

static_assert(std::is_standard_layout<CoordinateAccumulator>::value,
              "O1C82 coordinate record must have standard layout");
static_assert(sizeof(CoordinateAccumulator) == kPackedCoordinateBytes,
              "O1C82 coordinate record accounting differs");
static_assert(offsetof(CoordinateAccumulator, count) == 0U &&
                  offsetof(CoordinateAccumulator, raw_mean) == 8U &&
                  offsetof(CoordinateAccumulator, raw_m2) == 16U &&
                  offsetof(CoordinateAccumulator, raw_positive_count) == 24U &&
                  offsetof(CoordinateAccumulator, raw_zero_count) == 32U &&
                  offsetof(CoordinateAccumulator, centered_mean) == 40U &&
                  offsetof(CoordinateAccumulator, centered_m2) == 48U &&
                  offsetof(CoordinateAccumulator, centered_positive_count) ==
                      56U &&
                  offsetof(CoordinateAccumulator, centered_zero_count) == 64U &&
                  offsetof(CoordinateAccumulator, robust_z_mean) == 72U &&
                  offsetof(CoordinateAccumulator, robust_abs_z_mean) == 80U &&
                  offsetof(CoordinateAccumulator, robust_abs_z_max) == 88U,
              "O1C82 coordinate field offsets differ");

struct ParentScratchEntry {
  double differential = 0.0;
  uint64_t present = 0;
};

static_assert(sizeof(ParentScratchEntry) == kParentScratchEntryBytes,
              "O1C82 parent scratch entry accounting differs");

struct CoordinateReport {
  int variable = 0;
  uint64_t count = 0;
  double raw_mean = 0.0;
  double raw_variance = 0.0;
  double raw_positive_fraction = 0.0;
  double raw_negative_fraction = 0.0;
  double raw_zero_fraction = 0.0;
  double raw_directional_stability = 0.0;
  double centered_mean = 0.0;
  double centered_variance = 0.0;
  double centered_positive_fraction = 0.0;
  double centered_negative_fraction = 0.0;
  double centered_zero_fraction = 0.0;
  double centered_directional_stability = 0.0;
  double centered_signed_consistency = 0.0;
  double robust_z_mean = 0.0;
  double robust_abs_z_mean = 0.0;
  double robust_abs_z_max = 0.0;
  double priority = 0.0;
  bool eligible = false;
};

struct SelectionResult {
  bool available = false;
  int variable = 0;
  int action_literal = 0;
  double current_differential = 0.0;
  CoordinateReport coordinate;
  // These are contract markers, not learned state.
  bool proof_mining_action = true;
  bool belief_orientation_authorized = false;
};

struct ParentUpdateResult {
  size_t candidate_count = 0;
  double parent_median = 0.0;
  double parent_mad = 0.0;
  double robust_scale = kRobustScaleFloor;
  SelectionResult selection;
};

using PackedCoordinateBank = std::array<uint8_t, kCoordinateBankBytes>;

struct SeedImage {
  std::string magic;
  std::string schema;
  std::string payload_sha256;
  PackedCoordinateBank records{};
};

namespace detail {

inline uint32_t rotate_right(uint32_t value, unsigned count) {
  return (value >> count) | (value << (32U - count));
}

inline std::string sha256_hex(const uint8_t *input, size_t input_size) {
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
  if (input_size && !input)
    throw std::runtime_error("O1C82 SHA-256 input is null");
  if (input_size > (std::numeric_limits<uint64_t>::max() - 9U) / 8U)
    throw std::runtime_error("O1C82 SHA-256 input is too large");
  std::vector<uint8_t> message;
  message.reserve(input_size + 72U);
  if (input_size)
    message.insert(message.end(), input, input + input_size);
  const uint64_t bit_length = static_cast<uint64_t>(input_size) * 8U;
  message.push_back(0x80U);
  while (message.size() % 64U != 56U)
    message.push_back(0U);
  for (int shift = 56; shift >= 0; shift -= 8)
    message.push_back(static_cast<uint8_t>(bit_length >> shift));

  std::array<uint32_t, 8> state = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  for (size_t offset = 0; offset < message.size(); offset += 64U) {
    std::array<uint32_t, 64> words{};
    for (size_t index = 0; index < 16U; ++index) {
      const size_t position = offset + 4U * index;
      words[index] = static_cast<uint32_t>(message[position]) << 24U |
                     static_cast<uint32_t>(message[position + 1U]) << 16U |
                     static_cast<uint32_t>(message[position + 2U]) << 8U |
                     static_cast<uint32_t>(message[position + 3U]);
    }
    for (size_t index = 16U; index < words.size(); ++index) {
      const uint32_t x = words[index - 15U];
      const uint32_t y = words[index - 2U];
      const uint32_t sigma0 =
          rotate_right(x, 7U) ^ rotate_right(x, 18U) ^ (x >> 3U);
      const uint32_t sigma1 =
          rotate_right(y, 17U) ^ rotate_right(y, 19U) ^ (y >> 10U);
      words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
    }
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];
    for (size_t index = 0; index < words.size(); ++index) {
      const uint32_t sum1 =
          rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
      const uint32_t choose = (e & f) ^ (~e & g);
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
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  }
  static constexpr char hex[] = "0123456789abcdef";
  std::string result(64U, '0');
  size_t cursor = 0;
  for (const uint32_t word : state) {
    for (int shift = 28; shift >= 0; shift -= 4)
      result[cursor++] = hex[(word >> shift) & 0xfU];
  }
  return result;
}

inline void store_u64_le(uint8_t *destination, uint64_t value) {
  for (unsigned index = 0; index < 8U; ++index)
    destination[index] = static_cast<uint8_t>(value >> (8U * index));
}

inline uint64_t load_u64_le(const uint8_t *source) {
  uint64_t result = 0;
  for (unsigned index = 0; index < 8U; ++index)
    result |= static_cast<uint64_t>(source[index]) << (8U * index);
  return result;
}

inline void store_double_le(uint8_t *destination, double value) {
  uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value), "binary64 width differs");
  std::memcpy(&bits, &value, sizeof(bits));
  store_u64_le(destination, bits);
}

inline double load_double_le(const uint8_t *source) {
  const uint64_t bits = load_u64_le(source);
  double result = 0.0;
  std::memcpy(&result, &bits, sizeof(result));
  return result;
}

inline bool finite_accumulator(const CoordinateAccumulator &state) {
  return std::isfinite(state.raw_mean) && std::isfinite(state.raw_m2) &&
         std::isfinite(state.centered_mean) &&
         std::isfinite(state.centered_m2) &&
         std::isfinite(state.robust_z_mean) &&
         std::isfinite(state.robust_abs_z_mean) &&
         std::isfinite(state.robust_abs_z_max);
}

} // namespace detail

class ParentCenteredPriority final {
public:
  ParentCenteredPriority() = default;

  void reset() noexcept {
    bank_ = {};
    scratch_ = {};
  }

  void clear_current_parent() noexcept { scratch_ = {}; }

  const CoordinateAccumulator &accumulator(int variable) const {
    return bank_.at(variable_index(variable));
  }

  CoordinateReport coordinate_report(int variable) const {
    return make_report(variable, accumulator(variable));
  }

  static int lower_upper_bound_action_literal(int variable, double upper_zero,
                                              double upper_one) {
    (void)variable_index(variable);
    if (!std::isfinite(upper_zero) || !std::isfinite(upper_one))
      throw std::runtime_error("O1C82 action bound is non-finite");
    // Exact ties intentionally choose bit 0, encoded as literal -v.
    return upper_zero <= upper_one ? -variable : variable;
  }

  ParentUpdateResult observe_parent(const BoundPair *batch, size_t batch_size,
                                    const int *expected_candidates,
                                    size_t expected_count) {
    validate_batch(batch, batch_size, expected_candidates, expected_count);

    std::array<double, kCoordinateCount> work{};
    for (size_t index = 0; index < batch_size; ++index)
      work[index] = batch[index].upper_zero - batch[index].upper_one;
    std::sort(work.begin(), work.begin() + static_cast<ptrdiff_t>(batch_size));
    const double parent_median = sorted_median(work, batch_size);
    for (size_t index = 0; index < batch_size; ++index) {
      work[index] = std::abs(work[index] - parent_median);
      if (!std::isfinite(work[index]))
        throw std::runtime_error("O1C82 parent absolute deviation is non-finite");
    }
    std::sort(work.begin(), work.begin() + static_cast<ptrdiff_t>(batch_size));
    const double parent_mad = sorted_median(work, batch_size);
    const double scaled_mad = kNormalMadScale * parent_mad;
    if (!std::isfinite(scaled_mad))
      throw std::runtime_error("O1C82 parent robust scale is non-finite");
    const double robust_scale = std::max(scaled_mad, kRobustScaleFloor);

    // Complete the numerical preflight before touching either live region.
    for (size_t index = 0; index < batch_size; ++index) {
      const BoundPair &observation = batch[index];
      const double raw = observation.upper_zero - observation.upper_one;
      const double centered = raw - parent_median;
      const double robust_z = centered / robust_scale;
      if (!std::isfinite(centered) || !std::isfinite(robust_z))
        throw std::runtime_error("O1C82 centered differential is non-finite");
      (void)next_accumulator(bank_[static_cast<size_t>(observation.variable - 1)],
                             raw, centered, robust_z);
    }

    for (ParentScratchEntry &entry : scratch_)
      entry = {};
    for (size_t index = 0; index < batch_size; ++index) {
      const BoundPair &observation = batch[index];
      const size_t coordinate = static_cast<size_t>(observation.variable - 1);
      const double raw = observation.upper_zero - observation.upper_one;
      const double centered = raw - parent_median;
      const double robust_z = centered / robust_scale;
      bank_[coordinate] =
          next_accumulator(bank_[coordinate], raw, centered, robust_z);
      scratch_[coordinate] = {raw, 1U};
    }

    ParentUpdateResult result;
    result.candidate_count = batch_size;
    result.parent_median = parent_median;
    result.parent_mad = parent_mad;
    result.robust_scale = robust_scale;
    result.selection = select_current_parent();
    return result;
  }

  ParentUpdateResult observe_parent(const std::vector<BoundPair> &batch,
                                    const std::vector<int> &expected_candidates) {
    return observe_parent(batch.data(), batch.size(), expected_candidates.data(),
                          expected_candidates.size());
  }

  template <size_t BatchSize, size_t ExpectedSize>
  ParentUpdateResult
  observe_parent(const std::array<BoundPair, BatchSize> &batch,
                 const std::array<int, ExpectedSize> &expected_candidates) {
    return observe_parent(batch.data(), batch.size(), expected_candidates.data(),
                          expected_candidates.size());
  }

  SelectionResult select_current_parent() const {
    const std::array<bool, kCoordinateCount> excluded{};
    return select_current_parent(excluded);
  }

  // One-shot ownership stays outside this statistical bank.  Callers may
  // exclude consumed coordinates without changing counts, moments, or the
  // current-parent scratch values.
  SelectionResult select_current_parent(
      const std::array<bool, kCoordinateCount> &excluded) const {
    SelectionResult result;
    for (size_t coordinate = 0; coordinate < kCoordinateCount; ++coordinate) {
      if (excluded[coordinate] || !scratch_[coordinate].present ||
          bank_[coordinate].count < kMinimumEligibleCount)
        continue;
      const CoordinateReport candidate =
          make_report(static_cast<int>(coordinate + 1U), bank_[coordinate]);
      if (!result.available || better(candidate, result.coordinate)) {
        result.available = true;
        result.variable = candidate.variable;
        result.current_differential = scratch_[coordinate].differential;
        result.action_literal = result.current_differential <= 0.0
                                    ? -result.variable
                                    : result.variable;
        result.coordinate = candidate;
      }
    }
    return result;
  }

  bool current_parent_contains(int variable) const {
    return scratch_[variable_index(variable)].present != 0U;
  }

  double current_parent_differential(int variable) const {
    const ParentScratchEntry &entry = scratch_[variable_index(variable)];
    if (!entry.present)
      throw std::runtime_error("O1C82 variable is absent from current parent");
    return entry.differential;
  }

  std::vector<CoordinateReport>
  ranked_priorities(bool current_parent_only = false) const {
    std::vector<CoordinateReport> result;
    result.reserve(kCoordinateCount);
    for (size_t coordinate = 0; coordinate < kCoordinateCount; ++coordinate) {
      if (bank_[coordinate].count < kMinimumEligibleCount ||
          (current_parent_only && !scratch_[coordinate].present))
        continue;
      result.push_back(
          make_report(static_cast<int>(coordinate + 1U), bank_[coordinate]));
    }
    std::sort(result.begin(), result.end(), better);
    return result;
  }

  size_t eligible_coordinate_count() const noexcept {
    return static_cast<size_t>(std::count_if(
        bank_.begin(), bank_.end(), [](const CoordinateAccumulator &state) {
          return state.count >= kMinimumEligibleCount;
        }));
  }

  size_t current_candidate_count() const noexcept {
    return static_cast<size_t>(std::count_if(
        scratch_.begin(), scratch_.end(),
        [](const ParentScratchEntry &entry) { return entry.present != 0U; }));
  }

  PackedCoordinateBank export_packed_bank() const {
    PackedCoordinateBank result{};
    for (size_t coordinate = 0; coordinate < kCoordinateCount; ++coordinate)
      encode_record(bank_[coordinate], result.data() +
                                           coordinate * kPackedCoordinateBytes);
    return result;
  }

  SeedImage export_seed() const {
    SeedImage result;
    result.magic = std::string(kSeedMagic);
    result.schema = std::string(kSeedSchema);
    result.records = export_packed_bank();
    result.payload_sha256 = seed_payload_sha256(result.records);
    return result;
  }

  static std::string seed_payload_sha256(const PackedCoordinateBank &records) {
    return detail::sha256_hex(records.data(), records.size());
  }

  void import_seed(const SeedImage &seed) {
    import_seed(seed.magic, seed.schema, seed.payload_sha256, seed.records.data(),
                seed.records.size());
  }

  void import_seed(std::string_view magic, std::string_view schema,
                   std::string_view payload_sha256, const uint8_t *records,
                   size_t record_bytes) {
    if (magic != kSeedMagic)
      throw std::runtime_error("O1C82 seed magic differs");
    if (schema != kSeedSchema)
      throw std::runtime_error("O1C82 seed schema differs");
    if (record_bytes != kCoordinateBankBytes)
      throw std::runtime_error("O1C82 seed record byte count differs");
    if (!records)
      throw std::runtime_error("O1C82 seed records are null");
    if (payload_sha256.size() != 64U ||
        !std::all_of(payload_sha256.begin(), payload_sha256.end(), [](char value) {
          return (value >= '0' && value <= '9') ||
                 (value >= 'a' && value <= 'f');
        }))
      throw std::runtime_error("O1C82 seed digest encoding differs");
    if (detail::sha256_hex(records, record_bytes) != payload_sha256)
      throw std::runtime_error("O1C82 seed digest differs");

    std::array<CoordinateAccumulator, kCoordinateCount> staged{};
    for (size_t coordinate = 0; coordinate < kCoordinateCount; ++coordinate) {
      staged[coordinate] = decode_record(
          records + coordinate * kPackedCoordinateBytes);
      validate_accumulator(staged[coordinate]);
    }
    bank_ = staged;
    scratch_ = {};
  }

  static void write_coordinate_json(std::ostream &out,
                                    const CoordinateReport &row) {
    const std::streamsize precision = out.precision();
    out << std::setprecision(std::numeric_limits<double>::max_digits10)
        << "{\"variable\":" << row.variable << ",\"count\":" << row.count
        << ",\"eligible\":" << (row.eligible ? "true" : "false");
    if (!row.count) {
      out << ",\"raw_mean\":null,\"raw_variance\":null"
             ",\"raw_positive_fraction\":null"
             ",\"raw_negative_fraction\":null,\"raw_zero_fraction\":null"
             ",\"raw_directional_stability\":null"
             ",\"centered_mean\":null,\"centered_variance\":null"
             ",\"centered_positive_fraction\":null"
             ",\"centered_negative_fraction\":null"
             ",\"centered_zero_fraction\":null"
             ",\"centered_directional_stability\":null"
             ",\"centered_signed_consistency\":null"
             ",\"robust_z_mean\":null,\"robust_abs_z_mean\":null"
             ",\"robust_abs_z_max\":null,\"priority\":null}";
      out.precision(precision);
      return;
    }
    out << ",\"raw_mean\":" << row.raw_mean
        << ",\"raw_variance\":" << row.raw_variance
        << ",\"raw_positive_fraction\":" << row.raw_positive_fraction
        << ",\"raw_negative_fraction\":" << row.raw_negative_fraction
        << ",\"raw_zero_fraction\":" << row.raw_zero_fraction
        << ",\"raw_directional_stability\":"
        << row.raw_directional_stability
        << ",\"centered_mean\":" << row.centered_mean
        << ",\"centered_variance\":" << row.centered_variance
        << ",\"centered_positive_fraction\":"
        << row.centered_positive_fraction
        << ",\"centered_negative_fraction\":"
        << row.centered_negative_fraction
        << ",\"centered_zero_fraction\":" << row.centered_zero_fraction
        << ",\"centered_directional_stability\":"
        << row.centered_directional_stability
        << ",\"centered_signed_consistency\":"
        << row.centered_signed_consistency
        << ",\"robust_z_mean\":" << row.robust_z_mean
        << ",\"robust_abs_z_mean\":" << row.robust_abs_z_mean
        << ",\"robust_abs_z_max\":" << row.robust_abs_z_max
        << ",\"priority\":" << row.priority << '}';
    out.precision(precision);
  }

  static void write_selection_json(std::ostream &out,
                                   const SelectionResult &selection) {
    const std::streamsize precision = out.precision();
    out << std::setprecision(std::numeric_limits<double>::max_digits10)
        << "{\"available\":" << (selection.available ? "true" : "false")
        << ",\"proof_mining_action\":true"
           ",\"belief_orientation_authorized\":false";
    if (!selection.available) {
      out << ",\"variable\":null,\"action_literal\":null"
             ",\"current_differential\":null,\"coordinate\":null}";
      out.precision(precision);
      return;
    }
    out << ",\"variable\":" << selection.variable
        << ",\"action_literal\":" << selection.action_literal
        << ",\"current_differential\":"
        << selection.current_differential << ",\"coordinate\":";
    write_coordinate_json(out, selection.coordinate);
    out << '}';
    out.precision(precision);
  }

  void write_json(std::ostream &out) const {
    out << "{\"schema\":\"" << kTelemetrySchema
        << "\",\"coordinate_capacity\":" << kCoordinateCount
        << ",\"minimum_eligible_count\":" << kMinimumEligibleCount
        << ",\"eligible_coordinate_count\":" << eligible_coordinate_count()
        << ",\"current_parent_candidate_count\":"
        << current_candidate_count()
        << ",\"priority_order\":\"score-desc,count-desc,variable-asc\""
           ",\"action_semantics\":\"current-lower-upper-bound-proof-mining\""
           ",\"proof_mining_action_only\":true"
           ",\"belief_orientation_authorized\":false"
           ",\"selection\":";
    write_selection_json(out, select_current_parent());
    out << ",\"state_accounting\":{\"packed_bytes_per_coordinate\":"
        << kPackedCoordinateBytes << ",\"coordinate_state_bytes\":"
        << kCoordinateBankBytes << ",\"parent_scratch_bytes\":"
        << kParentScratchBytes << ",\"live_packed_state_bytes\":"
        << kLiveStateBytes << "}}";
  }

private:
  static size_t variable_index(int variable) {
    if (variable < 1 || variable > static_cast<int>(kCoordinateCount))
      throw std::runtime_error("O1C82 variable is out of range");
    return static_cast<size_t>(variable - 1);
  }

  static double sorted_median(
      const std::array<double, kCoordinateCount> &values, size_t size) {
    if (!size || size > values.size())
      throw std::runtime_error("O1C82 median population differs");
    const size_t middle = size / 2U;
    if (size & 1U)
      return values[middle];
    // Preserve O1C81/Python's binary64 evaluation order for exact seed/state
    // reproduction.  An unrepresentable midpoint is rejected transactionally.
    const double result = (values[middle - 1U] + values[middle]) / 2.0;
    if (!std::isfinite(result))
      throw std::runtime_error("O1C82 parent median is non-finite");
    return result;
  }

  static void validate_batch(const BoundPair *batch, size_t batch_size,
                             const int *expected_candidates,
                             size_t expected_count) {
    if (!batch_size || !expected_count)
      throw std::runtime_error("O1C82 parent candidate set is empty");
    if (batch_size > kCoordinateCount || expected_count > kCoordinateCount)
      throw std::runtime_error("O1C82 parent candidate count is out of range");
    if (!batch || !expected_candidates)
      throw std::runtime_error("O1C82 parent candidate input is null");
    std::array<bool, kCoordinateCount> expected{};
    std::array<bool, kCoordinateCount> observed{};
    for (size_t index = 0; index < expected_count; ++index) {
      const size_t coordinate = variable_index(expected_candidates[index]);
      if (expected[coordinate])
        throw std::runtime_error("O1C82 expected candidate is duplicated");
      expected[coordinate] = true;
    }
    for (size_t index = 0; index < batch_size; ++index) {
      const BoundPair &observation = batch[index];
      const size_t coordinate = variable_index(observation.variable);
      if (!std::isfinite(observation.upper_zero) ||
          !std::isfinite(observation.upper_one))
        throw std::runtime_error("O1C82 parent bound is non-finite");
      const double differential =
          observation.upper_zero - observation.upper_one;
      if (!std::isfinite(differential))
        throw std::runtime_error("O1C82 parent differential is non-finite");
      if (observed[coordinate])
        throw std::runtime_error("O1C82 parent candidate is duplicated");
      if (!expected[coordinate])
        throw std::runtime_error("O1C82 parent candidate is unexpected");
      observed[coordinate] = true;
    }
    if (batch_size != expected_count || observed != expected)
      throw std::runtime_error("O1C82 parent batch is missing a candidate");
  }

  static CoordinateAccumulator
  next_accumulator(const CoordinateAccumulator &previous, double raw,
                   double centered, double robust_z) {
    if (previous.count == std::numeric_limits<uint64_t>::max())
      throw std::runtime_error("O1C82 coordinate count overflow");
    CoordinateAccumulator result = previous;
    ++result.count;
    const double count = static_cast<double>(result.count);
    const double raw_delta = raw - result.raw_mean;
    result.raw_mean += raw_delta / count;
    result.raw_m2 += raw_delta * (raw - result.raw_mean);
    if (raw > 0.0)
      ++result.raw_positive_count;
    else if (raw == 0.0)
      ++result.raw_zero_count;

    const double centered_delta = centered - result.centered_mean;
    result.centered_mean += centered_delta / count;
    result.centered_m2 +=
        centered_delta * (centered - result.centered_mean);
    if (centered > 0.0)
      ++result.centered_positive_count;
    else if (centered == 0.0)
      ++result.centered_zero_count;

    const double z_delta = robust_z - result.robust_z_mean;
    result.robust_z_mean += z_delta / count;
    const double absolute_z = std::abs(robust_z);
    const double absolute_delta = absolute_z - result.robust_abs_z_mean;
    result.robust_abs_z_mean += absolute_delta / count;
    result.robust_abs_z_max =
        std::max(result.robust_abs_z_max, absolute_z);
    validate_accumulator(result);
    return result;
  }

  static void validate_accumulator(const CoordinateAccumulator &state) {
    if (!detail::finite_accumulator(state) || state.raw_m2 < 0.0 ||
        state.centered_m2 < 0.0 || state.robust_abs_z_mean < 0.0 ||
        state.robust_abs_z_max < 0.0 ||
        state.raw_positive_count > state.count ||
        state.raw_zero_count > state.count - state.raw_positive_count ||
        state.centered_positive_count > state.count ||
        state.centered_zero_count >
            state.count - state.centered_positive_count ||
        state.robust_abs_z_mean > state.robust_abs_z_max)
      throw std::runtime_error("O1C82 coordinate seed/state differs");
    if (!state.count) {
      const CoordinateAccumulator empty{};
      if (std::memcmp(&state, &empty, sizeof(state)) != 0)
        throw std::runtime_error("O1C82 empty coordinate seed is nonzero");
      return;
    }
    const uint64_t centered_negative =
        state.count - state.centered_positive_count - state.centered_zero_count;
    const double stability =
        static_cast<double>(std::max(state.centered_positive_count,
                                     centered_negative)) /
        static_cast<double>(state.count);
    const double priority = std::abs(state.robust_z_mean) *
                            std::sqrt(static_cast<double>(state.count)) *
                            stability;
    if (!std::isfinite(priority))
      throw std::runtime_error("O1C82 coordinate priority is non-finite");
  }

  static CoordinateReport make_report(int variable,
                                      const CoordinateAccumulator &state) {
    CoordinateReport result;
    result.variable = variable;
    result.count = state.count;
    result.eligible = state.count >= kMinimumEligibleCount;
    if (!state.count)
      return result;
    const double count = static_cast<double>(state.count);
    const uint64_t raw_negative =
        state.count - state.raw_positive_count - state.raw_zero_count;
    const uint64_t centered_negative =
        state.count - state.centered_positive_count - state.centered_zero_count;
    result.raw_mean = state.raw_mean;
    result.raw_variance = std::max(0.0, state.raw_m2 / count);
    result.raw_positive_fraction = state.raw_positive_count / count;
    result.raw_negative_fraction = raw_negative / count;
    result.raw_zero_fraction = state.raw_zero_count / count;
    result.raw_directional_stability =
        std::max(result.raw_positive_fraction, result.raw_negative_fraction);
    result.centered_mean = state.centered_mean;
    result.centered_variance = std::max(0.0, state.centered_m2 / count);
    result.centered_positive_fraction = state.centered_positive_count / count;
    result.centered_negative_fraction = centered_negative / count;
    result.centered_zero_fraction = state.centered_zero_count / count;
    result.centered_directional_stability =
        std::max(result.centered_positive_fraction,
                 result.centered_negative_fraction);
    result.centered_signed_consistency =
        (static_cast<double>(state.centered_positive_count) -
         static_cast<double>(centered_negative)) /
        count;
    result.robust_z_mean = state.robust_z_mean;
    result.robust_abs_z_mean = state.robust_abs_z_mean;
    result.robust_abs_z_max = state.robust_abs_z_max;
    result.priority = std::abs(result.robust_z_mean) * std::sqrt(count) *
                      result.centered_directional_stability;
    return result;
  }

  static bool better(const CoordinateReport &left,
                     const CoordinateReport &right) {
    if (left.priority != right.priority)
      return left.priority > right.priority;
    if (left.count != right.count)
      return left.count > right.count;
    return left.variable < right.variable;
  }

  static void encode_record(const CoordinateAccumulator &state,
                            uint8_t *destination) {
    validate_accumulator(state);
    detail::store_u64_le(destination + 0U, state.count);
    detail::store_double_le(destination + 8U, state.raw_mean);
    detail::store_double_le(destination + 16U, state.raw_m2);
    detail::store_u64_le(destination + 24U, state.raw_positive_count);
    detail::store_u64_le(destination + 32U, state.raw_zero_count);
    detail::store_double_le(destination + 40U, state.centered_mean);
    detail::store_double_le(destination + 48U, state.centered_m2);
    detail::store_u64_le(destination + 56U,
                         state.centered_positive_count);
    detail::store_u64_le(destination + 64U, state.centered_zero_count);
    detail::store_double_le(destination + 72U, state.robust_z_mean);
    detail::store_double_le(destination + 80U, state.robust_abs_z_mean);
    detail::store_double_le(destination + 88U, state.robust_abs_z_max);
  }

  static CoordinateAccumulator decode_record(const uint8_t *source) {
    CoordinateAccumulator result;
    result.count = detail::load_u64_le(source + 0U);
    result.raw_mean = detail::load_double_le(source + 8U);
    result.raw_m2 = detail::load_double_le(source + 16U);
    result.raw_positive_count = detail::load_u64_le(source + 24U);
    result.raw_zero_count = detail::load_u64_le(source + 32U);
    result.centered_mean = detail::load_double_le(source + 40U);
    result.centered_m2 = detail::load_double_le(source + 48U);
    result.centered_positive_count = detail::load_u64_le(source + 56U);
    result.centered_zero_count = detail::load_u64_le(source + 64U);
    result.robust_z_mean = detail::load_double_le(source + 72U);
    result.robust_abs_z_mean = detail::load_double_le(source + 80U);
    result.robust_abs_z_max = detail::load_double_le(source + 88U);
    return result;
  }

  std::array<CoordinateAccumulator, kCoordinateCount> bank_{};
  std::array<ParentScratchEntry, kCoordinateCount> scratch_{};
};

static_assert(sizeof(ParentCenteredPriority) == kLiveStateBytes,
              "O1C82 live state accounting differs");
static_assert(kCoordinateBankBytes == 24576U,
              "O1C82 coordinate bank byte count differs");
static_assert(kParentScratchBytes == 4096U,
              "O1C82 parent scratch byte count differs");
static_assert(kLiveStateBytes == 28672U,
              "O1C82 total live byte count differs");

} // namespace o1c82

#endif
