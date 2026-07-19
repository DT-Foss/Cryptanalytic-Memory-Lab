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
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr const char *kSchema = "o1-256-cadical-joint-score-sieve-result-v1";
constexpr const char *kPotentialSchema = "O1CRIT-POT-V1";
constexpr const char *kRequiredVersion = "3.0.0";
constexpr const char *kDecisionRule = "solver_owned_no_external_decisions";
constexpr const char *kBoundRule =
    "nextafter-positive-infinity-after-each-factor-maximum-addition";
constexpr const char *kCompleteThresholdRule =
    "exact-binary-superaccumulator-comparison";
constexpr const char *kStateEncoding =
    "observed-ascending-i8-sign;trail-u32le-level,u32le-count,"
    "u32le-local-index,u32le-level;pending-u32le-length,u32le-cursor,"
    "u8-ready,u8-blocking,i32le-literals;derived-cache-factor-order-f64le-max";
constexpr const char *kPersistentStateScope =
    "solver-functional-persistent-logical-state;excludes-immutable-potential-"
    "index,telemetry,allocator-capacity,transient-callback-scratch";
constexpr int kKeyBits = 256;
constexpr int kMaximumVariables = 1000000;
constexpr int kMaximumFactorVariables = 8;

class Sha256 final {
public:
  Sha256() = default;

  void update(const void *raw, size_t size) {
    if (!raw && size)
      throw std::runtime_error("SHA-256 input pointer differs");
    if (size > std::numeric_limits<uint64_t>::max() - total_bytes_)
      throw std::runtime_error("SHA-256 input is too large");
    total_bytes_ += static_cast<uint64_t>(size);
    const auto *input = static_cast<const uint8_t *>(raw);
    while (size) {
      const size_t take = std::min(size, buffer_.size() - buffered_);
      std::copy(input, input + take, buffer_.begin() +
                                      static_cast<std::ptrdiff_t>(buffered_));
      buffered_ += take;
      input += take;
      size -= take;
      if (buffered_ == buffer_.size()) {
        transform(buffer_.data());
        buffered_ = 0;
      }
    }
  }

  void update(std::string_view value) { update(value.data(), value.size()); }

  std::string hex_digest() const {
    Sha256 copy = *this;
    const uint64_t bit_length = copy.total_bytes_ * 8U;
    std::array<uint8_t, 128> padding{};
    padding[0] = 0x80U;
    const size_t zero_and_marker =
        copy.buffered_ < 56U ? 56U - copy.buffered_ : 120U - copy.buffered_;
    for (int shift = 56; shift >= 0; shift -= 8)
      padding[zero_and_marker + static_cast<size_t>((56 - shift) / 8)] =
          static_cast<uint8_t>(bit_length >> shift);
    copy.update(padding.data(), zero_and_marker + 8U);
    if (copy.buffered_)
      throw std::runtime_error("SHA-256 finalization differs");
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const uint32_t value : copy.state_)
      out << std::setw(8) << value;
    return out.str();
  }

private:
  static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32U - count));
  }

  void transform(const uint8_t *block) {
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
      const size_t position = 4U * index;
      words[index] = static_cast<uint32_t>(block[position]) << 24U |
                     static_cast<uint32_t>(block[position + 1U]) << 16U |
                     static_cast<uint32_t>(block[position + 2U]) << 8U |
                     static_cast<uint32_t>(block[position + 3U]);
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
    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];
    for (size_t index = 0; index < words.size(); ++index) {
      const uint32_t sum1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^
                            rotate_right(e, 25U);
      const uint32_t choose = (e & f) ^ (~e & g);
      const uint32_t temporary1 =
          h + sum1 + choose + constants[index] + words[index];
      const uint32_t sum0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^
                            rotate_right(a, 22U);
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

  std::array<uint32_t, 8> state_ = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  std::array<uint8_t, 64> buffer_{};
  size_t buffered_ = 0;
  uint64_t total_bytes_ = 0;
};

std::string sha256(std::string_view value) {
  Sha256 digest;
  digest.update(value);
  return digest.hex_digest();
}

void append_u32_le(std::string &output, uint32_t value) {
  for (unsigned shift = 0; shift < 32U; shift += 8U)
    output.push_back(static_cast<char>(value >> shift));
}

void append_u64_le(std::string &output, uint64_t value) {
  for (unsigned shift = 0; shift < 64U; shift += 8U)
    output.push_back(static_cast<char>(value >> shift));
}

std::string bytes_hex(std::string_view value) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const unsigned char byte : value)
    out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

bool is_sha256(const std::string &value) {
  return value.size() == 64U &&
         std::all_of(value.begin(), value.end(), [](char character) {
           return (character >= '0' && character <= '9') ||
                  (character >= 'a' && character <= 'f');
         });
}

std::string read_binary_file(const std::string &path, const char *field) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error(std::string("cannot open ") + field);
  std::ostringstream buffer;
  buffer << input.rdbuf();
  if (!input.eof() && input.fail())
    throw std::runtime_error(std::string("cannot read ") + field);
  return buffer.str();
}

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

double parse_double(std::string_view value, const char *field) {
  if (value.empty())
    throw std::runtime_error(std::string(field) + " is empty");
  const std::string owned(value);
  char *end = nullptr;
  errno = 0;
  const double parsed = std::strtod(owned.c_str(), &end);
  if ((errno && errno != ERANGE) || !end || *end || !std::isfinite(parsed))
    throw std::runtime_error(std::string(field) + " is invalid");
  return parsed;
}

class ExactDoubleSum final {
public:
  void add(double value, bool negate = false) {
    if (!std::isfinite(value))
      throw std::runtime_error("exact sum input is not finite");
    uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(value));
    std::memcpy(&bits, &value, sizeof(bits));
    const uint64_t fraction = bits & ((uint64_t{1} << 52U) - 1U);
    const unsigned exponent = static_cast<unsigned>((bits >> 52U) & 0x7ffU);
    if (!exponent && !fraction)
      return;
    const uint64_t significand =
        exponent ? fraction | (uint64_t{1} << 52U) : fraction;
    const unsigned shift = exponent ? exponent - 1U : 0U;
    const bool negative = static_cast<bool>(bits >> 63U) != negate;
    add_shifted(negative ? negative_ : positive_, significand, shift);
  }

  int compare_zero() const {
    for (size_t reverse = positive_.size(); reverse > 0; --reverse) {
      const size_t index = reverse - 1U;
      if (positive_[index] < negative_[index])
        return -1;
      if (positive_[index] > negative_[index])
        return 1;
    }
    return 0;
  }

  double rounded() const {
    const int comparison = compare_zero();
    if (!comparison)
      return 0.0;
    const auto &larger = comparison > 0 ? positive_ : negative_;
    const auto &smaller = comparison > 0 ? negative_ : positive_;
    std::array<uint64_t, 35> magnitude{};
    uint64_t borrow = 0;
    for (size_t index = 0; index < magnitude.size(); ++index) {
      const uint64_t difference = larger[index] - smaller[index];
      const bool first_borrow = larger[index] < smaller[index];
      magnitude[index] = difference - borrow;
      const bool second_borrow = difference < borrow;
      borrow = first_borrow || second_borrow ? 1U : 0U;
    }
    if (borrow)
      throw std::runtime_error("exact sum subtraction differs");
    size_t highest_word = magnitude.size();
    while (highest_word && !magnitude[highest_word - 1U])
      --highest_word;
    if (!highest_word)
      throw std::runtime_error("exact sum magnitude differs");
    const uint64_t top_word = magnitude[highest_word - 1U];
    const unsigned top_bit =
        63U - static_cast<unsigned>(__builtin_clzll(top_word));
    size_t highest_bit = 64U * (highest_word - 1U) + top_bit;
    if (highest_bit <= 52U) {
      const double value = std::ldexp(static_cast<double>(magnitude[0]), -1074);
      return comparison > 0 ? value : -value;
    }
    const size_t shift = highest_bit - 52U;
    uint64_t significand = shifted_low_word(magnitude, shift) &
                           ((uint64_t{1} << 53U) - 1U);
    const bool guard = bit(magnitude, shift - 1U);
    const bool sticky = any_bits_below(magnitude, shift - 1U);
    if (guard && (sticky || (significand & 1U)))
      ++significand;
    if (significand == (uint64_t{1} << 53U)) {
      significand >>= 1U;
      ++highest_bit;
    }
    const size_t exponent = highest_bit - 51U;
    if (exponent >= 0x7ffU)
      throw std::runtime_error("exact complete score is not finite");
    uint64_t result_bits = static_cast<uint64_t>(exponent) << 52U |
                           (significand & ((uint64_t{1} << 52U) - 1U));
    if (comparison < 0)
      result_bits |= uint64_t{1} << 63U;
    double result = 0.0;
    std::memcpy(&result, &result_bits, sizeof(result));
    return result;
  }

private:
  static uint64_t shifted_low_word(const std::array<uint64_t, 35> &value,
                                   size_t shift) {
    const size_t word = shift / 64U;
    const unsigned offset = static_cast<unsigned>(shift % 64U);
    uint64_t result = value.at(word) >> offset;
    if (offset && word + 1U < value.size())
      result |= value[word + 1U] << (64U - offset);
    return result;
  }

  static bool bit(const std::array<uint64_t, 35> &value, size_t index) {
    return static_cast<bool>(value.at(index / 64U) >> (index % 64U) & 1U);
  }

  static bool any_bits_below(const std::array<uint64_t, 35> &value,
                             size_t limit) {
    const size_t words = limit / 64U;
    for (size_t index = 0; index < words; ++index)
      if (value[index])
        return true;
    const unsigned remainder = static_cast<unsigned>(limit % 64U);
    return remainder &&
           (value.at(words) & ((uint64_t{1} << remainder) - 1U));
  }

  static void add_word(std::array<uint64_t, 35> &target, size_t index,
                       uint64_t value) {
    while (value) {
      if (index >= target.size())
        throw std::runtime_error("exact sum accumulator overflow");
      const uint64_t previous = target[index];
      target[index] += value;
      value = target[index] < previous ? 1U : 0U;
      ++index;
    }
  }

  static void add_shifted(std::array<uint64_t, 35> &target,
                          uint64_t significand, unsigned shift) {
    const size_t word = shift / 64U;
    const unsigned offset = shift % 64U;
    add_word(target, word, significand << offset);
    if (offset)
      add_word(target, word + 1U, significand >> (64U - offset));
  }

  std::array<uint64_t, 35> positive_{};
  std::array<uint64_t, 35> negative_{};
};

struct Arguments {
  std::string cnf_path;
  std::string potential_path;
  int conflict_limit = -1;
  int seed = 0;
  double threshold = std::numeric_limits<double>::quiet_NaN();
};

Arguments parse_arguments(int argc, char **argv) {
  Arguments result;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help") {
      std::cout << "usage: cadical_o1_joint_score_sieve --cnf PATH "
                   "--potential PATH --threshold FLOAT --conflict-limit N "
                   "[--seed N]\n";
      std::exit(0);
    }
    if (index + 1 >= argc)
      throw std::runtime_error("missing value for " + argument);
    const std::string value = argv[++index];
    if (argument == "--cnf")
      result.cnf_path = value;
    else if (argument == "--potential")
      result.potential_path = value;
    else if (argument == "--threshold")
      result.threshold = parse_double(value, "threshold");
    else if (argument == "--conflict-limit")
      result.conflict_limit =
          parse_integer(value, "conflict-limit", 1, 1000000000);
    else if (argument == "--seed")
      result.seed = parse_integer(value, "seed", 0, 2000000000);
    else
      throw std::runtime_error("unknown argument " + argument);
  }
  if (result.cnf_path.empty() || result.potential_path.empty() ||
      result.conflict_limit < 1 || !std::isfinite(result.threshold))
    throw std::runtime_error("required arguments are missing");
  return result;
}

struct PotentialFactor {
  std::vector<int> variables;
  std::vector<size_t> local_indices;
  std::vector<double> energies;
};

struct PotentialField {
  double offset = 0.0;
  std::string source_sha256;
  std::vector<PotentialFactor> factors;
};

PotentialField parse_potential(const std::string &payload, int variable_count) {
  std::istringstream input(payload);
  std::string schema;
  size_t factor_count = 0;
  PotentialField result;
  if (!(input >> schema >> factor_count >> result.offset >> result.source_sha256) ||
      schema != kPotentialSchema || !factor_count || factor_count > 65535U ||
      !std::isfinite(result.offset) || !is_sha256(result.source_sha256))
    throw std::runtime_error("potential header differs");
  std::vector<int> previous;
  for (size_t index = 0; index < factor_count; ++index) {
    int width = 0;
    if (!(input >> width) || width < 1 || width > kMaximumFactorVariables)
      throw std::runtime_error("potential factor width differs");
    PotentialFactor factor;
    factor.variables.resize(static_cast<size_t>(width));
    for (int &variable : factor.variables)
      if (!(input >> variable) || variable < 1 || variable > variable_count)
        throw std::runtime_error("potential variable differs");
    if (!std::is_sorted(factor.variables.begin(), factor.variables.end()) ||
        std::adjacent_find(factor.variables.begin(), factor.variables.end()) !=
            factor.variables.end() ||
        (!previous.empty() && !(previous < factor.variables)))
      throw std::runtime_error("potential variable order differs");
    previous = factor.variables;
    factor.energies.resize(size_t{1} << static_cast<unsigned>(width));
    for (double &energy : factor.energies)
      if (!(input >> energy) || !std::isfinite(energy))
        throw std::runtime_error("potential energy differs");
    result.factors.push_back(std::move(factor));
  }
  std::string trailing;
  if (input >> trailing)
    throw std::runtime_error("potential contains trailing fields");
  return result;
}

class JointScoreSieve final : public CaDiCaL::ExternalPropagator {
public:
  JointScoreSieve(PotentialField field, double threshold)
      : field_(std::move(field)), threshold_(threshold) {
    for (const PotentialFactor &factor : field_.factors)
      observed_.insert(observed_.end(), factor.variables.begin(),
                       factor.variables.end());
    std::sort(observed_.begin(), observed_.end());
    observed_.erase(std::unique(observed_.begin(), observed_.end()),
                    observed_.end());
    if (observed_.empty())
      throw std::runtime_error("joint-score potential observes no variables");
    assigned_.assign(observed_.size(), 0);
    incident_factors_.resize(observed_.size());
    factor_maxima_.resize(field_.factors.size());
    for (size_t factor_index = 0; factor_index < field_.factors.size();
         ++factor_index) {
      PotentialFactor &factor = field_.factors[factor_index];
      for (const int variable : factor.variables) {
        const size_t local = local_index(variable);
        if (local == observed_.size())
          throw std::runtime_error("joint-score local variable mapping differs");
        factor.local_indices.push_back(local);
        incident_factors_[local].push_back(factor_index);
        ++incident_edges_;
      }
      factor_maxima_[factor_index] = factor_maximum(factor, assigned_);
    }
    std::string observed_bytes;
    observed_bytes.reserve(observed_.size() * 4U);
    for (const int variable : observed_)
      append_u32_le(observed_bytes, static_cast<uint32_t>(variable));
    observed_sha256_ = sha256(observed_bytes);
    root_upper_bound_ = upper_from_cached_maxima();
    minimum_upper_bound_ = root_upper_bound_;
    maximum_upper_bound_ = root_upper_bound_;
    ++bound_checks_;
    update_maximum_live_state();
    if (root_upper_bound_ < threshold_)
      queue_clause(assigned_, root_upper_bound_, false);
    else
      record_trace(root_upper_bound_, false, 0U);
  }

  void notify_assignment(const std::vector<int> &literals) override {
    ++assignment_callbacks_;
    std::vector<size_t> changed;
    for (const int literal : literals) {
      const size_t local = local_index(std::abs(literal));
      if (local == observed_.size())
        throw std::runtime_error("unexpected joint-score assignment");
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      int8_t &slot = assigned_.at(local);
      if (!slot) {
        slot = value;
        trail_.push_back(
            {static_cast<uint32_t>(local), static_cast<uint32_t>(current_level_)});
        changed.push_back(local);
        ++assigned_count_;
        ++assignment_literals_;
        maximum_assigned_ = std::max(maximum_assigned_, assigned_count_);
        maximum_live_trail_entries_ =
            std::max(maximum_live_trail_entries_, trail_.size());
      } else if (slot != value) {
        throw std::runtime_error(
            "joint-score assignment changed without backtrack");
      }
    }
    update_maximum_live_state();
    if (!changed.empty()) {
      if (pending_ready_ || blocking_active_)
        refresh_factor_maxima(changed);
      else
        evaluate_current_bound(changed);
    }
  }

  void notify_new_decision_level() override {
    if (current_level_ >= 1000000U)
      throw std::runtime_error("joint-score decision level exceeds bound");
    ++current_level_;
    ++new_decision_levels_;
    maximum_level_ = std::max(maximum_level_, current_level_);
  }

  void notify_backtrack(size_t new_level) override {
    if (new_level > current_level_)
      throw std::runtime_error("invalid joint-score backtrack level");
    if (pending_ready_ || blocking_active_)
      throw std::runtime_error("joint-score backtrack with pending clause");
    std::vector<size_t> changed;
    while (!trail_.empty() && trail_.back().level > new_level) {
      const size_t local = trail_.back().local;
      int8_t &slot = assigned_.at(local);
      if (!slot)
        throw std::runtime_error(
            "joint-score backtrack found unassigned variable");
      slot = 0;
      trail_.pop_back();
      changed.push_back(local);
      --assigned_count_;
      ++backtracked_assignments_;
    }
    current_level_ = new_level;
    ++backtracks_;
    if (!changed.empty())
      evaluate_current_bound(changed);
  }

  bool cb_check_found_model(const std::vector<int> &model) override {
    ++model_checks_;
    std::vector<int8_t> values(observed_.size(), 0);
    for (const int literal : model) {
      const size_t local = local_index(std::abs(literal));
      if (local == observed_.size())
        continue;
      int8_t &slot = values.at(local);
      const int8_t value = literal > 0 ? int8_t{1} : int8_t{-1};
      if (slot && slot != value)
        throw std::runtime_error("joint-score model duplicates disagree");
      slot = value;
    }
    if (std::find(values.begin(), values.end(), int8_t{0}) != values.end())
      throw std::runtime_error("joint-score model omits observed variable");
    ExactDoubleSum exact = complete_score_sum(values);
    const double score = exact.rounded();
    exact.add(threshold_, true);
    const int threshold_comparison = exact.compare_zero();
    ++complete_model_score_checks_;
    if (!have_complete_score_) {
      minimum_complete_score_ = score;
      maximum_complete_score_ = score;
      have_complete_score_ = true;
    } else {
      minimum_complete_score_ = std::min(minimum_complete_score_, score);
      maximum_complete_score_ = std::max(maximum_complete_score_, score);
    }
    if (threshold_comparison < 0) {
      ++models_below_threshold_;
      if (blocking_active_ || pending_ready_)
        throw std::runtime_error("joint-score model rejection overlaps clause");
      queue_clause(values, score, true);
      return false;
    }
    ++models_at_or_above_threshold_;
    return true;
  }

  int cb_decide() override {
    ++cb_decide_calls_;
    return 0;
  }

  int cb_propagate() override {
    ++cb_propagate_calls_;
    return 0;
  }

  int cb_add_reason_clause_lit(int) override { return 0; }

  bool cb_has_external_clause(bool &forgettable) override {
    ++cb_has_external_clause_calls_;
    forgettable = false;
    return pending_ready_;
  }

  int cb_add_external_clause_lit() override {
    if (!pending_ready_)
      throw std::runtime_error("joint-score clause callback lacks pending clause");
    if (pending_cursor_ < pending_clause_.size())
      return pending_clause_.at(pending_cursor_++);
    ++external_clauses_emitted_;
    pending_clause_.clear();
    pending_cursor_ = 0;
    pending_ready_ = false;
    blocking_active_ = false;
    return 0;
  }

  const std::vector<int> &observed() const { return observed_; }

  std::string assignment_state() const {
    return std::string(reinterpret_cast<const char *>(assigned_.data()),
                       assigned_.size());
  }

  std::string trail_state() const {
    std::string result;
    result.reserve(8U + 8U * trail_.size());
    append_u32_le(result, static_cast<uint32_t>(current_level_));
    append_u32_le(result, static_cast<uint32_t>(trail_.size()));
    for (const TrailEntry &entry : trail_) {
      append_u32_le(result, entry.local);
      append_u32_le(result, entry.level);
    }
    return result;
  }

  std::string pending_state() const {
    std::string result;
    result.reserve(10U + 4U * pending_clause_.size());
    append_u32_le(result, static_cast<uint32_t>(pending_clause_.size()));
    append_u32_le(result, static_cast<uint32_t>(pending_cursor_));
    result.push_back(static_cast<char>(pending_ready_ ? 1 : 0));
    result.push_back(static_cast<char>(blocking_active_ ? 1 : 0));
    for (const int literal : pending_clause_)
      append_u32_le(result, static_cast<uint32_t>(static_cast<int32_t>(literal)));
    return result;
  }

  std::string factor_cache_state() const {
    std::string result;
    result.reserve(8U * factor_maxima_.size());
    for (const double maximum : factor_maxima_) {
      uint64_t bits = 0;
      static_assert(sizeof(bits) == sizeof(maximum));
      std::memcpy(&bits, &maximum, sizeof(bits));
      append_u64_le(result, bits);
    }
    return result;
  }

  size_t bounded_state_bytes() const {
    return observed_.size() + 8U + 8U * observed_.size() + 10U +
           4U * observed_.size();
  }

  void write_json(std::ostream &out) const {
    const std::string assignments = assignment_state();
    const std::string trail = trail_state();
    const std::string pending = pending_state();
    const std::string cache = factor_cache_state();
    const std::string canonical = assignments + trail + pending;
    const std::string working = canonical + cache;
    out << "\"factor_count\":" << field_.factors.size()
        << ",\"observed_variables\":" << observed_.size()
        << ",\"observed_variables_sha256\":\"" << observed_sha256_
        << "\",\"source_sha256\":\"" << field_.source_sha256
        << "\",\"offset\":" << field_.offset << ",\"threshold\":"
        << threshold_ << ",\"root_upper_bound\":" << root_upper_bound_
        << ",\"bound_rule\":\"" << kBoundRule
        << "\",\"complete_threshold_rule\":\"" << kCompleteThresholdRule
        << "\",\"decision_rule\":\"" << kDecisionRule
        << "\",\"external_implications\":0,\"cb_decide_calls\":"
        << cb_decide_calls_ << ",\"cb_decide_nonzero\":0"
        << ",\"cb_propagate_calls\":" << cb_propagate_calls_
        << ",\"assignment_callbacks\":" << assignment_callbacks_
        << ",\"assignment_literals\":" << assignment_literals_
        << ",\"new_decision_levels\":" << new_decision_levels_
        << ",\"backtracks\":" << backtracks_
        << ",\"backtracked_assignments\":" << backtracked_assignments_
        << ",\"maximum_assigned_variables\":" << maximum_assigned_
        << ",\"maximum_decision_level\":" << maximum_level_
        << ",\"bound_checks\":" << bound_checks_
        << ",\"bound_additions\":" << bound_additions_
        << ",\"incident_edges\":" << incident_edges_
        << ",\"incremental_factor_recomputations\":"
        << incremental_factor_recomputations_
        << ",\"maximum_incremental_factors_recomputed\":"
        << maximum_incremental_factors_recomputed_
        << ",\"factor_maximum_evaluations\":"
        << factor_maximum_evaluations_
        << ",\"factor_row_evaluations\":" << factor_row_evaluations_
        << ",\"minimum_upper_bound\":" << minimum_upper_bound_
        << ",\"maximum_upper_bound\":" << maximum_upper_bound_
        << ",\"threshold_prunes\":" << threshold_prunes_
        << ",\"trail_threshold_prunes\":" << trail_threshold_prunes_
        << ",\"model_threshold_prunes\":" << model_threshold_prunes_
        << ",\"external_clauses_queued\":" << external_clauses_queued_
        << ",\"external_clauses_emitted\":" << external_clauses_emitted_
        << ",\"external_clause_literals\":" << external_clause_literals_
        << ",\"minimum_clause_length\":" << minimum_clause_length()
        << ",\"maximum_clause_length\":" << maximum_clause_length_
        << ",\"maximum_pending_clause_length\":"
        << maximum_pending_clause_length_
        << ",\"pending_clause_count\":" << (pending_ready_ ? 1 : 0)
        << ",\"cb_has_external_clause_calls\":"
        << cb_has_external_clause_calls_ << ",\"model_checks\":"
        << model_checks_ << ",\"complete_model_score_checks\":"
        << complete_model_score_checks_ << ",\"models_below_threshold\":"
        << models_below_threshold_ << ",\"models_at_or_above_threshold\":"
        << models_at_or_above_threshold_ << ",\"minimum_complete_score\":";
    if (have_complete_score_)
      out << minimum_complete_score_;
    else
      out << "null";
    out << ",\"maximum_complete_score\":";
    if (have_complete_score_)
      out << maximum_complete_score_;
    else
      out << "null";
    out << ",\"trace_sha256\":\"" << trace_.hex_digest()
        << "\",\"state\":{\"encoding\":\"" << kStateEncoding
        << "\",\"persistent_state_scope\":\"" << kPersistentStateScope
        << "\",\"assignment_bytes\":" << assignments.size()
        << ",\"bounded_trail_bytes\":" << 8U + 8U * observed_.size()
        << ",\"bounded_pending_bytes\":" << 10U + 4U * observed_.size()
        << ",\"bounded_state_bytes\":" << bounded_state_bytes()
        << ",\"derived_factor_cache_bytes\":" << cache.size()
        << ",\"bounded_persistent_state_bytes\":"
        << bounded_state_bytes() + cache.size()
        << ",\"live_trail_bytes\":" << trail.size()
        << ",\"live_pending_bytes\":" << pending.size()
        << ",\"live_state_bytes\":" << canonical.size()
        << ",\"live_persistent_state_bytes\":" << working.size()
        << ",\"maximum_live_trail_bytes\":"
        << 8U + 8U * maximum_live_trail_entries_
        << ",\"maximum_live_state_bytes\":" << maximum_live_state_bytes_
        << ",\"maximum_live_persistent_state_bytes\":"
        << maximum_live_state_bytes_ + cache.size()
        << ",\"current_assigned_variables\":" << assigned_count_
        << ",\"current_decision_level\":" << current_level_
        << ",\"trail_entries\":" << trail_.size()
        << ",\"pending_clause_length\":" << pending_clause_.size()
        << ",\"assignment_hex\":\"" << bytes_hex(assignments)
        << "\",\"trail_hex\":\"" << bytes_hex(trail)
        << "\",\"pending_hex\":\"" << bytes_hex(pending)
        << "\",\"factor_cache_hex\":\"" << bytes_hex(cache)
        << "\",\"assignment_sha256\":\"" << sha256(assignments)
        << "\",\"trail_sha256\":\"" << sha256(trail)
        << "\",\"pending_sha256\":\"" << sha256(pending)
        << "\",\"factor_cache_sha256\":\"" << sha256(cache)
        << "\",\"sha256\":\"" << sha256(canonical)
        << "\",\"persistent_sha256\":\"" << sha256(working) << "\"}";
  }

private:
  struct TrailEntry {
    uint32_t local;
    uint32_t level;
  };

  size_t local_index(int variable) const {
    const auto found = std::lower_bound(observed_.begin(), observed_.end(), variable);
    if (found == observed_.end() || *found != variable)
      return observed_.size();
    return static_cast<size_t>(found - observed_.begin());
  }

  double outward_add(double left, double right) const {
    const double raw = left + right;
    if (!std::isfinite(raw))
      throw std::runtime_error("joint-score upper bound is not finite");
    const double bounded =
        std::nextafter(raw, std::numeric_limits<double>::infinity());
    if (!std::isfinite(bounded))
      throw std::runtime_error("joint-score upper bound is not representable");
    return bounded;
  }

  double factor_maximum(const PotentialFactor &factor,
                        const std::vector<int8_t> &values) {
    ++factor_maximum_evaluations_;
    factor_row_evaluations_ += static_cast<int64_t>(factor.energies.size());
    double best = -std::numeric_limits<double>::infinity();
    for (size_t row = 0; row < factor.energies.size(); ++row) {
      bool consistent = true;
      for (size_t position = 0; position < factor.local_indices.size();
           ++position) {
        const int8_t spin = values.at(factor.local_indices[position]);
        if (spin && ((row >> position) & 1U) !=
                        static_cast<unsigned>(spin > 0)) {
          consistent = false;
          break;
        }
      }
      if (consistent)
        best = std::max(best, factor.energies[row]);
    }
    if (!std::isfinite(best))
      throw std::runtime_error("joint-score factor has no consistent row");
    return best;
  }

  double upper_from_cached_maxima() {
    double result = field_.offset;
    for (const double maximum : factor_maxima_) {
      result = outward_add(result, maximum);
      ++bound_additions_;
    }
    return result;
  }

  ExactDoubleSum
  complete_score_sum(const std::vector<int8_t> &values) const {
    ExactDoubleSum result;
    result.add(field_.offset);
    for (const PotentialFactor &factor : field_.factors) {
      size_t row = 0;
      for (size_t position = 0; position < factor.local_indices.size();
           ++position) {
        const int8_t spin = values.at(factor.local_indices[position]);
        if (!spin)
          throw std::runtime_error("joint-score complete model is partial");
        if (spin > 0)
          row |= size_t{1} << position;
      }
      result.add(factor.energies.at(row));
    }
    return result;
  }

  void refresh_factor_maxima(const std::vector<size_t> &changed_locals) {
    std::vector<size_t> affected;
    for (const size_t local : changed_locals)
      affected.insert(affected.end(), incident_factors_.at(local).begin(),
                      incident_factors_.at(local).end());
    std::sort(affected.begin(), affected.end());
    affected.erase(std::unique(affected.begin(), affected.end()), affected.end());
    if (affected.empty())
      throw std::runtime_error("joint-score update has no incident factor");
    incremental_factor_recomputations_ +=
        static_cast<int64_t>(affected.size());
    maximum_incremental_factors_recomputed_ =
        std::max(maximum_incremental_factors_recomputed_, affected.size());
    for (const size_t factor_index : affected)
      factor_maxima_.at(factor_index) =
          factor_maximum(field_.factors.at(factor_index), assigned_);
  }

  void evaluate_current_bound(const std::vector<size_t> &changed_locals) {
    refresh_factor_maxima(changed_locals);
    const double upper = upper_from_cached_maxima();
    ++bound_checks_;
    minimum_upper_bound_ = std::min(minimum_upper_bound_, upper);
    maximum_upper_bound_ = std::max(maximum_upper_bound_, upper);
    if (upper < threshold_)
      queue_clause(assigned_, upper, false);
    else
      record_trace(upper, false, 0U);
  }

  void queue_clause(const std::vector<int8_t> &values, double score,
                    bool model_clause) {
    if (pending_ready_ || blocking_active_)
      throw std::runtime_error("joint-score clause already blocks current trail");
    pending_clause_.clear();
    for (size_t local = 0; local < observed_.size(); ++local) {
      const int8_t spin = values.at(local);
      if (spin)
        pending_clause_.push_back(spin > 0 ? -observed_[local] : observed_[local]);
    }
    pending_cursor_ = 0;
    pending_ready_ = true;
    blocking_active_ = true;
    ++threshold_prunes_;
    if (model_clause)
      ++model_threshold_prunes_;
    else
      ++trail_threshold_prunes_;
    ++external_clauses_queued_;
    external_clause_literals_ +=
        static_cast<int64_t>(pending_clause_.size());
    if (!have_clause_length_) {
      minimum_clause_length_ = pending_clause_.size();
      have_clause_length_ = true;
    } else {
      minimum_clause_length_ =
          std::min(minimum_clause_length_, pending_clause_.size());
    }
    maximum_clause_length_ =
        std::max(maximum_clause_length_, pending_clause_.size());
    maximum_pending_clause_length_ =
        std::max(maximum_pending_clause_length_, pending_clause_.size());
    update_maximum_live_state();
    record_trace(score, true, pending_clause_.size());
  }

  void update_maximum_live_state() {
    const size_t live = observed_.size() + 8U + 8U * trail_.size() + 10U +
                        4U * pending_clause_.size();
    maximum_live_state_bytes_ = std::max(maximum_live_state_bytes_, live);
  }

  void record_trace(double upper, bool pruned, size_t clause_length) {
    std::string event;
    event.reserve(25U);
    append_u64_le(event, static_cast<uint64_t>(bound_checks_));
    append_u32_le(event, static_cast<uint32_t>(assigned_count_));
    uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(upper));
    std::memcpy(&bits, &upper, sizeof(bits));
    append_u64_le(event, bits);
    event.push_back(static_cast<char>(pruned ? 1 : 0));
    append_u32_le(event, static_cast<uint32_t>(clause_length));
    trace_.update(event);
  }

  size_t minimum_clause_length() const {
    return have_clause_length_ ? minimum_clause_length_ : 0U;
  }

  PotentialField field_;
  double threshold_;
  std::vector<int8_t> assigned_;
  std::vector<int> observed_;
  std::vector<std::vector<size_t>> incident_factors_;
  std::vector<double> factor_maxima_;
  std::vector<TrailEntry> trail_;
  size_t current_level_ = 0;
  std::vector<int> pending_clause_;
  size_t pending_cursor_ = 0;
  bool pending_ready_ = false;
  bool blocking_active_ = false;
  std::string observed_sha256_;
  double root_upper_bound_ = 0.0;
  double minimum_upper_bound_ = 0.0;
  double maximum_upper_bound_ = 0.0;
  double minimum_complete_score_ = 0.0;
  double maximum_complete_score_ = 0.0;
  bool have_complete_score_ = false;
  bool have_clause_length_ = false;
  int64_t assigned_count_ = 0;
  int64_t maximum_assigned_ = 0;
  size_t maximum_level_ = 0;
  size_t maximum_live_trail_entries_ = 0;
  size_t maximum_live_state_bytes_ = 0;
  int64_t assignment_callbacks_ = 0;
  int64_t assignment_literals_ = 0;
  int64_t new_decision_levels_ = 0;
  int64_t backtracks_ = 0;
  int64_t backtracked_assignments_ = 0;
  int64_t cb_decide_calls_ = 0;
  int64_t cb_propagate_calls_ = 0;
  int64_t cb_has_external_clause_calls_ = 0;
  int64_t bound_checks_ = 0;
  int64_t bound_additions_ = 0;
  int64_t incident_edges_ = 0;
  int64_t incremental_factor_recomputations_ = 0;
  size_t maximum_incremental_factors_recomputed_ = 0;
  int64_t factor_maximum_evaluations_ = 0;
  int64_t factor_row_evaluations_ = 0;
  int64_t threshold_prunes_ = 0;
  int64_t trail_threshold_prunes_ = 0;
  int64_t model_threshold_prunes_ = 0;
  int64_t external_clauses_queued_ = 0;
  int64_t external_clauses_emitted_ = 0;
  int64_t external_clause_literals_ = 0;
  size_t minimum_clause_length_ = 0;
  size_t maximum_clause_length_ = 0;
  size_t maximum_pending_clause_length_ = 0;
  int64_t model_checks_ = 0;
  int64_t complete_model_score_checks_ = 0;
  int64_t models_below_threshold_ = 0;
  int64_t models_at_or_above_threshold_ = 0;
  Sha256 trace_;
};

class ExternalConnectionGuard final {
public:
  explicit ExternalConnectionGuard(CaDiCaL::Solver *solver) : solver_(solver) {
    if (!solver_)
      throw std::runtime_error("external connection guard lacks solver");
  }

  ExternalConnectionGuard(const ExternalConnectionGuard &) = delete;
  ExternalConnectionGuard &operator=(const ExternalConnectionGuard &) = delete;

  ~ExternalConnectionGuard() noexcept {
    try {
      disconnect();
    } catch (...) {
    }
  }

  void connect(CaDiCaL::ExternalPropagator *propagator) {
    if (connected_ || !propagator)
      throw std::runtime_error("external propagator connection differs");
    solver_->connect_external_propagator(propagator);
    connected_ = true;
  }

  void disconnect() {
    if (!connected_)
      return;
    solver_->disconnect_external_propagator();
    connected_ = false;
  }

private:
  CaDiCaL::Solver *solver_;
  bool connected_ = false;
};

int64_t statistic(CaDiCaL::Solver &solver, const char *name) {
  return solver.get_statistic_value(name);
}

int64_t peak_rss_bytes() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return 0;
#ifdef __APPLE__
  return static_cast<int64_t>(usage.ru_maxrss);
#else
  return static_cast<int64_t>(usage.ru_maxrss) * 1024;
#endif
}

int64_t cpu_microseconds() {
  struct rusage usage {};
  if (getrusage(RUSAGE_SELF, &usage))
    return 0;
  return static_cast<int64_t>(usage.ru_utime.tv_sec) * 1000000 +
         usage.ru_utime.tv_usec +
         static_cast<int64_t>(usage.ru_stime.tv_sec) * 1000000 +
         usage.ru_stime.tv_usec;
}

std::string key_hex(CaDiCaL::Solver &solver) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (int byte_index = 0; byte_index < 32; ++byte_index) {
    unsigned value = 0;
    for (int bit = 0; bit < 8; ++bit) {
      const int variable = byte_index * 8 + bit + 1;
      if (solver.val(variable) > 0)
        value |= 1U << bit;
    }
    out << std::setw(2) << value;
  }
  return out.str();
}

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
    const auto started = std::chrono::steady_clock::now();
    const int status = solver.solve();
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);
    const std::string model = status == 10 ? key_hex(solver) : std::string();
    connection.disconnect();

    std::cout << std::setprecision(std::numeric_limits<double>::max_digits10)
              << "{\"schema\":\"" << kSchema
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
              << "\",\"stats\":{\"conflicts\":"
              << statistic(solver, "conflicts") << ",\"decisions\":"
              << statistic(solver, "decisions") << ",\"propagations\":"
              << statistic(solver, "propagations") << "},\"sieve\":{";
    propagator->write_json(std::cout);
    std::cout << "},\"resources\":{\"wall_microseconds\":" << elapsed.count()
              << ",\"cpu_microseconds\":" << cpu_microseconds()
              << ",\"peak_rss_bytes\":" << peak_rss_bytes() << "}}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cadical_o1_joint_score_sieve: " << error.what() << '\n';
    return 1;
  }
}
