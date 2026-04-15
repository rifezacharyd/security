#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace zdr::entropy {

// Shannon entropy in bits per byte, in [0.0, 8.0].
// Uses a SIMD-accelerated histogram when available (NEON on aarch64),
// scalar fallback otherwise. Both paths produce identical results.
double shannon(std::span<const std::uint8_t> bytes) noexcept;

// Exposed for bench + tests. Always scalar.
double shannon_scalar(std::span<const std::uint8_t> bytes) noexcept;

}  // namespace zdr::entropy
