#include "zdr/entropy.hpp"

#include <array>
#include <cmath>
#include <cstdint>

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#define ZDR_HAS_NEON 1
#include <arm_neon.h>
#else
#define ZDR_HAS_NEON 0
#endif

namespace zdr::entropy {

namespace {

double entropy_from_counts(const std::uint32_t (&counts)[256], std::size_t total) noexcept {
    if (total == 0) return 0.0;
    const double inv = 1.0 / static_cast<double>(total);
    double h = 0.0;
    for (std::size_t i = 0; i < 256; ++i) {
        const std::uint32_t c = counts[i];
        if (c == 0) continue;
        const double p = static_cast<double>(c) * inv;
        h -= p * std::log2(p);
    }
    if (h < 0.0) h = 0.0;
    if (h > 8.0) h = 8.0;
    return h;
}

}  // namespace

double shannon_scalar(std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t counts[256] = {};
    for (auto b : bytes) counts[b]++;
    return entropy_from_counts(counts, bytes.size());
}

double shannon(std::span<const std::uint8_t> bytes) noexcept {
#if ZDR_HAS_NEON
    // Multi-histogram trick: four interleaved 256-bin histograms, summed at
    // the end. Eliminates the write-after-write hazard that plagues the
    // naive single-histogram loop on out-of-order cores. NEON itself doesn't
    // have a scatter-add; the win is from independent streams, not SIMD ops.
    if (bytes.size() < 64) return shannon_scalar(bytes);

    alignas(64) std::uint32_t c0[256] = {};
    alignas(64) std::uint32_t c1[256] = {};
    alignas(64) std::uint32_t c2[256] = {};
    alignas(64) std::uint32_t c3[256] = {};

    const std::uint8_t* p = bytes.data();
    const std::size_t n = bytes.size();
    const std::size_t n4 = n & ~std::size_t{3};

    for (std::size_t i = 0; i < n4; i += 4) {
        c0[p[i + 0]]++;
        c1[p[i + 1]]++;
        c2[p[i + 2]]++;
        c3[p[i + 3]]++;
    }
    for (std::size_t i = n4; i < n; ++i) c0[p[i]]++;

    std::uint32_t counts[256];
    for (std::size_t i = 0; i < 256; ++i) {
        counts[i] = c0[i] + c1[i] + c2[i] + c3[i];
    }
    return entropy_from_counts(counts, n);
#else
    return shannon_scalar(bytes);
#endif
}

}  // namespace zdr::entropy
