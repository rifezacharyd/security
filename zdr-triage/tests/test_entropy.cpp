#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <cstdint>
#include <random>
#include <span>
#include <vector>

#include "zdr/entropy.hpp"

using Catch::Matchers::WithinAbs;

TEST_CASE("shannon entropy of empty span is zero", "[entropy]") {
    std::span<const std::uint8_t> empty{};
    REQUIRE(zdr::entropy::shannon(empty) == 0.0);
    REQUIRE(zdr::entropy::shannon_scalar(empty) == 0.0);
}

TEST_CASE("shannon entropy of single-byte buffer is zero", "[entropy]") {
    std::vector<std::uint8_t> zeros(1024, 0);
    REQUIRE_THAT(zdr::entropy::shannon(zeros), WithinAbs(0.0, 1e-12));
    REQUIRE_THAT(zdr::entropy::shannon_scalar(zeros), WithinAbs(0.0, 1e-12));
}

TEST_CASE("shannon entropy of uniform byte distribution is eight", "[entropy]") {
    std::vector<std::uint8_t> uniform;
    uniform.reserve(256 * 16);
    for (int rep = 0; rep < 16; ++rep) {
        for (int b = 0; b < 256; ++b) {
            uniform.push_back(static_cast<std::uint8_t>(b));
        }
    }
    REQUIRE_THAT(zdr::entropy::shannon(uniform), WithinAbs(8.0, 1e-9));
    REQUIRE_THAT(zdr::entropy::shannon_scalar(uniform), WithinAbs(8.0, 1e-9));
}

TEST_CASE("simd and scalar shannon agree on pseudo-random buffer", "[entropy]") {
    std::mt19937 rng(0xC0FFEEu);
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<std::uint8_t> buf(10 * 1024);
    for (auto& b : buf) {
        b = static_cast<std::uint8_t>(dist(rng));
    }
    const double a = zdr::entropy::shannon(buf);
    const double s = zdr::entropy::shannon_scalar(buf);
    REQUIRE_THAT(a, WithinAbs(s, 1e-12));
}
