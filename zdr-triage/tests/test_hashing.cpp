#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zdr/hashing.hpp"

namespace {

std::span<const std::uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

}  // namespace

TEST_CASE("sha256 of empty input", "[hashing][sha256]") {
    auto d = zdr::hashing::sha256({});
    REQUIRE(zdr::hashing::hex(d) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("sha256 of \"abc\"", "[hashing][sha256]") {
    auto d = zdr::hashing::sha256(as_bytes("abc"));
    REQUIRE(zdr::hashing::hex(d) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("Sha256Streamer matches one-shot across split updates", "[hashing][streamer]") {
    zdr::hashing::Sha256Streamer s;
    s.update(as_bytes("a"));
    s.update(as_bytes("bc"));
    auto streamed = s.finalize();
    REQUIRE(zdr::hashing::hex(streamed) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("hex round-trip for known digests", "[hashing][hex]") {
    SECTION("all zeros") {
        std::array<std::uint8_t, 32> z{};
        REQUIRE(zdr::hashing::hex(z) ==
                "0000000000000000000000000000000000000000000000000000000000000000");
    }
    SECTION("ascending bytes") {
        std::array<std::uint8_t, 4> b{0x00, 0x01, 0xAB, 0xFF};
        REQUIRE(zdr::hashing::hex(b) == "0001abff");
    }
    SECTION("sha256 abc matches canonical hex") {
        auto d = zdr::hashing::sha256(as_bytes("abc"));
        REQUIRE(zdr::hashing::hex(d).size() == 64);
        REQUIRE(zdr::hashing::hex(d) ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
