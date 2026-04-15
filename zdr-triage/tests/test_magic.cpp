#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "zdr/magic.hpp"
#include "zdr/triage.hpp"

namespace {

std::vector<std::uint8_t> bytes_of(std::initializer_list<std::uint8_t> xs) {
    std::vector<std::uint8_t> v(xs.begin(), xs.end());
    v.resize(std::max<std::size_t>(v.size(), 16), 0);
    return v;
}

}  // namespace

TEST_CASE("magic::detect recognises known signatures", "[magic]") {
    SECTION("ELF") {
        auto b = bytes_of({0x7F, 'E', 'L', 'F', 2, 1, 1, 0});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Elf);
    }
    SECTION("Mach-O 32-bit 0xFEEDFACE") {
        auto b = bytes_of({0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::MachO);
    }
    SECTION("Mach-O 64-bit 0xFEEDFACF") {
        auto b = bytes_of({0xFE, 0xED, 0xFA, 0xCF, 0, 0, 0, 0});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::MachO);
    }
    SECTION("PE") {
        auto b = bytes_of({'M', 'Z', 0x90, 0x00});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Pe);
    }
    SECTION("ZIP") {
        auto b = bytes_of({'P', 'K', 0x03, 0x04});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Zip);
    }
    SECTION("gzip") {
        auto b = bytes_of({0x1F, 0x8B, 0x08, 0x00});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Gzip);
    }
    SECTION("PNG") {
        auto b = bytes_of({0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Png);
    }
    SECTION("JPEG") {
        auto b = bytes_of({0xFF, 0xD8, 0xFF, 0xE0});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Jpeg);
    }
    SECTION("PDF") {
        auto b = bytes_of({'%', 'P', 'D', 'F', '-', '1', '.', '4'});
        REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Pdf);
    }
}

TEST_CASE("magic::detect classifies plain ASCII as text", "[magic]") {
    const char* s = "hello world\n";
    std::vector<std::uint8_t> b(s, s + 12);
    REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Text);
}

TEST_CASE("magic::detect returns unknown for null-filled buffer", "[magic]") {
    std::vector<std::uint8_t> b(64, 0);
    REQUIRE(zdr::magic::detect(b) == zdr::FileKind::Unknown);
}
