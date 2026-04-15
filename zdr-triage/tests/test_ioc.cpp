#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "zdr/ioc.hpp"
#include "zdr/triage.hpp"

namespace {

std::span<const std::uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

bool contains(const std::vector<std::string>& v, std::string_view needle) {
    return std::find(v.begin(), v.end(), needle) != v.end();
}

}  // namespace

TEST_CASE("url extraction", "[ioc][url]") {
    SECTION("plain url inside surrounding prose") {
        auto s = std::string("see https://example.com/path?q=1 for details");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.urls, "https://example.com/path?q=1"));
    }
    SECTION("trailing punctuation is trimmed") {
        auto s = std::string("url: https://example.com/path?q=1. and https://example.com/a, then (https://example.com/b)");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.urls, "https://example.com/path?q=1"));
        REQUIRE(contains(set.urls, "https://example.com/a"));
        REQUIRE(contains(set.urls, "https://example.com/b"));
        REQUIRE_FALSE(contains(set.urls, "https://example.com/path?q=1."));
        REQUIRE_FALSE(contains(set.urls, "https://example.com/a,"));
        REQUIRE_FALSE(contains(set.urls, "https://example.com/b)"));
    }
    SECTION("defanged url is refanged on emission") {
        auto s = std::string("check hxxp://bad[.]example[.]com/payload for IOC");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.urls, "http://bad.example.com/payload"));
        REQUIRE_FALSE(contains(set.urls, "hxxp://bad[.]example[.]com/payload"));
    }
}

TEST_CASE("ipv4 extraction", "[ioc][ipv4]") {
    SECTION("valid addresses") {
        auto s = std::string("hosts 10.0.0.1 and 192.168.1.255 reachable");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.ipv4, "10.0.0.1"));
        REQUIRE(contains(set.ipv4, "192.168.1.255"));
    }
    SECTION("rejects out-of-range octet") {
        auto s = std::string("bogus 999.1.1.1 here");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE_FALSE(contains(set.ipv4, "999.1.1.1"));
    }
    SECTION("rejects three-octet fragment") {
        auto s = std::string("not-an-ip 1.2.3 nope");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE_FALSE(contains(set.ipv4, "1.2.3"));
    }
}

TEST_CASE("domain extraction", "[ioc][domain]") {
    SECTION("extracts real-looking hostname") {
        auto s = std::string("beacon to attacker.example.com observed");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.domains, "attacker.example.com"));
    }
    SECTION("rejects common document filenames") {
        auto s = std::string("opened file.txt and readme.md from disk");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE_FALSE(contains(set.domains, "file.txt"));
        REQUIRE_FALSE(contains(set.domains, "readme.md"));
    }
}

TEST_CASE("hash extraction", "[ioc][hash]") {
    SECTION("md5 32-hex") {
        auto s = std::string("md5 d41d8cd98f00b204e9800998ecf8427e leak");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.md5, "d41d8cd98f00b204e9800998ecf8427e"));
    }
    SECTION("sha1 40-hex") {
        auto s = std::string("sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 observed");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }
    SECTION("sha256 64-hex") {
        auto s = std::string("sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 seen");
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
    SECTION("64-hex inside a 128-hex run is not emitted as sha256") {
        std::string run(128, 'a');
        auto s = std::string("blob ") + run + " end";
        auto set = zdr::ioc::extract(as_bytes(s));
        std::string inner = run.substr(0, 64);
        REQUIRE_FALSE(contains(set.sha256, inner));
    }
    SECTION("64-hex separated by spaces from surrounding hex is emitted") {
        std::string target = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        std::string noise(64, 'a');
        auto s = noise + " " + target + " " + noise;
        auto set = zdr::ioc::extract(as_bytes(s));
        REQUIRE(contains(set.sha256, target));
    }
}

TEST_CASE("base64 extraction", "[ioc][base64]") {
    SECTION("mixed-case 80-char run is emitted") {
        std::string blob(40, 'A');
        blob.append(40, 'b');
        auto set = zdr::ioc::extract(as_bytes(blob));
        REQUIRE(contains(set.base64_blobs, blob));
    }
    SECTION("all-digit run is not emitted") {
        std::string digits;
        for (int i = 0; i < 5; ++i) digits += "0123456789";
        auto set = zdr::ioc::extract(as_bytes(digits));
        REQUIRE_FALSE(contains(set.base64_blobs, digits));
    }
    SECTION("plausible base64 string is emitted") {
        std::string b64 = "VGhpc0lzQVJlYXNvbmFibHlMb25nQmFzZTY0U3RyaW5nV2l0aE1peGVkQ2FzZUNoYXJz";
        auto set = zdr::ioc::extract(as_bytes(b64));
        REQUIRE(contains(set.base64_blobs, b64));
    }
}
