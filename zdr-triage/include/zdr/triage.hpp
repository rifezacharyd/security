// zdr-triage — public API
//
// One-shot structured triage of a file: hash, magic, entropy, extracted IOCs.
// Everything here is read-only; the library never mutates the target file.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace zdr {

enum class FileKind : std::uint8_t {
    Unknown,
    Elf,
    MachO,
    Pe,
    Zip,
    Gzip,
    Png,
    Jpeg,
    Pdf,
    Text,
};

std::string_view to_string(FileKind k) noexcept;

struct IocSet {
    std::vector<std::string> urls;
    std::vector<std::string> ipv4;
    std::vector<std::string> domains;
    std::vector<std::string> md5;
    std::vector<std::string> sha1;
    std::vector<std::string> sha256;
    std::vector<std::string> base64_blobs;  // base64 runs >= 32 chars
};

struct Report {
    std::filesystem::path path;
    std::uintmax_t size = 0;
    std::array<std::uint8_t, 32> sha256{};
    FileKind kind = FileKind::Unknown;
    double entropy = 0.0;  // Shannon entropy, bits per byte [0.0, 8.0]
    IocSet iocs{};
    std::string error{};   // populated if triage failed; other fields invalid
};

// Pre-sized read ceiling. Files larger than this are triaged by streaming
// but IOC extraction only sees the first N bytes — the default matches
// typical malware sample + office-doc sizes.
constexpr std::size_t kDefaultIocWindow = 16 * 1024 * 1024;  // 16 MiB

struct Options {
    std::size_t ioc_window = kDefaultIocWindow;
    bool extract_iocs = true;
};

// Triage a file on disk. Never throws — errors are surfaced via
// Report::error. Safe for parallel invocation on distinct paths.
Report triage_file(const std::filesystem::path& p, Options opts = {}) noexcept;

// Triage an in-memory buffer (for unit tests and future streaming modes).
// The buffer must outlive the returned Report's IOC string_views — IOCs are
// copied, so this is already the case.
Report triage_buffer(std::span<const std::uint8_t> bytes,
                     const std::filesystem::path& label_path = {},
                     Options opts = {}) noexcept;

// Serialize a single report as one NDJSON line, no trailing newline.
std::string to_ndjson(const Report& r);

}  // namespace zdr
