#include "zdr/magic.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace zdr::magic {

namespace {

struct Sig {
    const std::uint8_t* bytes;
    std::size_t len;
    FileKind kind;
};

bool starts_with(std::span<const std::uint8_t> b, const std::uint8_t* sig, std::size_t n) {
    return b.size() >= n && std::memcmp(b.data(), sig, n) == 0;
}

// Heuristic: looks "texty" if the first N bytes are printable ASCII or
// common whitespace. Used only when no magic matched.
bool looks_textual(std::span<const std::uint8_t> b) {
    const std::size_t n = std::min<std::size_t>(b.size(), 512);
    if (n == 0) return false;
    std::size_t printable = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const auto c = b[i];
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7E)) {
            ++printable;
        } else if (c == 0) {
            return false;
        }
    }
    return printable * 10 >= n * 9;  // ≥90% printable
}

}  // namespace

FileKind detect(std::span<const std::uint8_t> b) noexcept {
    static constexpr std::uint8_t kElf[]    = {0x7F, 'E', 'L', 'F'};
    static constexpr std::uint8_t kPe[]     = {'M', 'Z'};
    static constexpr std::uint8_t kZip[]    = {'P', 'K', 0x03, 0x04};
    static constexpr std::uint8_t kZipEmpty[] = {'P', 'K', 0x05, 0x06};
    static constexpr std::uint8_t kGzip[]   = {0x1F, 0x8B};
    static constexpr std::uint8_t kPng[]    = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    static constexpr std::uint8_t kJpeg[]   = {0xFF, 0xD8, 0xFF};
    static constexpr std::uint8_t kPdf[]    = {'%', 'P', 'D', 'F', '-'};
    static constexpr std::uint8_t kMachO32[] = {0xFE, 0xED, 0xFA, 0xCE};
    static constexpr std::uint8_t kMachO64[] = {0xFE, 0xED, 0xFA, 0xCF};
    static constexpr std::uint8_t kMachO32R[] = {0xCE, 0xFA, 0xED, 0xFE};
    static constexpr std::uint8_t kMachO64R[] = {0xCF, 0xFA, 0xED, 0xFE};
    static constexpr std::uint8_t kMachOFat1[] = {0xCA, 0xFE, 0xBA, 0xBE};
    static constexpr std::uint8_t kMachOFat2[] = {0xBE, 0xBA, 0xFE, 0xCA};

    if (starts_with(b, kElf, sizeof(kElf))) return FileKind::Elf;
    if (starts_with(b, kMachO32, 4) || starts_with(b, kMachO64, 4) ||
        starts_with(b, kMachO32R, 4) || starts_with(b, kMachO64R, 4) ||
        starts_with(b, kMachOFat1, 4) || starts_with(b, kMachOFat2, 4))
        return FileKind::MachO;
    if (starts_with(b, kPng, sizeof(kPng)))  return FileKind::Png;
    if (starts_with(b, kJpeg, sizeof(kJpeg))) return FileKind::Jpeg;
    if (starts_with(b, kPdf, sizeof(kPdf)))  return FileKind::Pdf;
    if (starts_with(b, kGzip, sizeof(kGzip))) return FileKind::Gzip;
    if (starts_with(b, kZip, sizeof(kZip)) || starts_with(b, kZipEmpty, sizeof(kZipEmpty)))
        return FileKind::Zip;
    if (starts_with(b, kPe, sizeof(kPe)))    return FileKind::Pe;
    if (looks_textual(b))                    return FileKind::Text;
    return FileKind::Unknown;
}

}  // namespace zdr::magic
