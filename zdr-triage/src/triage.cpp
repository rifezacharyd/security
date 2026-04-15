#include "zdr/triage.hpp"
#include "zdr/hashing.hpp"
#include "zdr/magic.hpp"
#include "zdr/entropy.hpp"
#include "zdr/ioc.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <span>
#include <string_view>
#include <vector>

namespace zdr {

std::string_view to_string(FileKind k) noexcept {
    switch (k) {
        case FileKind::Unknown: return "unknown";
        case FileKind::Elf:     return "elf";
        case FileKind::MachO:   return "macho";
        case FileKind::Pe:      return "pe";
        case FileKind::Zip:     return "zip";
        case FileKind::Gzip:    return "gzip";
        case FileKind::Png:     return "png";
        case FileKind::Jpeg:    return "jpeg";
        case FileKind::Pdf:     return "pdf";
        case FileKind::Text:    return "text";
    }
    return "unknown";
}

Report triage_file(const std::filesystem::path& p, Options opts) noexcept {
    Report r;
    r.path = p;
    try {
        std::error_code ec;
        auto sz = std::filesystem::file_size(p, ec);
        if (ec) {
            r.error = ec.message();
            return r;
        }
        r.size = sz;

        std::ifstream in(p, std::ios::binary);
        if (!in) {
            r.error = "failed to open file";
            return r;
        }

        hashing::Sha256Streamer sha;
        std::array<std::uint8_t, 8> head{};
        std::size_t head_filled = 0;
        std::vector<std::uint8_t> window;
        window.reserve(std::min<std::size_t>(opts.ioc_window, static_cast<std::size_t>(sz)));

        constexpr std::size_t kChunk = 64 * 1024;
        std::vector<std::uint8_t> buf(kChunk);

        while (in) {
            in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(kChunk));
            auto got = static_cast<std::size_t>(in.gcount());
            if (got == 0) break;

            std::span<const std::uint8_t> chunk(buf.data(), got);
            sha.update(chunk);

            if (head_filled < head.size()) {
                std::size_t take = std::min(head.size() - head_filled, got);
                std::copy_n(buf.begin(), take, head.begin() + head_filled);
                head_filled += take;
            }

            if (window.size() < opts.ioc_window) {
                std::size_t remaining = opts.ioc_window - window.size();
                std::size_t take = std::min(remaining, got);
                window.insert(window.end(), buf.begin(), buf.begin() + take);
            }
        }

        r.sha256 = sha.finalize();
        r.kind = magic::detect(std::span<const std::uint8_t>(head.data(), head_filled));
        r.entropy = entropy::shannon(std::span<const std::uint8_t>(window));
        if (opts.extract_iocs) {
            r.iocs = ioc::extract(std::span<const std::uint8_t>(window));
        }
    } catch (const std::exception& e) {
        r.error = e.what();
    } catch (...) {
        r.error = "unknown exception";
    }
    return r;
}

Report triage_buffer(std::span<const std::uint8_t> bytes,
                     const std::filesystem::path& label_path,
                     Options opts) noexcept {
    Report r;
    r.path = label_path;
    try {
        r.size = bytes.size();
        r.sha256 = hashing::sha256(bytes);

        std::size_t head_n = std::min<std::size_t>(8, bytes.size());
        r.kind = magic::detect(bytes.first(head_n));

        std::size_t win_n = std::min(opts.ioc_window, bytes.size());
        auto window = bytes.first(win_n);
        r.entropy = entropy::shannon(window);
        if (opts.extract_iocs) {
            r.iocs = ioc::extract(window);
        }
    } catch (const std::exception& e) {
        r.error = e.what();
    } catch (...) {
        r.error = "unknown exception";
    }
    return r;
}

}  // namespace zdr
