#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace zdr::hashing {

// SHA-256 via OpenSSL's EVP. Picks up ARMv8 SHA-256 crypto extensions
// automatically when available.
std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> bytes) noexcept;

// Incremental variant for streaming large files without mmap pressure.
class Sha256Streamer {
  public:
    Sha256Streamer();
    Sha256Streamer(const Sha256Streamer&) = delete;
    Sha256Streamer& operator=(const Sha256Streamer&) = delete;
    Sha256Streamer(Sha256Streamer&&) noexcept;
    Sha256Streamer& operator=(Sha256Streamer&&) noexcept;
    ~Sha256Streamer();

    void update(std::span<const std::uint8_t> chunk) noexcept;
    std::array<std::uint8_t, 32> finalize() noexcept;

  private:
    void* ctx_;  // EVP_MD_CTX*; hidden to avoid leaking OpenSSL into the header
};

std::string hex(std::span<const std::uint8_t> bytes);

}  // namespace zdr::hashing
