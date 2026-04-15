#include "zdr/hashing.hpp"

#include <openssl/evp.h>

#include <utility>

namespace zdr::hashing {

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> bytes) noexcept {
    std::array<std::uint8_t, 32> out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return out;
    unsigned int len = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1) {
        EVP_DigestFinal_ex(ctx, out.data(), &len);
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

Sha256Streamer::Sha256Streamer() : ctx_(EVP_MD_CTX_new()) {
    if (ctx_) {
        EVP_DigestInit_ex(static_cast<EVP_MD_CTX*>(ctx_), EVP_sha256(), nullptr);
    }
}

Sha256Streamer::Sha256Streamer(Sha256Streamer&& other) noexcept
    : ctx_(std::exchange(other.ctx_, nullptr)) {}

Sha256Streamer& Sha256Streamer::operator=(Sha256Streamer&& other) noexcept {
    if (this != &other) {
        if (ctx_) EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
        ctx_ = std::exchange(other.ctx_, nullptr);
    }
    return *this;
}

Sha256Streamer::~Sha256Streamer() {
    if (ctx_) EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
}

void Sha256Streamer::update(std::span<const std::uint8_t> chunk) noexcept {
    if (!ctx_ || chunk.empty()) return;
    EVP_DigestUpdate(static_cast<EVP_MD_CTX*>(ctx_), chunk.data(), chunk.size());
}

std::array<std::uint8_t, 32> Sha256Streamer::finalize() noexcept {
    std::array<std::uint8_t, 32> out{};
    if (!ctx_) return out;
    unsigned int len = 0;
    EVP_DigestFinal_ex(static_cast<EVP_MD_CTX*>(ctx_), out.data(), &len);
    return out;
}

std::string hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[2 * i]     = kHex[bytes[i] >> 4];
        out[2 * i + 1] = kHex[bytes[i] & 0x0F];
    }
    return out;
}

}  // namespace zdr::hashing
