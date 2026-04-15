#pragma once

#include <cstdint>
#include <span>

#include "zdr/triage.hpp"

namespace zdr::magic {

// Best-effort file-kind detection from the first ~8 bytes.
FileKind detect(std::span<const std::uint8_t> bytes) noexcept;

}  // namespace zdr::magic
