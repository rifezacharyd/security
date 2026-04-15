#pragma once

#include <cstdint>
#include <span>

#include "zdr/triage.hpp"

namespace zdr::ioc {

// Extract IOCs from a buffer. Scans ASCII only — UTF-16 support is planned.
IocSet extract(std::span<const std::uint8_t> bytes);

}  // namespace zdr::ioc
