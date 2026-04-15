#include "zdr/triage.hpp"
#include "zdr/hashing.hpp"

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace zdr {

namespace {

void write_escaped(std::ostringstream& os, std::string_view s) {
    os << '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b"; break;
            case '\f': os << "\\f"; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                if (c < 0x20) {
                    os << "\\u00"
                       << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<int>(c)
                       << std::dec << std::setfill(' ');
                } else {
                    os << static_cast<char>(c);
                }
        }
    }
    os << '"';
}

void write_string_array(std::ostringstream& os,
                        std::string_view key,
                        const std::vector<std::string>& v,
                        bool trailing_comma) {
    write_escaped(os, key);
    os << ":[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) os << ',';
        write_escaped(os, v[i]);
    }
    os << ']';
    if (trailing_comma) os << ',';
}

}  // namespace

std::string to_ndjson(const Report& r) {
    std::ostringstream os;
    os << '{';

    write_escaped(os, "path");
    os << ':';
    write_escaped(os, r.path.string());
    os << ',';

    write_escaped(os, "size");
    os << ':' << r.size << ',';

    write_escaped(os, "sha256");
    os << ':';
    write_escaped(os, hashing::hex(r.sha256));
    os << ',';

    write_escaped(os, "kind");
    os << ':';
    write_escaped(os, to_string(r.kind));
    os << ',';

    write_escaped(os, "entropy");
    os << ':' << std::fixed << std::setprecision(6) << r.entropy;
    os.unsetf(std::ios_base::floatfield);
    os << ',';

    write_escaped(os, "iocs");
    os << ":{";
    write_string_array(os, "urls", r.iocs.urls, true);
    write_string_array(os, "ipv4", r.iocs.ipv4, true);
    write_string_array(os, "domains", r.iocs.domains, true);
    write_string_array(os, "md5", r.iocs.md5, true);
    write_string_array(os, "sha1", r.iocs.sha1, true);
    write_string_array(os, "sha256", r.iocs.sha256, true);
    write_string_array(os, "base64_blobs", r.iocs.base64_blobs, false);
    os << '}';

    if (!r.error.empty()) {
        os << ',';
        write_escaped(os, "error");
        os << ':';
        write_escaped(os, r.error);
    }

    os << '}';
    return os.str();
}

}  // namespace zdr
