#include "zdr/triage.hpp"
#include "zdr/hashing.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace {

int usage() {
    std::fprintf(stderr, "usage: zdr-triage [--ndjson|--text] <file>\n");
    return 1;
}

void print_text(const zdr::Report& r) {
    std::cout << "path:    " << r.path.string() << '\n'
              << "size:    " << r.size << '\n'
              << "sha256:  " << zdr::hashing::hex(r.sha256) << '\n'
              << "kind:    " << zdr::to_string(r.kind) << '\n'
              << "entropy: " << std::fixed << std::setprecision(4) << r.entropy << '\n'
              << "iocs:\n"
              << "  urls:         " << r.iocs.urls.size() << '\n'
              << "  ipv4:         " << r.iocs.ipv4.size() << '\n'
              << "  domains:      " << r.iocs.domains.size() << '\n'
              << "  md5:          " << r.iocs.md5.size() << '\n'
              << "  sha1:         " << r.iocs.sha1.size() << '\n'
              << "  sha256:       " << r.iocs.sha256.size() << '\n'
              << "  base64_blobs: " << r.iocs.base64_blobs.size() << '\n';
    if (!r.error.empty()) {
        std::cout << "error:   " << r.error << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    bool ndjson = true;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        if (a == "--ndjson") {
            ndjson = true;
        } else if (a == "--text") {
            ndjson = false;
        } else if (!a.empty() && a[0] == '-') {
            return usage();
        } else if (!path) {
            path = argv[i];
        } else {
            return usage();
        }
    }

    if (!path) return usage();

    auto report = zdr::triage_file(std::filesystem::path(path));

    if (ndjson) {
        std::cout << zdr::to_ndjson(report) << '\n';
    } else {
        print_text(report);
    }

    return report.error.empty() ? 0 : 2;
}
