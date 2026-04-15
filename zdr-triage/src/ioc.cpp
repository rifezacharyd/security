#include "zdr/ioc.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <unordered_set>

namespace zdr::ioc {

namespace {

inline bool is_alpha(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}
inline bool is_digit(unsigned char c) { return c >= '0' && c <= '9'; }
inline bool is_alnum(unsigned char c) { return is_alpha(c) || is_digit(c); }
inline bool is_lower(unsigned char c) { return c >= 'a' && c <= 'z'; }
inline bool is_upper(unsigned char c) { return c >= 'A' && c <= 'Z'; }
inline bool is_hex(unsigned char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
inline bool is_url_tail(unsigned char c) {
    // RFC 3986 unreserved + common sub-delims + gen-delims minus terminators.
    if (is_alnum(c)) return true;
    switch (c) {
        case '-': case '.': case '_': case '~':
        case ':': case '/': case '?': case '#':
        case '[': case ']': case '@':
        case '!': case '$': case '&': case '\'':
        case '(': case ')': case '*': case '+':
        case ',': case ';': case '=':
        case '%':
            return true;
        default:
            return false;
    }
}
inline bool is_domain_char(unsigned char c) {
    return is_alnum(c) || c == '-' || c == '.';
}
inline bool is_base64_char(unsigned char c) {
    return is_alnum(c) || c == '+' || c == '/' || c == '=';
}

// Trim trailing punctuation likely to be text rather than URL.
std::string_view trim_url_tail(std::string_view s) {
    while (!s.empty()) {
        const char c = s.back();
        if (c == '.' || c == ',' || c == ';' || c == ':' || c == ')' ||
            c == ']' || c == '}' || c == '>' || c == '"' || c == '\'' || c == '!' ||
            c == '?') {
            s.remove_suffix(1);
        } else {
            break;
        }
    }
    return s;
}

bool valid_ipv4(std::string_view s) {
    int octets = 0;
    std::size_t i = 0;
    while (i < s.size()) {
        int val = 0;
        int digits = 0;
        const std::size_t octet_start = i;
        while (i < s.size() && is_digit(static_cast<unsigned char>(s[i]))) {
            val = val * 10 + (s[i] - '0');
            ++digits;
            if (digits > 3 || val > 255) return false;
            ++i;
        }
        if (digits == 0) return false;
        // Reject leading zeros (e.g. "001") — ambiguous with octal in some tools.
        if (digits > 1 && s[octet_start] == '0') return false;
        ++octets;
        if (i < s.size() && s[i] == '.') {
            ++i;
            if (i == s.size()) return false;
        }
    }
    if (octets != 4) return false;
    // Reject all-zero and broadcast.
    if (s == "0.0.0.0" || s == "255.255.255.255") return false;
    return true;
}

// File-extension deny-list for bare-domain TLDs (reduces false positives on
// filenames like "config.ini", "notes.txt").
bool is_denied_tld(std::string_view tld) {
    static constexpr std::string_view kDenied[] = {
        "txt", "ini", "log", "md", "json", "yaml", "yml", "xml",
        "csv", "tsv", "cpp", "hpp", "py", "js", "ts", "go", "rs",
        "exe", "dll", "so", "dylib",
    };
    std::string lower(tld);
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }
    for (auto d : kDenied) if (lower == d) return true;
    return false;
}

bool valid_domain(std::string_view s) {
    // Must have at least one dot, TLD is ≥ 2 alpha chars, labels non-empty,
    // no leading/trailing hyphen, max 63 chars per label.
    if (s.size() < 4 || s.size() > 253) return false;
    std::size_t start = 0;
    std::size_t dots = 0;
    std::string_view last_label;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        const bool end = (i == s.size());
        if (end || s[i] == '.') {
            const auto label = s.substr(start, i - start);
            if (label.empty() || label.size() > 63) return false;
            if (label.front() == '-' || label.back() == '-') return false;
            last_label = label;
            if (!end) ++dots;
            start = i + 1;
        }
    }
    if (dots == 0) return false;
    if (last_label.size() < 2) return false;
    for (char c : last_label) {
        if (!is_alpha(static_cast<unsigned char>(c))) return false;
    }
    if (is_denied_tld(last_label)) return false;
    return true;
}

// Push-unique helper.
struct UniqueSink {
    std::vector<std::string>& out;
    std::unordered_set<std::string> seen;
    void push(std::string_view v) {
        std::string s(v);
        if (seen.insert(s).second) out.push_back(std::move(s));
    }
    void push(std::string&& s) {
        if (seen.insert(s).second) out.push_back(std::move(s));
    }
};

// Re-fang a defanged URL/host fragment: hxxp→http, hxxps→https,
// [.]/(.)/{.} →., [:]→:. Operates on a copy.
std::string refang(std::string_view in) {
    std::string s(in);
    // Scheme prefix — case-insensitive match on hxxp(s)://
    auto starts_with_ci = [](const std::string& str, std::string_view pfx) {
        if (str.size() < pfx.size()) return false;
        for (std::size_t i = 0; i < pfx.size(); ++i) {
            char a = str[i];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
            if (a != pfx[i]) return false;
        }
        return true;
    };
    if (starts_with_ci(s, "hxxps://")) s.replace(0, 8, "https://");
    else if (starts_with_ci(s, "hxxp://")) s.replace(0, 7, "http://");

    // Replace bracketed separators anywhere in the string.
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (i + 3 <= s.size() &&
            (s[i] == '[' || s[i] == '(' || s[i] == '{') &&
            (s[i + 2] == ']' || s[i + 2] == ')' || s[i + 2] == '}')) {
            const char mid = s[i + 1];
            if (mid == '.' || mid == ':') {
                out.push_back(mid);
                i += 3;
                continue;
            }
        }
        out.push_back(s[i]);
        ++i;
    }
    return out;
}

// Character class for defanged-URL tails — superset of is_url_tail that also
// allows the bracket-wrappers we will strip during refang.
inline bool is_defanged_url_tail(unsigned char c) {
    return is_url_tail(c) || c == '{' || c == '}';
}

void scan_urls_and_domains(std::string_view text, IocSet& /*out*/,
                           UniqueSink& urls, UniqueSink& domains) {
    // Schemes in fanged and common defanged forms. We do NOT extract
    // schemeless URLs — keeps false-positive rate down on code/text blobs.
    static constexpr std::string_view kSchemes[] = {
        "http://", "https://", "ftp://",
        "hxxp://", "hxxps://", "hXXp://", "hXXps://",
        "hxxp[://]", "hxxps[://]",
    };

    for (auto scheme : kSchemes) {
        std::size_t pos = 0;
        while ((pos = text.find(scheme, pos)) != std::string_view::npos) {
            std::size_t end = pos + scheme.size();
            while (end < text.size() &&
                   is_defanged_url_tail(static_cast<unsigned char>(text[end]))) {
                ++end;
            }
            auto url = trim_url_tail(text.substr(pos, end - pos));
            if (url.size() > scheme.size()) {
                std::string fanged = refang(url);
                if (fanged.size() > 0) urls.push(std::move(fanged));
            }
            pos = end;
        }
    }

    // Domain pass (bare): scan tokens separated by non-domain chars.
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() &&
               !is_domain_char(static_cast<unsigned char>(text[i]))) {
            ++i;
        }
        std::size_t start = i;
        while (i < text.size() &&
               is_domain_char(static_cast<unsigned char>(text[i]))) {
            ++i;
        }
        if (start == i) continue;
        auto tok = text.substr(start, i - start);
        while (!tok.empty() && tok.front() == '.') tok.remove_prefix(1);
        while (!tok.empty() && tok.back() == '.')  tok.remove_suffix(1);
        if (valid_domain(tok)) domains.push(tok);
    }
}

void scan_ipv4(std::string_view text, UniqueSink& sink) {
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && !is_digit(static_cast<unsigned char>(text[i]))) ++i;
        std::size_t start = i;
        int dots = 0;
        while (i < text.size()) {
            const unsigned char c = static_cast<unsigned char>(text[i]);
            if (is_digit(c)) { ++i; continue; }
            if (c == '.')    { ++dots; ++i; continue; }
            break;
        }
        if (dots == 3) {
            auto tok = text.substr(start, i - start);
            if (tok.back() == '.') tok.remove_suffix(1);
            if (valid_ipv4(tok)) sink.push(tok);
        }
    }
}

void scan_hashes(std::string_view text, UniqueSink& md5, UniqueSink& sha1,
                 UniqueSink& sha256) {
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && !is_hex(static_cast<unsigned char>(text[i]))) ++i;
        std::size_t start = i;
        while (i < text.size() && is_hex(static_cast<unsigned char>(text[i]))) ++i;
        const std::size_t len = i - start;
        if (len == 32) md5.push(text.substr(start, len));
        else if (len == 40) sha1.push(text.substr(start, len));
        else if (len == 64) sha256.push(text.substr(start, len));
    }
}

void scan_base64(std::string_view text, UniqueSink& sink) {
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && !is_base64_char(static_cast<unsigned char>(text[i]))) ++i;
        std::size_t start = i;
        std::size_t digits = 0, lowers = 0, uppers = 0, specials = 0, total = 0;
        while (i < text.size() && is_base64_char(static_cast<unsigned char>(text[i]))) {
            const unsigned char c = static_cast<unsigned char>(text[i]);
            if (is_digit(c)) ++digits;
            else if (is_lower(c)) ++lowers;
            else if (is_upper(c)) ++uppers;
            else if (c == '+' || c == '/') ++specials;
            ++total;
            ++i;
        }
        if (total < 32) continue;
        // Heuristics: reject digit-dominant runs (timestamps, IDs) and hex-only
        // runs (already covered by hash scanner). Require mixed case OR a
        // base64-only special char.
        if (digits * 2 > total) continue;
        const bool has_mixed_case = (lowers > 0 && uppers > 0);
        const bool has_special = (specials > 0);
        if (!has_mixed_case && !has_special) continue;
        sink.push(text.substr(start, total));
    }
}

}  // namespace

IocSet extract(std::span<const std::uint8_t> bytes) {
    IocSet out;
    const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    UniqueSink urls{out.urls, {}};
    UniqueSink ipv4{out.ipv4, {}};
    UniqueSink domains{out.domains, {}};
    UniqueSink md5{out.md5, {}};
    UniqueSink sha1{out.sha1, {}};
    UniqueSink sha256{out.sha256, {}};
    UniqueSink b64{out.base64_blobs, {}};

    scan_urls_and_domains(text, out, urls, domains);
    scan_ipv4(text, ipv4);
    scan_hashes(text, md5, sha1, sha256);
    scan_base64(text, b64);

    return out;
}

}  // namespace zdr::ioc
