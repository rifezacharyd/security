# zdr-triage

Fast, single-binary file triage for incident response and audit. Emits SHA-256, magic-byte file type, Shannon entropy, and embedded IOCs (URLs, IPs, domains, emails) as a single NDJSON line per file. ARM-optimized C++20, local-only, no network calls, no telemetry.

## Usage

```sh
zdr-triage sample.bin
zdr-triage --text sample.bin
```

Sample NDJSON output:

```json
{"path":"sample.bin","size":20480,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","magic":"PE32+","entropy":7.81,"iocs":{"urls":["https://evil.example/x"],"ips":["10.0.0.4"],"domains":["evil.example"],"emails":[]}}
```

`--text` switches to a human-readable multi-line report; default output is NDJSON suitable for piping into jq or a SIEM.

## Build

macOS (arm64):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Linux (x86_64 or arm64):

```sh
sudo apt-get install -y libssl-dev cmake build-essential
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## About

Part of ZDR Development LLC's Custom Security Tooling product line — veteran-owned, SW Virginia. More at [zerodayresearch.dev](https://zerodayresearch.dev).

## License

BUSL-1.1 — free for non-commercial use; commercial licensing via [zerodayresearch.dev](https://zerodayresearch.dev).
