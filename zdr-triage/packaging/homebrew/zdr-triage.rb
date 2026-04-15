class ZdrTriage < Formula
  desc "Fast single-binary file triage for incident response and audit"
  homepage "https://zerodayresearch.dev"
  url "https://github.com/rifezacharyd/security/archive/refs/tags/zdr-triage-v0.1.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "BUSL-1.1"

  depends_on "cmake" => :build
  depends_on "openssl@3"

  def install
    cd "zdr-triage" do
      system "cmake", "-S", ".", "-B", "build", *std_cmake_args
      system "cmake", "--build", "build", "-j"
      bin.install "build/zdr-triage"
    end
  end

  test do
    fixture = testpath/"fixture.bin"
    fixture.write("MZ\x90\x00hello zdr-triage test fixture")
    output = shell_output("#{bin}/zdr-triage --ndjson #{fixture}")
    assert !output.strip.empty?, "expected non-empty NDJSON output"
  end
end
