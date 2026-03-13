# Homebrew formula for Aegis
#
# This file is a template. During release, the CI pipeline replaces
# PLACEHOLDER_VERSION and SHA256 values with real ones and pushes the
# result to the markm39/homebrew-tap repo.
#
# To install: brew install markm39/tap/aegis
# To update:  brew upgrade aegis

class Aegis < Formula
  desc "AI agent security testing: adversarial probes for coding agents"
  homepage "https://github.com/markm39/aegis"
  version "PLACEHOLDER_VERSION"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/markm39/aegis/releases/download/v#{version}/aegis-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    end
    if Hardware::CPU.intel?
      url "https://github.com/markm39/aegis/releases/download/v#{version}/aegis-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_SHA256"
    end
  end

  def install
    bin.install "aegis"
    bin.install "aegis-probe"

    generate_completions_from_executable(bin/"aegis", "completions")
    generate_completions_from_executable(bin/"aegis-probe", "completions")

    man_output = Utils.safe_popen_read(bin/"aegis", "manpage")
    (man1/"aegis.1").write(man_output)
  end

  def caveats
    <<~EOS
      To get started with security testing:
        aegis-probe run --agent-binary claude  # test an agent
        aegis-probe list --probes-dir probes   # list available probes
        aegis-probe validate --probes-dir probes  # validate probe files

      Shell completions have been installed. Restart your terminal to activate them.
    EOS
  end

  test do
    assert_match "aegis", shell_output("#{bin}/aegis --version")
    assert_match "aegis-probe", shell_output("#{bin}/aegis-probe --version")
  end
end
