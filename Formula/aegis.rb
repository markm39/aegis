# Homebrew formula for Aegis Probe
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
      url "https://github.com/markm39/aegis/releases/download/v#{version}/aegis-probe-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    end
    if Hardware::CPU.intel?
      url "https://github.com/markm39/aegis/releases/download/v#{version}/aegis-probe-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_SHA256"
    end
  end

  def install
    bin.install "aegis-probe"
    generate_completions_from_executable(bin/"aegis-probe", "completions")
  end

  def caveats
    <<~EOS
      To get started with security testing:
        aegis-probe run --agent-binary claude  # test an agent
        aegis-probe list --probes-dir probes   # list available probes
        aegis-probe validate --probes-dir probes  # validate probe files
        aegis-probe registry status  # inspect registry upload config

      Shell completions have been installed. Restart your terminal to activate them.
    EOS
  end

  test do
    assert_match "aegis-probe", shell_output("#{bin}/aegis-probe --version")
  end
end
