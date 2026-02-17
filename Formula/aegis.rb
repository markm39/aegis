# Homebrew formula for Aegis
#
# This file is a template. During release, the CI pipeline replaces
# PLACEHOLDER_VERSION and SHA256 values with real ones and pushes the
# result to the markm39/homebrew-tap repo.
#
# To install: brew install markm39/tap/aegis
# To update:  brew upgrade aegis

class Aegis < Formula
  desc "Zero-trust runtime for AI agents with per-file observability and Cedar policy enforcement"
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

    generate_completions_from_executable(bin/"aegis", "completions")

    man_output = Utils.safe_popen_read(bin/"aegis", "manpage")
    (man1/"aegis.1").write(man_output)
  end

  def post_install
    system bin/"aegis", "setup"
  end

  def caveats
    <<~EOS
      To get started:
        aegis init            # interactive setup wizard
        aegis wrap -- claude  # observe any command
        aegis pilot -- claude # supervise with auto-approval

      Shell completions have been installed. Restart your terminal to activate them.
    EOS
  end

  test do
    assert_match "aegis", shell_output("#{bin}/aegis --version")
  end
end
