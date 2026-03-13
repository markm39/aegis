# Aegis developer Makefile
#
# Targets:
#   make build          Build release binary
#   make install        Install to PREFIX with completions
#   make uninstall      Remove installed files
#   make completions    Generate shell completions to ./completions/
#   make test           Run all tests
#   make lint           Run clippy
#   make check          Lint + test
#   make clean          Cargo clean + remove generated artifacts
#   make dist           Create release tarball with checksums

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
ZSH_COMPLETIONS_DIR = $(PREFIX)/share/zsh/site-functions
BASH_COMPLETIONS_DIR = $(PREFIX)/etc/bash_completion.d
FISH_COMPLETIONS_DIR = $(PREFIX)/share/fish/vendor_completions.d

VERSION = $(shell grep '^version' crates/aegis-probe/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
TARGET = $(shell rustc -vV | grep host | cut -d' ' -f2)
BINARY = target/release/aegis-probe

.PHONY: build install uninstall completions test lint check clean dist

build:
	cargo build --release -p aegis-probe

$(BINARY): build

install: $(BINARY)
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/aegis-probe
	@echo "Installed aegis-probe to $(BINDIR)/aegis-probe"
	install -d $(ZSH_COMPLETIONS_DIR)
	$(BINARY) completions zsh > $(ZSH_COMPLETIONS_DIR)/_aegis-probe
	install -d $(BASH_COMPLETIONS_DIR)
	$(BINARY) completions bash > $(BASH_COMPLETIONS_DIR)/aegis-probe
	install -d $(FISH_COMPLETIONS_DIR)
	$(BINARY) completions fish > $(FISH_COMPLETIONS_DIR)/aegis-probe.fish
	@echo "Installed shell completions"

uninstall:
	rm -f $(BINDIR)/aegis-probe
	rm -f $(ZSH_COMPLETIONS_DIR)/_aegis-probe
	rm -f $(BASH_COMPLETIONS_DIR)/aegis-probe
	rm -f $(FISH_COMPLETIONS_DIR)/aegis-probe.fish
	@echo "Aegis uninstalled."

completions: $(BINARY)
	mkdir -p completions
	$(BINARY) completions bash > completions/aegis-probe.bash
	$(BINARY) completions zsh > completions/_aegis-probe
	$(BINARY) completions fish > completions/aegis-probe.fish
	@echo "Generated completions in ./completions/"

test:
	cargo test --workspace

lint:
	cargo clippy --workspace -- -D warnings

check: lint test

clean:
	cargo clean
	rm -rf completions dist

dist: $(BINARY) completions
	mkdir -p dist
	tar czf dist/aegis-probe-$(VERSION)-$(TARGET).tar.gz -C target/release aegis-probe
	cp completions/* dist/
	cd dist && shasum -a 256 aegis-probe-*.tar.gz > aegis-probe-$(VERSION)-checksums.sha256
	@echo "Release artifacts in ./dist/"
