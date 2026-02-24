# Aegis developer Makefile
#
# Targets:
#   make build          Build release binary
#   make install        Install to PREFIX with completions and man page
#   make uninstall      Remove installed files
#   make completions    Generate shell completions to ./completions/
#   make manpage        Generate man page to ./man/
#   make test           Run all tests
#   make lint           Run clippy
#   make check          Lint + test
#   make clean          Cargo clean + remove generated artifacts
#   make dist           Create release tarball with checksums

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1
ZSH_COMPLETIONS_DIR = $(PREFIX)/share/zsh/site-functions
BASH_COMPLETIONS_DIR = $(PREFIX)/etc/bash_completion.d
FISH_COMPLETIONS_DIR = $(PREFIX)/share/fish/vendor_completions.d

VERSION = $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
TARGET = $(shell rustc -vV | grep host | cut -d' ' -f2)
BINARY = target/release/aegis

.PHONY: build install uninstall completions manpage test lint check clean dist sync-coding-runtime check-coding-runtime

build:
	cargo build --release

$(BINARY): build

install: $(BINARY)
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/aegis
	@echo "Installed aegis to $(BINDIR)/aegis"
	install -d $(ZSH_COMPLETIONS_DIR)
	$(BINARY) completions zsh > $(ZSH_COMPLETIONS_DIR)/_aegis
	install -d $(BASH_COMPLETIONS_DIR)
	$(BINARY) completions bash > $(BASH_COMPLETIONS_DIR)/aegis
	install -d $(FISH_COMPLETIONS_DIR)
	$(BINARY) completions fish > $(FISH_COMPLETIONS_DIR)/aegis.fish
	@echo "Installed shell completions"
	install -d $(MANDIR)
	$(BINARY) manpage > $(MANDIR)/aegis.1
	@echo "Installed man page"
	@echo ""
	@echo "Run 'aegis setup' to verify the installation."

uninstall:
	rm -f $(BINDIR)/aegis
	rm -f $(ZSH_COMPLETIONS_DIR)/_aegis
	rm -f $(BASH_COMPLETIONS_DIR)/aegis
	rm -f $(FISH_COMPLETIONS_DIR)/aegis.fish
	rm -f $(MANDIR)/aegis.1
	@echo "Aegis uninstalled."

completions: $(BINARY)
	mkdir -p completions
	$(BINARY) completions bash > completions/aegis.bash
	$(BINARY) completions zsh > completions/_aegis
	$(BINARY) completions fish > completions/aegis.fish
	@echo "Generated completions in ./completions/"

manpage: $(BINARY)
	mkdir -p man
	$(BINARY) manpage > man/aegis.1
	@echo "Generated man page at ./man/aegis.1"

test:
	cargo test --workspace

lint:
	cargo clippy --workspace -- -D warnings

check: lint test

clean:
	cargo clean
	rm -rf completions man dist

dist: $(BINARY) completions manpage
	mkdir -p dist
	tar czf dist/aegis-$(VERSION)-$(TARGET).tar.gz -C target/release aegis
	cp completions/* dist/
	cp man/aegis.1 dist/
	cd dist && shasum -a 256 aegis-*.tar.gz > aegis-$(VERSION)-checksums.sha256
	@echo "Release artifacts in ./dist/"

sync-coding-runtime:
	./scripts/sync-coding-runtime.sh

check-coding-runtime:
	./scripts/sync-coding-runtime.sh --check
