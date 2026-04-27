NAME := wgh3
CARGO := cargo
FLAGS := --release

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
UNITDIR ?= $(PREFIX)/lib/systemd/system
SYSCTLDIR ?= $(PREFIX)/lib/sysctl.d
SYSCONFDIR ?= /etc

BIN := target/release/$(NAME)
SYSCTL := configs/$(NAME)-sysctl.conf
SERVICE := configs/$(NAME).service

.PHONY: all build test check fmt fmt-check clippy clean install uninstall

all: build

build:
	$(CARGO) build $(FLAGS)

test:
	$(CARGO) test

check:
	$(CARGO) check --all-targets

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt -- --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

clean:
	$(CARGO) clean

reload:
	sudo sysctl --system
	sudo systemctl daemon-reload
	sudo systemctl restart $(NAME)

install:
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(UNITDIR)
	install -d $(DESTDIR)$(SYSCTLDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)/$(NAME)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(NAME)
	install -m 0600 configs/client.toml $(DESTDIR)$(SYSCONFDIR)/$(NAME)
	install -m 0600 configs/server.toml $(DESTDIR)$(SYSCONFDIR)/$(NAME)
	install -m 0644 $(SERVICE) $(DESTDIR)$(UNITDIR)/$(NAME).service
	install -m 0644 $(SYSCTL) $(DESTDIR)$(SYSCTLDIR)/60-$(NAME).conf

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(NAME)
	rm -f $(DESTDIR)$(UNITDIR)/$(NAME).service
	rm -f $(DESTDIR)$(SYSCTLDIR)/60-$(NAME).conf
