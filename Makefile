NAME := wgh3
CARGO := cargo
FLAGS := --release

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
SYSCONFDIR ?= /etc
UNITDIR ?= $(PREFIX)/lib/systemd/system

BIN := target/release/$(NAME)
SERVICE := configs/$(NAME).service
CLIENT_CONFIG := configs/client.toml
SERVER_CONFIG := configs/server.toml

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

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(NAME)
	install -d $(DESTDIR)$(SYSCONFDIR)/$(NAME)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 $(SERVICE) $(DESTDIR)$(UNITDIR)/$(NAME).service
	install -m 0644 $(CLIENT_CONFIG) $(DESTDIR)$(SYSCONFDIR)/$(NAME)/client.toml
	install -m 0644 $(SERVER_CONFIG) $(DESTDIR)$(SYSCONFDIR)/$(NAME)/server.toml

uninstall:
	rm -fr $(DESTDIR)$(BINDIR)/$(NAME)
	rm -fr $(DESTDIR)$(SYSCONFDIR)/$(NAME)
	rm -fr $(DESTDIR)$(UNITDIR)/$(NAME).service
