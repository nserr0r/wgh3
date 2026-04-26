NAME := wgh3
CARGO := cargo
FLAGS := --release

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
SYSCONFDIR ?= /etc
UNITDIR ?= $(PREFIX)/lib/systemd/system
SYSCTLDIR ?= $(PREFIX)/lib/sysctl.d

BIN := target/release/$(NAME)
SERVICE := configs/$(NAME).service
SYSCTL := configs/$(NAME)-sysctl.conf

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
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(NAME)
	install -d $(DESTDIR)$(SYSCONFDIR)/$(NAME)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 $(SERVICE) $(DESTDIR)$(UNITDIR)/$(NAME).service
	install -d $(DESTDIR)$(SYSCTLDIR)
	install -m 0644 $(SYSCTL) $(DESTDIR)$(SYSCTLDIR)/60-$(NAME).conf

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(NAME)
	rm -f $(DESTDIR)$(UNITDIR)/$(NAME).service
	rm -f $(DESTDIR)$(SYSCTLDIR)/60-$(NAME).conf
