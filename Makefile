# pocketkey build/install helpers.
#
#   make build            release build (needs libdbus-1-dev; or FEATURES=vendored-dbus)
#   sudo make install     binary + udev rule (system-wide); run `make build` first
#   make install-user     systemd user unit for the current user, enabled + started
#   make uninstall-user / sudo make uninstall

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
UDEV_RULES_DIR ?= /etc/udev/rules.d
USER_UNIT_DIR ?= $(HOME)/.config/systemd/user
FEATURES ?=
CARGO ?= cargo
CARGO_FEATURES := $(if $(FEATURES),--features $(FEATURES),)

.PHONY: build test clippy fmt install install-user uninstall uninstall-user deb

build:
	$(CARGO) build --release $(CARGO_FEATURES)

test:
	$(CARGO) test $(CARGO_FEATURES)

clippy:
	$(CARGO) clippy --all-targets $(CARGO_FEATURES) -- -D warnings

fmt:
	$(CARGO) fmt --check

# Installs the already-built binary; run `make build` first (as your user,
# not root, so cargo from rustup is on PATH).
install:
	@test -x target/release/pocketkey || { echo "target/release/pocketkey not found; run 'make build' first"; exit 1; }
	install -Dm755 target/release/pocketkey $(DESTDIR)$(BINDIR)/pocketkey
	install -Dm644 packaging/99-pocketkey.rules $(DESTDIR)$(UDEV_RULES_DIR)/99-pocketkey.rules
	@if [ -z "$(DESTDIR)" ]; then \
		udevadm control --reload && udevadm trigger --name-match=uhid; \
		echo "udev rule installed; /dev/uhid ACL: $$(getfacl -p /dev/uhid 2>/dev/null | grep '^user:' | tr '\n' ' ')"; \
	fi

install-user:
	install -d $(USER_UNIT_DIR)
	sed 's|^ExecStart=.*|ExecStart=$(BINDIR)/pocketkey|' packaging/pocketkey.service > $(USER_UNIT_DIR)/pocketkey.service
	systemctl --user daemon-reload
	systemctl --user enable --now pocketkey.service
	systemctl --user --no-pager status pocketkey.service || true

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/pocketkey $(DESTDIR)$(UDEV_RULES_DIR)/99-pocketkey.rules
	-udevadm control --reload

uninstall-user:
	-systemctl --user disable --now pocketkey.service
	rm -f $(USER_UNIT_DIR)/pocketkey.service
	systemctl --user daemon-reload

deb:
	dpkg-buildpackage -us -uc -b
