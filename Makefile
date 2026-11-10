# pocketkey build/install helpers.
#
#   make build            release build (needs libdbus-1-dev; or FEATURES=vendored-dbus)
#   sudo make install     binaries + privileged uhid helper units (system-wide); run `make build` first
#   make install-user     systemd user unit for the current user, enabled + started
#   make uninstall-user / sudo make uninstall

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
UDEV_RULES_DIR ?= /etc/udev/rules.d
MODULES_LOAD_DIR ?= /etc/modules-load.d
SYSTEM_UNIT_DIR ?= /etc/systemd/system
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
	@test -x target/release/pocketkey -a -x target/release/pocketkey-uhid-helper || { echo "release binaries not found; run 'make build' first"; exit 1; }
	install -Dm755 target/release/pocketkey $(DESTDIR)$(BINDIR)/pocketkey
	install -Dm755 target/release/pocketkey-uhid-helper $(DESTDIR)$(BINDIR)/pocketkey-uhid-helper
	# Older installs granted the whole desktop session /dev/uhid; remove that.
	rm -f $(DESTDIR)$(UDEV_RULES_DIR)/60-pocketkey.rules $(DESTDIR)$(UDEV_RULES_DIR)/99-pocketkey.rules
	install -Dm644 packaging/pocketkey-modules.conf $(DESTDIR)$(MODULES_LOAD_DIR)/pocketkey.conf
	sed 's|^ExecStart=.*|ExecStart=$(BINDIR)/pocketkey-uhid-helper|' packaging/pocketkey-uhid.service > $(DESTDIR)$(SYSTEM_UNIT_DIR)/pocketkey-uhid.service
	install -Dm644 packaging/pocketkey-uhid.socket $(DESTDIR)$(SYSTEM_UNIT_DIR)/pocketkey-uhid.socket
	@if [ -z "$(DESTDIR)" ]; then \
		udevadm control --reload; \
		modprobe uhid; \
		systemctl daemon-reload; \
		systemctl enable --now pocketkey-uhid.socket; \
	fi

install-user:
	install -d $(USER_UNIT_DIR)
	sed 's|^ExecStart=.*|ExecStart=$(BINDIR)/pocketkey|' packaging/pocketkey.service > $(USER_UNIT_DIR)/pocketkey.service
	systemctl --user daemon-reload
	systemctl --user enable --now pocketkey.service
	systemctl --user --no-pager status pocketkey.service || true

uninstall:
	-systemctl disable --now pocketkey-uhid.socket pocketkey-uhid.service
	rm -f $(DESTDIR)$(BINDIR)/pocketkey $(DESTDIR)$(BINDIR)/pocketkey-uhid-helper
	rm -f $(DESTDIR)$(SYSTEM_UNIT_DIR)/pocketkey-uhid.socket $(DESTDIR)$(SYSTEM_UNIT_DIR)/pocketkey-uhid.service
	rm -f $(DESTDIR)$(UDEV_RULES_DIR)/60-pocketkey.rules $(DESTDIR)$(MODULES_LOAD_DIR)/pocketkey.conf
	-systemctl daemon-reload
	-udevadm control --reload

uninstall-user:
	-systemctl --user disable --now pocketkey.service
	rm -f $(USER_UNIT_DIR)/pocketkey.service
	systemctl --user daemon-reload

deb:
	dpkg-buildpackage -us -uc -b -d
