SHELL   := /usr/bin/env bash
VERSION := 0.3.0

TARGETS := armv7-apple-ios \
           armv7s-apple-ios \
           i386-apple-ios \
           aarch64-apple-ios \
           x86_64-apple-ios

# pkg-config is invoked by libsodium-sys
# cf. https://github.com/alexcrichton/pkg-config-rs/blob/master/src/lib.rs#L12
export PKG_CONFIG_ALLOW_CROSS=1

all: dist

distclean:
	rm -rf build
	rm -rf dist

dist/cryptobox-ios-$(VERSION).tar.gz: dist-libs
	tar -C dist \
		-czf dist/cryptobox-ios-$(VERSION).tar.gz \
		lib include

dist-tar: dist/cryptobox-ios-$(VERSION).tar.gz

dist: dist-tar

#############################################################################
# cryptobox

build/include/cbox.h: $(CRYPTOBOX_SRC)
	mkdir -p build/include
	cp $(CRYPTOBOX_SRC)/cbox.h build/include/

cryptobox: build/include/cbox.h

# Build against an existing release.
cryptobox-%:
	mkdir -p build
	cd build
	if [ ! -f build/cryptobox-ios-$*.tar.gz ]; then \
	curl -L -o build/cryptobox-ios-$*.tar.gz https://github.com/wireapp/cryptobox-ios/releases/download/v$*/cryptobox-ios-$*.tar.gz; \
	fi
	cd build && tar -xzf cryptobox-ios-$*.tar.gz

#############################################################################
