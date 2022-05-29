.PHONY: macos libusb ios clean

CC ?= clang

macos:
	xcrun -sdk macosx clang -mmacosx-version-min=10.9 -Weverything gaster.c -o gaster -framework CoreFoundation -framework IOKit -Os

libusb:
	$(CC) -Wall -Wextra -Wpedantic -DHAVE_LIBUSB gaster.c -o gaster -lusb-1.0 -lcrypto -Os

ios:
	mkdir headers
	ln -s $(shell xcrun -sdk macosx -show-sdk-path)/usr/include/libkern headers
	ln -s $(shell xcrun -sdk macosx -show-sdk-path)/System/Library/Frameworks/IOKit.framework/Headers headers/IOKit
	xcrun -sdk iphoneos clang -arch armv7 -arch arm64 -isystemheaders -mios-version-min=9.0 -Weverything gaster.c -o gaster -framework CoreFoundation -framework IOKit -Os
	$(RM) -r headers

clean:
	$(RM) gaster
