# ════════════════════════════════════════════════════════════════════════════
# CryptoLib — bindings & demos orchestrator
#
#   make                 # this help
#   make lib             # build the C shared library (build/release)
#   make cpp             # build + run the C++ examples (example/)
#   make go swift java kotlin dart node   # build + run each language demo
#   make flutter         # analyze the Flutter GUI app (Dart + FFI)
#   make react           # build the React frontend (Node/koffi backend)
#   make demos           # all host-runnable demos above
#   make showcases       # full per-language showcases (every capability family)
#   make <lang>-showcase # one language's full showcase (e.g. go-showcase)
#   make android         # cross-compile the native .so (arm64-v8a + x86_64)
#   make ios             # (re)assemble CryptoLib.xcframework
#   make test            # build + run the C++ test suite
#   make asan            # build + run tests under AddressSanitizer/UBSan
#   make all             # lib + demos
#   make clean           # remove build artifacts
#
# Each language target builds the library first and points the demo at it.
# Targets whose toolchain is missing are skipped with a clear message.
# ════════════════════════════════════════════════════════════════════════════

ROOT      := $(CURDIR)
LIBDIR    := $(ROOT)/build/release
DYLIB     := $(LIBDIR)/libcryptolib_c.dylib
CMAKE     ?= cmake
GENERATOR ?= Ninja

# Android NDK auto-detect (override with ANDROID_NDK_HOME=...)
ANDROID_NDK_HOME ?= $(lastword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*)))

# Pretty headers
define hdr
	@printf "\n\033[1;36m═══ %s ═══\033[0m\n" "$(1)"
endef

.DEFAULT_GOAL := help

.PHONY: help
help:
	@sed -n '2,22p' Makefile | sed 's/^# \{0,1\}//'

# ── C library ────────────────────────────────────────────────────────────────
.PHONY: lib
lib:
	$(call hdr,Building C library (Release))
	@$(CMAKE) -S . -B build/release -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release \
		-DCRYPTOLIB_BUILD_TESTS=OFF >/dev/null
	@$(CMAKE) --build build/release --target cryptolib_c
	@echo "→ $(DYLIB)"

# ── C++ examples ─────────────────────────────────────────────────────────────
.PHONY: cpp
cpp:
	$(call hdr,C++ examples)
	@$(CMAKE) -S . -B build/release -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release \
		-DCRYPTOLIB_BUILD_TESTS=OFF >/dev/null
	@$(CMAKE) --build build/release --target cryptolib_poc cryptolib_usage cryptolib_demo cryptolib_showcase
	@echo "--- cryptolib_poc ---";   ./build/release/cryptolib_poc   | tail -1
	@echo "--- cryptolib_usage ---"; ./build/release/cryptolib_usage | tail -1
	@echo "--- cryptolib_demo all ---"; ./build/release/cryptolib_demo all | tail -1

# Composition recipes — real-world flows that combine multiple primitives.
# `recipes` = the C++ reference (6, incl. Shamir); the per-binding targets mirror
# the other five (Shamir is C++-only, not in the C ABI).
.PHONY: recipes
recipes:
	$(call hdr,Recipes (composition in practice))
	@$(CMAKE) -S . -B build/release -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release \
		-DCRYPTOLIB_BUILD_TESTS=OFF >/dev/null
	@$(CMAKE) --build build/release --target cryptolib_recipes
	@DYLD_LIBRARY_PATH=$(LIBDIR) LD_LIBRARY_PATH=$(LIBDIR) ./build/release/cryptolib_recipes

.PHONY: go-recipes
go-recipes: lib
	$(call hdr,Go recipes)
	@if command -v go >/dev/null 2>&1; then \
		cd bridge/bindings/go && DYLD_LIBRARY_PATH=$(LIBDIR) LD_LIBRARY_PATH=$(LIBDIR) go run ./recipes | tail -2; \
	else echo "go not found — skipping"; fi

.PHONY: node-recipes
node-recipes: lib
	$(call hdr,Node recipes)
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB=$(DYLIB) node recipes.js | tail -2; \
	else echo "node not found — skipping"; fi

.PHONY: node-suite
node-suite: lib
	$(call hdr,Node Suite (advanced combinations))
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB=$(DYLIB) node suite.js | tail -2; \
	else echo "node not found — skipping"; fi

# Refresh every binding's BUNDLED native library from one self-contained build,
# so each package ships a current, self-contained libcryptolib_c (no C++ source
# tree needed to install). Run before publishing to any registry. Host platform
# only; CI / `make ios` / `make android` fill the cross-platform matrix.
.PHONY: bundle
bundle:
	$(call hdr,Bundling self-contained native library into every binding)
	@bash scripts/bundle_native.sh

# Flagship/Fortress sealed-messaging demos (Identity + one-shot + streaming).
.PHONY: sealed
sealed: node-sealed go-sealed dart-sealed swift-sealed

.PHONY: node-sealed
node-sealed: lib
	$(call hdr,Node Flagship/Fortress sealed messaging)
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB=$(DYLIB) node sealed.js | tail -2; \
	else echo "node not found — skipping"; fi

.PHONY: go-sealed
go-sealed: lib
	$(call hdr,Go Flagship/Fortress sealed messaging)
	@if command -v go >/dev/null 2>&1; then \
		cd bridge/bindings/go && DYLD_LIBRARY_PATH=$(LIBDIR) LD_LIBRARY_PATH=$(LIBDIR) go run ./sealed | tail -2; \
	else echo "go not found — skipping"; fi

.PHONY: dart-sealed
dart-sealed: lib
	$(call hdr,Dart Flagship/Fortress sealed messaging)
	@if command -v dart >/dev/null 2>&1; then \
		cd bridge/bindings/cipherbird_dart && dart pub get >/dev/null 2>&1 && \
		CRYPTOLIB_DYLIB=$(DYLIB) dart run bin/sealed.dart | tail -2; \
	else echo "dart not found — skipping"; fi

.PHONY: swift-recipes
swift-recipes: lib
	$(call hdr,Swift recipes)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/recipes.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_recipes && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_recipes | tail -2; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-suite
swift-suite: lib
	$(call hdr,Swift Suite (advanced combinations))
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/suite.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_suite && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_suite | tail -2; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-sealed
swift-sealed: lib
	$(call hdr,Swift Flagship/Fortress sealed messaging)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/sealed.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_sealed && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_sealed | tail -14; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-session
swift-session: lib
	$(call hdr,Swift Session ratchet)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/session.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_session && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_session | tail -8; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-frost
swift-frost: lib
	$(call hdr,Swift FROST threshold signatures)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/frost.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_frost && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_frost | tail -20; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-hpke
swift-hpke: lib
	$(call hdr,Swift HPKE (RFC 9180))
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/hpke.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_hpke && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_hpke | tail -12; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-bbs
swift-bbs: lib
	$(call hdr,Swift BBS signatures)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/bbs.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_bbs && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_bbs | tail -12; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-bbs-pseudonym
swift-bbs-pseudonym: lib
	$(call hdr,Swift BBS pseudonyms + blind issuance)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/bbs_pseudonym.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_bbs_pseudonym && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_bbs_pseudonym | tail -12; \
	else echo "swiftc not found — skipping"; fi

.PHONY: node-security
node-security: lib
	$(call hdr,Node security profiles + recipes)
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB=$(DYLIB) node test/security.js | tail -3 && \
		CRYPTOLIB_DYLIB=$(DYLIB) node test/extensibility.js | tail -1; \
	else echo "node not found — skipping"; fi

.PHONY: node-noise
node-noise: lib
	$(call hdr,Node incremental BLAKE3 + Noise XX)
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-node && CRYPTOLIB_DYLIB=$(DYLIB) node test/noise.js | tail -3; \
	else echo "node not found — skipping"; fi

.PHONY: dart-security
dart-security: lib
	$(call hdr,Dart security profiles + recipes + extension points)
	@if command -v dart >/dev/null 2>&1; then \
		cd bridge/bindings/cipherbird_dart && dart pub get >/dev/null 2>&1 && \
		dart run bin/security_verify.dart $(DYLIB) | tail -1 && \
		dart run bin/extensibility_verify.dart $(DYLIB) | tail -1 && \
		dart run bin/easy_verify.dart $(DYLIB) | tail -1; \
	else echo "dart not found — skipping"; fi

.PHONY: dart-noise
dart-noise: lib
	$(call hdr,Dart incremental BLAKE3 + Noise XX)
	@if command -v dart >/dev/null 2>&1; then \
		cd bridge/bindings/cipherbird_dart && dart pub get >/dev/null 2>&1 && \
		dart run bin/noise_verify.dart $(DYLIB) | tail -3; \
	else echo "dart not found — skipping"; fi

.PHONY: java-security
java-security: lib
	$(call hdr,Java security profiles + recipes)
	@if command -v javac >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-jvm && javac -d out src/cryptolib/*.java && \
		mkdir -p out/native && cp -R native/* out/native/ 2>/dev/null; \
		java --enable-native-access=ALL-UNNAMED -cp out cryptolib.RecipeVerify | tail -3; \
	else echo "javac not found — skipping"; fi

.PHONY: kotlin-security
kotlin-security: java-security
	$(call hdr,Kotlin security profiles + recipes)
	@if command -v kotlinc >/dev/null 2>&1; then \
		cd bridge/bindings/kotlin && kotlinc RecipeDemo.kt -cp ../cryptolib-jvm/out -include-runtime -d recipe.jar 2>/dev/null && \
		java --enable-native-access=ALL-UNNAMED -cp recipe.jar:../cryptolib-jvm/out RecipeDemoKt | tail -3; \
	else echo "kotlinc not found — skipping"; fi

.PHONY: python-security
python-security: lib
	$(call hdr,Python security profiles + recipes)
	@if command -v python3 >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-python && CRYPTOLIB_DYLIB=$(DYLIB) python3 tests/test_recipe.py | tail -3; \
	else echo "python3 not found — skipping"; fi

.PHONY: ruby-security
ruby-security: lib
	$(call hdr,Ruby security profiles + recipes)
	@if command -v ruby >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-ruby && CRYPTOLIB_DYLIB=$(DYLIB) ruby -Ilib test/recipe.rb | tail -3; \
	else echo "ruby not found — skipping"; fi

.PHONY: rust-security
rust-security: lib
	$(call hdr,Rust security profiles + recipes)
	@if command -v cargo >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-rust && DYLD_LIBRARY_PATH=$(LIBDIR) cargo run --quiet --example recipe | tail -3; \
	else echo "cargo not found — skipping"; fi

.PHONY: dotnet-security
dotnet-security: lib
	$(call hdr,.NET security profiles + recipes)
	@if command -v dotnet >/dev/null 2>&1; then \
		cd bridge/bindings/cryptolib-dotnet && dotnet run -v q | tail -3; \
	else echo "dotnet not found — skipping"; fi

# Every binding seals a fixed set of recipe configurations; every OTHER binding
# must open them. This is what makes the envelope one library format rather than
# nine look-alike implementations.
.PHONY: recipe-interop
recipe-interop: lib swift-security java-security
	$(call hdr,CryptoRecipe cross-language interop)
	@cd bridge/bindings/cryptolib-dotnet && dotnet build -v q --nologo >/dev/null 2>&1 || true
	@bash scripts/verify_recipe_interop.sh

.PHONY: swift-security
swift-security: lib
	$(call hdr,Swift security profiles + recipes)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/security.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_security && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_security | tail -20; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-opaque
swift-opaque: lib
	$(call hdr,Swift OPAQUE aPAKE)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/opaque.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_opaque && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_opaque | tail -10; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-oprf
swift-oprf: lib
	$(call hdr,Swift OPRF (RFC 9497))
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/oprf.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_oprf && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_oprf | tail -12; \
	else echo "swiftc not found — skipping"; fi

.PHONY: swift-ecvrf
swift-ecvrf: lib
	$(call hdr,Swift ECVRF (RFC 9381))
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/ecvrf.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_ecvrf && \
		DYLD_LIBRARY_PATH=$(LIBDIR) ./build/swift_ecvrf | tail -12; \
	else echo "swiftc not found — skipping"; fi

# Prove the Flutter package works for a pub.dev consumer: serves the exact
# publish archive from a local pub server, installs it as a HOSTED dependency
# in a fresh app, runs the package's test suite on DEVICE (flutter devices).
.PHONY: flutter-consumer
flutter-consumer:
	$(call hdr,Flutter pub.dev consumer test on $(or $(DEVICE),macos))
	@bash scripts/verify_pub_consumer.sh $(or $(DEVICE),macos)

.PHONY: flutter-recipes
flutter-recipes: lib
	$(call hdr,Flutter recipes (host test))
	@if command -v flutter >/dev/null 2>&1; then \
		cd bridge/bindings/cipherbird && \
		CRYPTOLIB_DYLIB=$(DYLIB) flutter test test/recipes_test.dart test/extensibility_test.dart test/easy_test.dart | tail -2; \
	else echo "flutter not found — skipping"; fi

# ── Go (cgo) ─────────────────────────────────────────────────────────────────
.PHONY: go
go: lib
	$(call hdr,Go demo)
	@if command -v go >/dev/null 2>&1; then \
		cd bridge/bindings/go && DYLD_LIBRARY_PATH=$(LIBDIR) go run ./example | tail -3; \
	else echo "go not found — skipping"; fi

# Self-contained static archive (every dependency baked in).
.PHONY: static-archive
static-archive:
	$(call hdr,Static archive (self-contained))
	@bash scripts/build_static_archive.sh

# Go demo built fully static — runs with NO library path (no dylib needed).
.PHONY: go-static
go-static: static-archive
	$(call hdr,Go demo (fully static, no runtime library))
	@if command -v go >/dev/null 2>&1; then \
		cd bridge/bindings/go && go run -tags cryptolib_static ./example | tail -3; \
	else echo "go not found — skipping"; fi

# ── Swift (console) ──────────────────────────────────────────────────────────
.PHONY: swift
swift: lib
	$(call hdr,Swift demo)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/main.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_demo && \
		./build/swift_demo; \
	else echo "swiftc not found — skipping"; fi

# ── Java (Foreign Function & Memory API, JDK 22+) ───────────────────────────
.PHONY: java
java: lib
	$(call hdr,Java demo)
	@if command -v javac >/dev/null 2>&1; then \
		cd bridge/bindings/java && javac CryptoLibDemo.java && \
		java --enable-native-access=ALL-UNNAMED CryptoLibDemo $(DYLIB); \
	else echo "javac not found — skipping"; fi

# ── Swift device-factor provider (Keychain → keyring device slot) ───────────
.PHONY: swift-keyring
swift-keyring: lib
	$(call hdr,Swift device-factor (Keychain) demo)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/keyring_device.swift \
			-framework Security -L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/kd && \
		./build/kd; \
	else echo "swiftc not found — skipping"; fi

# ── Kotlin/JVM (Foreign Function & Memory API) ──────────────────────────────
.PHONY: kotlin
kotlin: lib
	$(call hdr,Kotlin demo)
	@if command -v kotlinc >/dev/null 2>&1; then \
		cd bridge/bindings/kotlin && kotlinc CryptoLibDemo.kt -include-runtime -d demo.jar && \
		java --enable-native-access=ALL-UNNAMED -jar demo.jar $(DYLIB); \
	else echo "kotlinc not found — skipping (install Kotlin 2.x)"; fi

# ── Dart (dart:ffi console) ──────────────────────────────────────────────────
.PHONY: dart
dart: lib
	$(call hdr,Dart demo)
	@if command -v dart >/dev/null 2>&1; then \
		cd bridge/bindings/cipherbird_dart && (dart pub get --offline >/dev/null 2>&1 || dart pub get >/dev/null) && \
		dart run bin/demo.dart $(DYLIB); \
	else echo "dart not found — skipping"; fi

# ── Node.js (koffi) — also the React Native native-call path ────────────────
.PHONY: node
node: lib
	$(call hdr,Node demo)
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/node && { [ -d node_modules/koffi ] || npm install >/dev/null 2>&1; } && \
		node demo.js $(DYLIB); \
	else echo "node not found — skipping"; fi

# ── Flutter (analyze the GUI app + its dart:ffi binding) ────────────────────
# `flutter analyze` is the reliable compile check for the Dart + FFI code.
# A full desktop build needs platform scaffolding first: cd bridge/bindings/flutter &&
# ./setup_macos.sh && flutter build macos   (or `flutter build apk/ios`).
.PHONY: flutter
flutter: lib
	$(call hdr,Flutter (analyze + runtime FFI test))
	@if command -v flutter >/dev/null 2>&1; then \
		cd bridge/bindings/flutter && flutter pub get >/dev/null && \
		flutter analyze --no-fatal-infos --no-fatal-warnings && \
		flutter test test/ffi_test.dart; \
	else echo "flutter not found — skipping"; fi

# ── WebAuthn E2E (Playwright virtual authenticator drives the passkey flow) ──
.PHONY: react-webauthn-test
react-webauthn-test: lib
	$(call hdr,WebAuthn E2E (Playwright virtual authenticator))
	@if command -v npm >/dev/null 2>&1; then \
		cd bridge/bindings/react && { [ -d node_modules ] || npm install >/dev/null 2>&1; } && \
		npx playwright install chromium >/dev/null 2>&1 && npm run build >/dev/null && \
		CRYPTOLIB_DYLIB=$(DYLIB) node test/webauthn_e2e.mjs; \
	else echo "npm not found — skipping"; fi

# ── React (Vite frontend + Node/koffi backend) ──────────────────────────────
# Browsers can't load a .dylib, so the React UI calls a Node+koffi server that
# uses the native library. `make react` builds the frontend (compile check).
# To run live:  make lib && (cd bridge/bindings/react && npm run server &) && npm run dev
.PHONY: react
react: lib
	$(call hdr,React (build frontend))
	@if command -v npm >/dev/null 2>&1; then \
		cd bridge/bindings/react && { [ -d node_modules ] || npm install >/dev/null 2>&1; } && npm run build; \
	else echo "npm not found — skipping"; fi

# ── Comprehensive showcases (every capability family, per language) ──────────
# Distinct from the demos: each `*-showcase` exercises hashing, symmetric,
# asymmetric, vaults, post-quantum, BLS, and the keyring in one run.

.PHONY: cpp-showcase
cpp-showcase: lib
	$(call hdr,C++ full showcase)
	@$(CMAKE) --build build/release --target cryptolib_showcase >/dev/null && \
		./build/release/cryptolib_showcase | tail -4

.PHONY: go-showcase
go-showcase: lib
	$(call hdr,Go full showcase)
	@if command -v go >/dev/null 2>&1; then \
		cd bridge/bindings/go && DYLD_LIBRARY_PATH=$(LIBDIR) go run ./showcase | tail -3; \
	else echo "go not found — skipping"; fi

.PHONY: swift-showcase
swift-showcase: lib
	$(call hdr,Swift full showcase)
	@if command -v swiftc >/dev/null 2>&1; then \
		swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/showcase.swift \
			-L $(LIBDIR) -lcryptolib_c -Xlinker -rpath -Xlinker $(LIBDIR) -o build/swift_showcase && \
		./build/swift_showcase $(DYLIB) | tail -3; \
	else echo "swiftc not found — skipping"; fi

.PHONY: java-showcase
java-showcase: lib
	$(call hdr,Java full showcase)
	@if command -v javac >/dev/null 2>&1; then \
		cd bridge/bindings/java && javac Showcase.java && \
		java --enable-native-access=ALL-UNNAMED Showcase $(DYLIB) | tail -3; \
	else echo "javac not found — skipping"; fi

.PHONY: kotlin-showcase
kotlin-showcase: lib
	$(call hdr,Kotlin full showcase)
	@if command -v kotlinc >/dev/null 2>&1; then \
		cd bridge/bindings/kotlin && kotlinc Showcase.kt -include-runtime -d showcase.jar && \
		java --enable-native-access=ALL-UNNAMED -jar showcase.jar $(DYLIB) | tail -3; \
	else echo "kotlinc not found — skipping (install Kotlin 2.x)"; fi

.PHONY: dart-showcase
dart-showcase: lib
	$(call hdr,Dart full showcase)
	@if command -v dart >/dev/null 2>&1; then \
		cd bridge/bindings/cipherbird_dart && (dart pub get --offline >/dev/null 2>&1 || dart pub get >/dev/null) && \
		dart run bin/showcase.dart $(DYLIB) | tail -3; \
	else echo "dart not found — skipping"; fi

.PHONY: node-showcase
node-showcase: lib
	$(call hdr,Node full showcase)
	@if command -v node >/dev/null 2>&1; then \
		cd bridge/bindings/node && { [ -d node_modules/koffi ] || npm install >/dev/null 2>&1; } && \
		node showcase.js $(DYLIB) | tail -3; \
	else echo "node not found — skipping"; fi

# React surfaces the Node showcase over HTTP (server.mjs /api/showcase); the
# flutter showcase is the runtime FFI test already run by `make flutter`.
.PHONY: showcases
showcases: cpp-showcase go-showcase swift-showcase java-showcase kotlin-showcase dart-showcase node-showcase flutter
	$(call hdr,All comprehensive showcases completed)

# ── All host demos ───────────────────────────────────────────────────────────
.PHONY: demos
demos: cpp go swift java kotlin dart node flutter react
	$(call hdr,All host demos completed)

.PHONY: all
all: lib demos

# ── Android native .so (arm64-v8a + x86_64) ──────────────────────────────────
.PHONY: android
android:
	$(call hdr,Android native libraries)
	@if [ -n "$(ANDROID_NDK_HOME)" ] && [ -d "$(ANDROID_NDK_HOME)" ]; then \
		for abi in arm64-v8a x86_64; do \
			echo "→ $$abi"; \
			$(CMAKE) -S . -B build/android-$$abi -G $(GENERATOR) \
				-DCMAKE_TOOLCHAIN_FILE=$(ANDROID_NDK_HOME)/build/cmake/android.toolchain.cmake \
				-DANDROID_ABI=$$abi -DANDROID_PLATFORM=android-24 \
				-DCRYPTOLIB_DEPS_ROOT=$(ROOT)/third_party/android/$$abi >/dev/null && \
			$(CMAKE) --build build/android-$$abi --target cryptolib_c >/dev/null && \
			ls -la build/android-$$abi/libcryptolib_c.so; \
		done; \
	else echo "Android NDK not found (set ANDROID_NDK_HOME) — skipping"; fi

# ── iOS XCFramework (reuses prebuilt third_party/ios deps) ───────────────────
.PHONY: ios
ios:
	$(call hdr,iOS XCFramework)
	@if command -v xcodebuild >/dev/null 2>&1; then \
		for s in iphoneos iphonesimulator macosx; do bash scripts/ios/build_cryptolib_slice.sh $$s; done && \
		bash scripts/ios/assemble_xcframework.sh iphoneos iphonesimulator macosx; \
	else echo "Xcode not found — skipping"; fi

# ── Tests ────────────────────────────────────────────────────────────────────
# "No ambient authority" gate — fails if the built library imports any
# networking or process-execution symbol (see scripts/audit_symbols.sh).
.PHONY: audit
audit: lib
	$(call hdr,Self-containment audit (no ambient authority))
	@bash scripts/audit_symbols.sh $(DYLIB)

.PHONY: test
test:
	$(call hdr,C++ test suite)
	@$(CMAKE) -S . -B build/test -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release \
		-DCRYPTOLIB_BUILD_TESTS=ON -DCRYPTOLIB_BUILD_BRIDGE=OFF >/dev/null
	@$(CMAKE) --build build/test --target cryptolib_tests
	@./build/test/cryptolib_tests | tail -3

# Same test suite, but with the standardized PQC algorithms backed by OpenSSL EVP
# (FIPS-track) instead of liboqs. The ACVP known-answer tests are the equivalence
# gate — they must pass identically under both backends.
.PHONY: test-openssl-pq
test-openssl-pq:
	$(call hdr,C++ test suite — OpenSSL PQC backend)
	@$(CMAKE) -S . -B build/ossl-pq -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release \
		-DCRYPTOLIB_BUILD_TESTS=ON -DCRYPTOLIB_BUILD_BRIDGE=OFF \
		-DCRYPTOLIB_PQ_BACKEND_OPENSSL=ON >/dev/null
	@$(CMAKE) --build build/ossl-pq --target cryptolib_tests
	@./build/ossl-pq/cryptolib_tests | tail -3

.PHONY: asan
asan:
	$(call hdr,Tests under AddressSanitizer + UBSan)
	@$(CMAKE) -S . -B build/asan -G $(GENERATOR) -DCRYPTOLIB_SANITIZE=ON \
		-DCRYPTOLIB_BUILD_BRIDGE=OFF -DCRYPTOLIB_BUILD_EXAMPLE=OFF >/dev/null
	@$(CMAKE) --build build/asan --target cryptolib_tests
	@ASAN_OPTIONS=detect_leaks=0 ./build/asan/cryptolib_tests | tail -3

# ── Cleanup ──────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	$(call hdr,Cleaning)
	@rm -rf build/release build/asan build/android-arm64 build/android-x86_64 \
		build/swift_demo bridge/bindings/java/*.class
	@echo "done"
