#
# CryptoLib Flutter plugin — macOS podspec.
# Vendors the prebuilt CryptoLib.xcframework (static archive); the macos-arm64
# slice is used. Run `pod lib lint` to validate.
#
Pod::Spec.new do |s|
  s.name             = 'cryptolib_flutter'
  s.version          = '3.0.0'
  s.summary          = 'CryptoLib native cryptography for Flutter (dart:ffi).'
  s.description      = 'Bundled CryptoLib static library exposed via dart:ffi — hashing, AEAD, asymmetric, vaults, post-quantum, hybrid KEM, BLS, keyring.'
  s.homepage         = 'https://example.com/cryptolib'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'CryptoLib' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.dependency 'FlutterMacOS'
  s.platform         = :osx, '10.14'
  s.swift_version    = '5.0'

  s.vendored_frameworks = 'CryptoLib.xcframework'
  s.static_framework    = true

  # CocoaPods extracts the active slice's static archive into
  # PODS_XCFRAMEWORKS_BUILD_DIR but doesn't auto-link a static-library
  # xcframework. -force_load links it AND keeps every object for dart:ffi.
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) -force_load "${PODS_XCFRAMEWORKS_BUILD_DIR}/cryptolib_flutter/libcryptolib_c_merged.a"'
  }
end
