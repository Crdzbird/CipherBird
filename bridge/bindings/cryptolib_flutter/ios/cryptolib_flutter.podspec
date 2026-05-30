#
# CryptoLib Flutter plugin — iOS podspec.
# Vendors the prebuilt CryptoLib.xcframework (static archive) so consuming apps
# get the native library with no manual setup. Run `pod lib lint` to validate.
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
  s.dependency 'Flutter'
  s.platform         = :ios, '13.0'
  s.swift_version    = '5.0'

  # Vendoring the xcframework keeps the pod target valid; but for a *static*
  # library xcframework CocoaPods adds a bare `-lcryptolib_c_merged` it never
  # resolves (it doesn't copy the slice into XCFrameworkIntermediates). We make
  # that `-l` resolve by pointing LIBRARY_SEARCH_PATHS at the real slice, and
  # -force_load the same archive so its objects survive (dart:ffi resolves
  # symbols at runtime, so nothing references them at link time). Slice paths
  # differ for device vs simulator, hence the sdk-conditional flags.
  s.vendored_frameworks = 'CryptoLib.xcframework'
  s.static_framework    = true

  s.pod_target_xcconfig = {
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386 x86_64'
  }

  xcfw = '${PODS_ROOT}/../.symlinks/plugins/cryptolib_flutter/ios/CryptoLib.xcframework'
  s.user_target_xcconfig = {
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]'        => 'i386 x86_64',
    'LIBRARY_SEARCH_PATHS[sdk=iphoneos*]'         => %(\$(inherited) "#{xcfw}/ios-arm64"),
    'LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*]'  => %(\$(inherited) "#{xcfw}/ios-arm64-simulator"),
    'OTHER_LDFLAGS[sdk=iphoneos*]'                => %(\$(inherited) -force_load "#{xcfw}/ios-arm64/libcryptolib_c_merged.a"),
    'OTHER_LDFLAGS[sdk=iphonesimulator*]'         => %(\$(inherited) -force_load "#{xcfw}/ios-arm64-simulator/libcryptolib_c_merged.a")
  }
end
