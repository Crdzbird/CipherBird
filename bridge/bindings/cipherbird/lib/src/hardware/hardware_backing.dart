/// Where a hardware key lives, as reported by the platform key module.
enum HardwareBacking {
  /// Apple Secure Enclave.
  secureEnclave,

  /// Android StrongBox, a discrete secure element.
  strongBox,

  /// Android trusted execution environment; the fallback when StrongBox is
  /// absent.
  trustedExecutionEnvironment,

  /// A software key, used only by the iOS simulator and Android emulators
  /// without a hardware-backed keystore.
  software,

  /// No key module on this platform.
  none;

  /// The backing named by a platform code.
  static HardwareBacking fromCode(String code) => switch (code) {
    'secure_enclave' => HardwareBacking.secureEnclave,
    'strongbox' => HardwareBacking.strongBox,
    'tee' => HardwareBacking.trustedExecutionEnvironment,
    'software' => HardwareBacking.software,
    _ => HardwareBacking.none,
  };

  /// Whether the key material is protected by dedicated hardware.
  bool get isHardware =>
      this == HardwareBacking.secureEnclave ||
      this == HardwareBacking.strongBox ||
      this == HardwareBacking.trustedExecutionEnvironment;
}
