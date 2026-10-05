/// The native platform layer: dart:ffi, the bundled library loader and the
/// isolate runner. The root library imports this on every platform except the
/// web, where `web_platform.dart` provides the same surface over WebAssembly.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:cipherbird_dart/src/runner/cipher_bird_job.dart';
import 'package:cipherbird_dart/src/runner/cipher_bird_runner.dart';
import 'package:ffi/ffi.dart';

export 'dart:ffi';
export 'package:ffi/ffi.dart';

part 'bundled_library.dart';
part 'cipher_bird_isolate_runner.dart';
part 'engine_loader.dart';
part 'structs/cipher_bird_asym_bundle.dart';
part 'structs/cipher_bird_buffer.dart';
part 'structs/cipher_bird_buffer_result.dart';
part 'structs/cipher_bird_derived_keys.dart';
part 'structs/cipher_bird_entropy_info.dart';
part 'structs/cipher_bird_file_inspection.dart';
part 'structs/cipher_bird_frost_commit.dart';
part 'structs/cipher_bird_frost_key_gen.dart';
part 'structs/cipher_bird_health_report.dart';
part 'structs/cipher_bird_hidden_data_report.dart';
part 'structs/cipher_bird_kem_encaps_result.dart';
part 'structs/cipher_bird_key_pair.dart';
part 'structs/cipher_bird_opaque_ke1.dart';
part 'structs/cipher_bird_opaque_ke2.dart';
part 'structs/cipher_bird_opaque_ke3.dart';
part 'structs/cipher_bird_opaque_record.dart';
part 'structs/cipher_bird_oprf_blind.dart';
part 'structs/cipher_bird_packet.dart';
part 'structs/cipher_bird_result.dart';
part 'structs/cipher_bird_sealed_info.dart';
