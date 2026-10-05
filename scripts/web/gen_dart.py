#!/usr/bin/env python3
"""Generate the web platform layer's struct views and symbol registry.

Inputs: build/web/gen/signatures.json and layouts.json (from gen_wrappers.py
and the Emscripten build) plus the native struct declarations, which supply
the Dart field names. Output goes under lib/src/platform/web/ of the plugin.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

RESERVED = {'in', 'is', 'as', 'if', 'do', 'for', 'new', 'var', 'this', 'with', 'class'}
HANDWRITTEN = [
    'allocator', 'array', 'cipher_bird_isolate_runner', 'double_type', 'dynamic_library',
    'engine_loader', 'engine_module', 'engine_worker', 'heap_memory', 'int32', 'local_memory', 'memory',
    'native_type', 'pointer', 'pointer_extensions', 'size', 'size_of', 'struct', 'uint16',
    'uint64', 'uint8', 'utf8', 'utf8_extensions', 'void_type', 'web_engine',
]


def camel(name):
    parts = name.split('_')
    out = parts[0] + ''.join(p[:1].upper() + p[1:] for p in parts[1:])
    return out + '_' if out in RESERVED else out


def snake(name):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


def dart_struct(c_name):
    return 'CipherBird' + c_name[len('Crypto'):]


def parse_native_fields(path):
    fields = []
    for match in re.finditer(r'external\s+([\w<>]+)\s+(\w+);', path.read_text()):
        fields.append({'type': match.group(1), 'name': match.group(2)})
    return fields


def field_accessors(field, dart, offset):
    kind = field['kind']
    name = dart['name']
    at = '_base + %d' % offset
    if field.get('count'):
        return ['  Array<Uint8> get %s => Array<Uint8>._(_memory, %s, %d);' % (name, at, field['count'])]
    if kind == 'struct':
        inner = dart_struct(field['ctype'])
        return ['  %s get %s => %s._(_memory, %s);' % (inner, name, inner, at)]
    if kind == 'ptr':
        return ['  %s get %s => %s._(_memory.getU32(%s));' % (dart['type'], name, dart['type'], at),
                '  set %s(%s value) => _memory.setU32(%s, value.address);' % (name, dart['type'], at)]
    if kind == 'f64':
        return ['  double get %s => _memory.getF64(%s);' % (name, at)]
    getter = {'uint8_t': 'getU8', 'uint16_t': 'getU32', 'int': 'getI32', 'int32_t': 'getI32',
              'uint32_t': 'getU32', 'size_t': 'getU32', 'u64': 'getU64'}[kind]
    setter = getter.replace('get', 'set')
    return ['  int get %s => _memory.%s(%s);' % (name, getter, at),
            '  set %s(int value) => _memory.%s(%s, value);' % (name, setter, at)]


def write_struct(struct, layout, native_dir, out_dir):
    dart = dart_struct(struct['name'])
    native = parse_native_fields(native_dir / ('%s.dart' % snake(dart)))
    if len(native) != len(struct['fields']):
        sys.exit('field count mismatch for %s' % dart)
    lines = ["part of '../web_platform.dart';", '',
             '/// Web view of the C `%s` struct.' % struct['name'],
             'final class %s extends Struct {' % dart,
             '  const %s._(super.memory, super.base);' % dart, '',
             '  static %s _new(Memory memory, int base) => %s._(memory, base);' % (dart, dart), '',
             '  /// Byte size under wasm32.',
             '  static const int size = %d;' % layout['size'], '']
    for field, nat in zip(struct['fields'], native):
        lines += field_accessors(field, nat, layout['fields'][field['name']]['offset'])
    lines.append('}')
    (out_dir / ('%s.dart' % snake(dart))).write_text('\n'.join(lines) + '\n')
    return dart


def write_struct_registry(names, out_dir):
    lines = ["part of '../web_platform.dart';", '',
             '/// wasm32 byte sizes of the struct views, for `sizeOf` and `calloc`.',
             'final Map<Type, int> structSizes = {']
    lines += ['  %s: %s.size,' % (n, n) for n in names]
    lines += ['};', '', 'final Map<Type, Struct Function(Memory memory, int base)> _factories = {']
    lines += ['  %s: %s._new,' % (n, n) for n in names]
    lines += ['};', '', '/// A view of struct [T] at [base] in [memory].',
              'T structView<T extends Struct>(Memory memory, int base) {',
              '  final make = _factories[T];', '  if (make == null) {',
              "    throw ArgumentError('cipherbird: unknown struct type $T');", '  }',
              '  return make(memory, base) as T;', '}']
    (out_dir / 'struct_registry.dart').write_text('\n'.join(lines) + '\n')


def entry(fn):
    params = []
    args = []
    for p in fn['params']:
        name = camel(p['name'])
        if p['kind'] == 'ptr':
            params.append('Pointer<NativeType> %s' % name)
            args.append('%s.address.toJS' % name)
        elif p['kind'] == 'u64':
            params.append('int %s' % name)
            args.append('(%s %% 4294967296).toJS, (%s ~/ 4294967296).toJS' % (name, name))
        else:
            params.append('int %s' % name)
            args.append('%s.toJS' % name)
    export = "'_cbw_%s'" % fn['name']
    arglist = '[%s]' % ', '.join(args)
    kind = fn['ret_kind']
    if kind == 'struct':
        dart = dart_struct(fn['ret'])
        body = 'WebEngine.current.callStruct(%s, %s, %s.size, %s._new)' % (export, arglist, dart, dart)
    elif kind == 'void':
        body = 'WebEngine.current.callVoid(%s, %s)' % (export, arglist)
    elif kind == 'u64':
        body = 'WebEngine.current.callU64(%s, %s)' % (export, arglist)
    elif kind == 'ptr':
        target = 'Pointer<Utf8>' if fn['ret'] == 'const char*' else 'Pointer<Void>'
        body = '%s._(WebEngine.current.callInt(%s, %s))' % (target, export, arglist)
    else:
        body = 'WebEngine.current.callInt(%s, %s)' % (export, arglist)
    return "  '%s': (%s) => %s," % (fn['name'], ', '.join(params), body)


def write_registry(functions, out_dir, tmp):
    tmp.write_text("part of '../web_platform.dart';\n\nfinal Map<String, Function> _all = {\n"
                   + '\n'.join(entry(fn) for fn in functions) + '\n};\n')
    subprocess.run(['dart', 'format', str(tmp)], check=True, capture_output=True)
    lines = tmp.read_text().splitlines()
    start = lines.index('final Map<String, Function> _all = {') + 1
    end = len(lines) - 1
    entries = []
    for line in lines[start:end]:
        if line.startswith("  '"):
            entries.append([line])
        else:
            entries[-1].append(line)
    chunks = []
    current = []
    for e in entries:
        if current and sum(len(x) for x in current) + len(e) > 90:
            chunks.append(current)
            current = []
        current.append(e)
    chunks.append(current)
    names = []
    for i, chunk in enumerate(chunks, 1):
        name = '_registry%02d' % i
        names.append(name)
        body = '\n'.join('\n'.join(e) for e in chunk)
        (out_dir / ('registry_%02d.dart' % i)).write_text(
            "part of '../web_platform.dart';\n\nfinal Map<String, Function> %s = {\n%s\n};\n" % (name, body))
    merged = ["part of '../web_platform.dart';", '',
              '/// Every C ABI symbol, as the Dart closure `lookupFunction` returns.',
              'final Map<String, Function> symbolRegistry = {'] + ['  ...%s,' % n for n in names] + ['};']
    (out_dir / 'symbol_registry.dart').write_text('\n'.join(merged) + '\n')
    return len(chunks)


def write_root(web_dir, struct_names, chunk_count):
    parts = ["part '%s.dart';" % n for n in sorted(HANDWRITTEN)]
    parts += ["part 'registry/registry_%02d.dart';" % i for i in range(1, chunk_count + 1)]
    parts += ["part 'registry/symbol_registry.dart';"]
    parts += ["part 'structs/%s.dart';" % snake(n) for n in sorted(struct_names)]
    parts += ["part 'structs/struct_registry.dart';"]
    text = '''/// The web platform layer: a dart:ffi-shaped surface over the WebAssembly
/// build of the engine. The root library imports this instead of
/// `native_platform.dart` when compiled for the browser. The struct views and
/// the symbol registry are generated by scripts/web/gen_dart.py.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:cipherbird/src/runner/cipher_bird_job.dart';
import 'package:cipherbird/src/runner/cipher_bird_runner.dart';
import 'package:meta/meta.dart';

%s
''' % '\n'.join(parts)
    (web_dir / 'web_platform.dart').write_text(text)


def main():
    gen = Path(sys.argv[1])
    plugin = Path(sys.argv[2])
    sig = json.load((gen / 'signatures.json').open())
    layouts = json.load((gen / 'layouts.json').open())
    web_dir = plugin / 'lib/src/platform/web'
    native_dir = plugin / 'lib/src/platform/native/structs'
    for d in (web_dir / 'structs', web_dir / 'registry'):
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob('*.dart'):
            old.unlink()
    names = [write_struct(s, layouts[s['name']], native_dir, web_dir / 'structs') for s in sig['structs']]
    write_struct_registry(names, web_dir / 'structs')
    chunks = write_registry(sig['functions'], web_dir / 'registry', gen / 'registry_all.dart')
    write_root(web_dir, names, chunks)
    subprocess.run(['dart', 'format', str(web_dir)], check=True, capture_output=True)
    print('structs %d registry chunks %d' % (len(names), chunks))


if __name__ == '__main__':
    main()
