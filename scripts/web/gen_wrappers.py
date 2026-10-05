#!/usr/bin/env python3
"""Generate the flat WebAssembly boundary over bridge/cryptolib_c.h.

Every C ABI function gets a cbw_ twin that JavaScript can call without
knowing the wasm32 struct-return convention: struct results are written to
a caller-supplied pointer, 64-bit integers travel as two 32-bit halves.
Also emits exports.json (the Emscripten export list), signatures.json (the
boundary description the Dart generator consumes) and layouts.c (a program
that prints the wasm32 struct layouts as JSON).
"""
import json
import re
import sys
from pathlib import Path

HANDLE_TYPES = {
    'CryptoVaultHandle', 'CryptoEntropyHandle', 'CryptoStreamEncHandle',
    'CryptoStreamDecHandle', 'CryptoKeyringHandle', 'CryptoDrbgHandle',
    'CryptoFortunaHandle', 'CryptoBlake3Handle', 'CryptoNoiseHandle',
    'CryptoSealedSealer', 'CryptoSealedOpener', 'CryptoSession', 'CryptoHpkeContext',
}


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def parse_structs(text):
    structs = []
    for body, name in re.findall(r'typedef struct\s*\{([^}]*)\}\s*(\w+);', text, re.S):
        fields = []
        for decl in body.split(';'):
            decl = ' '.join(decl.split())
            if not decl:
                continue
            match = re.match(r'(.+?)\s*(\w+)(\[(\d+)\])?$', decl)
            ctype, fname, _, count = match.groups()
            fields.append({'name': fname, 'ctype': ctype, 'count': int(count) if count else None})
        structs.append({'name': name, 'fields': fields})
    return structs


def split_params(raw):
    raw = ' '.join(raw.split())
    if raw in ('', 'void'):
        return []
    params = []
    for item in raw.split(','):
        item = item.strip()
        match = re.match(r'(.+?)\s*(\w+)$', item)
        ctype, name = match.groups()
        params.append({'name': name, 'ctype': ctype})
    return params


def classify(ctype, struct_names):
    if ctype in struct_names:
        return 'struct'
    if '*' in ctype or ctype in HANDLE_TYPES:
        return 'ptr'
    if ctype == 'uint64_t':
        return 'u64'
    if ctype == 'double':
        return 'f64'
    if ctype == 'void':
        return 'void'
    return 'i32'


def parse_functions(text, struct_names):
    functions = []
    pattern = re.compile(r'CRYPTO_API\s+([\w\s\*]+?)\s*\b(cryptolib_\w+)\s*\(([^;{]*)\)\s*;')
    for ret, name, params in pattern.findall(text):
        ret = ' '.join(ret.split())
        plist = split_params(params)
        for p in plist:
            p['kind'] = classify(p['ctype'], struct_names)
        functions.append({'name': name, 'ret': ret, 'ret_kind': classify(ret, struct_names), 'params': plist})
    return functions


def c_wrapper(fn):
    name = fn['name']
    wrapper = 'cbw_' + name
    c_params = []
    call_args = []
    for p in fn['params']:
        if p['kind'] == 'u64':
            c_params.append('uint32_t %s_lo, uint32_t %s_hi' % (p['name'], p['name']))
            call_args.append('((uint64_t)%s_hi << 32) | (uint64_t)%s_lo' % (p['name'], p['name']))
        else:
            c_params.append('%s %s' % (p['ctype'], p['name']))
            call_args.append(p['name'])
    args = ', '.join(call_args)
    if fn['ret_kind'] == 'struct':
        c_params.insert(0, '%s* out' % fn['ret'])
        body = '    *out = %s(%s);' % (name, args)
        signature = 'void %s(%s)' % (wrapper, ', '.join(c_params))
    elif fn['ret_kind'] == 'u64':
        c_params.insert(0, 'uint32_t* out')
        body = '    uint64_t v = %s(%s);\n    out[0] = (uint32_t)(v & 0xffffffffu);\n    out[1] = (uint32_t)(v >> 32);' % (name, args)
        signature = 'void %s(%s)' % (wrapper, ', '.join(c_params))
    elif fn['ret_kind'] == 'void':
        body = '    %s(%s);' % (name, args)
        signature = 'void %s(%s)' % (wrapper, ', '.join(c_params) or 'void')
    else:
        body = '    return %s(%s);' % (name, args)
        signature = '%s %s(%s)' % (fn['ret'], wrapper, ', '.join(c_params) or 'void')
    return 'EMSCRIPTEN_KEEPALIVE\n%s {\n%s\n}\n' % (signature, body)


def layouts_program(structs):
    lines = ['#include "cryptolib_c.h"', '#include <stddef.h>', '#include <stdio.h>', '', 'int main(void) {', '    printf("{");']
    for i, s in enumerate(structs):
        sep = ', ' if i else ''
        lines.append('    printf("%s\\"%s\\": {\\"size\\": %%u, \\"fields\\": {", (unsigned)sizeof(%s));' % (sep, s['name'], s['name']))
        for j, f in enumerate(s['fields']):
            fsep = ', ' if j else ''
            lines.append('    printf("%s\\"%s\\": {\\"offset\\": %%u, \\"size\\": %%u}", (unsigned)offsetof(%s, %s), (unsigned)sizeof(((%s*)0)->%s));'
                         % (fsep, f['name'], s['name'], f['name'], s['name'], f['name']))
        lines.append('    printf("}}");')
    lines += ['    printf("}\\n");', '    return 0;', '}']
    return '\n'.join(lines) + '\n'


def main():
    header = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    text = strip_comments(header.read_text())
    structs = parse_structs(text)
    struct_names = {s['name'] for s in structs}
    for s in structs:
        for f in s['fields']:
            f['kind'] = classify(f['ctype'], struct_names)
            if f['ctype'] in ('uint8_t', 'uint16_t', 'int', 'int32_t', 'uint32_t', 'size_t'):
                f['kind'] = f['ctype']
    functions = parse_functions(text, struct_names)
    c_lines = ['#include "cryptolib_c.h"', '#include <emscripten/emscripten.h>', '#include <stdint.h>', '']
    c_lines += [c_wrapper(fn) for fn in functions]
    (out_dir / 'cipherbird_wrappers.c').write_text('\n'.join(c_lines))
    exports = ['_cbw_' + fn['name'] for fn in functions] + ['_malloc', '_free']
    (out_dir / 'exports.json').write_text(json.dumps(exports))
    (out_dir / 'signatures.json').write_text(json.dumps({'functions': functions, 'structs': structs}, indent=1))
    (out_dir / 'layouts.c').write_text(layouts_program(structs))
    print('functions %d structs %d' % (len(functions), len(structs)))


if __name__ == '__main__':
    main()
