#!/usr/bin/env python3
"""Write site/js/abi.json: the C ABI as the demo site's JavaScript caller sees it.

Runs gen_wrappers.py over bridge/cipherbird_c.h, compiles its layouts.c with
emcc to learn the wasm32 struct layouts, and joins the two with the header's
section titles and doc comments. Run after any change to the C ABI:

    python3 scripts/web/gen_site_abi.py
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'bridge' / 'cipherbird_c.h'
OUT = ROOT / 'site' / 'js' / 'abi.json'


ASCII = {0x2014: '-', 0x2013: '-', 0x2192: 'to', 0x2190: 'from', 0x2194: 'and', 0x2264: '<=',
         0x2265: '>=', 0xd7: 'x', 0x2026: '...', 0x2018: "'", 0x2019: "'", 0x201c: '"', 0x201d: '"',
         0xb7: '.', 0x2260: '!=', 0x2208: 'in', 0x2218: 'o', 0x2016: '||', 0xb5: 'u', 0x2248: '~'}
BOX = chr(0x2550)
DASH = chr(0x2014)


def ascii_only(text):
    for code, plain in ASCII.items():
        text = text.replace(chr(code), f' {plain} ' if plain.isalpha() else plain)
    return ' '.join(text.encode('ascii', 'ignore').decode().split())


def sections_and_docs(text):
    lines = text.split('\n')
    section = 'Core'
    doc = []
    found = {}
    pending = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if line.startswith('/* ' + BOX):
            title = lines[i + 1].strip(' *')
            section = re.split(r'\s+[' + DASH + r'(-]\s*|\s+\(', title)[0].strip()
            doc = []
            continue
        if stripped.startswith('/**'):
            doc = [stripped]
            if not stripped.endswith('*/'):
                pending = doc
            continue
        if pending is not None:
            pending.append(stripped)
            if stripped.endswith('*/'):
                pending = None
            continue
        match = re.search(r'CRYPTO_API\b.*?\b(cipherbird_\w+)\s*\(', line)
        if match:
            body = ' '.join(doc)
            body = re.sub(r'^/\*\*|\*/$', '', body)
            body = re.sub(r'\s\*\s', ' ', body)
            body = ' '.join(body.replace('*', ' ').split())
            found[match.group(1)] = {'section': ascii_only(section), 'doc': ascii_only(body)}
            doc = []
        elif stripped and not stripped.startswith('*') and not stripped.startswith('//'):
            if not stripped.startswith('CRYPTO_API') and not line.startswith(' '):
                doc = []
    return found


def main():
    text = HEADER.read_text()
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(ROOT / 'scripts/web/gen_wrappers.py'), str(HEADER), tmp],
                       check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['emcc', '-O1', '-I', str(ROOT / 'bridge'), f'{tmp}/layouts.c', '-o', f'{tmp}/layouts.js'],
                       check=True)
        layouts = json.loads(subprocess.run(['node', f'{tmp}/layouts.js'], check=True,
                                            capture_output=True, text=True).stdout)
        sigs = json.loads(Path(tmp, 'signatures.json').read_text())
    meta = sections_and_docs(text)
    structs = {}
    for struct in sigs['structs']:
        layout = layouts[struct['name']]
        fields = []
        for field in struct['fields']:
            place = layout['fields'][field['name']]
            fields.append({'name': field['name'], 'ctype': field['ctype'], 'count': field['count'],
                           'offset': place['offset'], 'size': place['size']})
        structs[struct['name']] = {'size': layout['size'], 'fields': fields}
    functions = []
    for fn in sigs['functions']:
        info = meta.get(fn['name'], {'section': 'Other', 'doc': ''})
        functions.append({'name': fn['name'], 'ret': fn['ret'], 'retKind': fn['ret_kind'],
                          'params': [{'name': p['name'], 'ctype': p['ctype'], 'kind': p['kind']}
                                     for p in fn['params']],
                          'section': info['section'], 'doc': info['doc']})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({'functions': functions, 'structs': structs}, indent=1) + '\n')
    print(f'{OUT.relative_to(ROOT)}: {len(functions)} functions, {len(structs)} structs')


main()
