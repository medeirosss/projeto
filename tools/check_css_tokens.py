#!/usr/bin/env python3
"""MAGI CSS token integrity check; run from project root."""
from pathlib import Path
import re,sys
root=Path(__file__).resolve().parents[1]/'frontend'
tokens=(root/'design-system/tokens.css').read_text(encoding='utf-8')
expected={'--magi-bg':'#000000','--magi-panel':'#0b0b0b','--magi-elevated':'#151515','--magi-border':'#292929'}
errors=[]
for key,value in expected.items():
    if not re.search(re.escape(key)+r'\s*:\s*'+re.escape(value)+r'(?=[;\s}])',tokens,re.I):errors.append(f'missing canonical {key}={value}')
for p in root.rglob('*.css'):
    if p.name=='tokens.css':continue
    s=p.read_text(encoding='utf-8',errors='replace')
    for m in re.finditer(r'(--magi-(?:bg|panel|elevated|border))\s*:',s):
        errors.append(f'noncanonical token declaration: {p.relative_to(root)}:{s.count(chr(10),0,m.start())+1} {m.group(1)}')
    for m in re.finditer(r'(--[\w-]+)\s*:\s*var\(\s*\1\s*\)',s):
        errors.append(f'self-referential token: {p.relative_to(root)}:{s.count(chr(10),0,m.start())+1}')
print('PASS: canonical MAGI CSS tokens' if not errors else '\n'.join(errors))
sys.exit(bool(errors))
