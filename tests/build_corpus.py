#!/usr/bin/env python3
"""Build the CBOR corpus: hand-encoder produces bytes, then an independent
python DECODER recomputes every expected fact (structure, canonicality,
duplicate keys) - the JS engine never touches this file."""
import json, os, struct

os.makedirs('tests/corpus', exist_ok=True)

# ---------- encoder (used only to write files) ----------
def hdr(mt, n):
    if n < 24: return bytes([mt << 5 | n])
    if n < 256: return bytes([mt << 5 | 24, n])
    if n < 65536: return bytes([mt << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 2**32: return bytes([mt << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([mt << 5 | 27]) + n.to_bytes(8, 'big')

def enc(x):
    if isinstance(x, bool): return b'\xf5' if x else b'\xf4'
    if x is None: return b'\xf6'
    if isinstance(x, int):
        return hdr(0, x) if x >= 0 else hdr(1, -1 - x)
    if isinstance(x, float): return b'\xfb' + struct.pack('>d', x)
    if isinstance(x, bytes): return hdr(2, len(x)) + x
    if isinstance(x, str): return hdr(3, len(x.encode())) + x.encode()
    if isinstance(x, list): return hdr(4, len(x)) + b''.join(enc(i) for i in x)
    if isinstance(x, dict): return hdr(5, len(x)) + b''.join(enc(k) + enc(v) for k, v in x.items())
    raise TypeError(x)

# ---------- independent decoder (the oracle) ----------
def dec(buf, st, pos=0):
    def u8(p):
        if p >= len(buf): raise Trunc
        return buf[p], p + 1
    def take(p, n):
        if p + n > len(buf): raise Trunc
        return buf[p:p+n], p + n
    def head(p):
        b, p = u8(p)
        mt, ai = b >> 5, b & 31
        st['items'] += 1
        st['last_ai'] = ai
        if ai < 24: return mt, ai, p
        if ai == 24:
            v, p = u8(p)
            if v < 24: st['violations'].append('non-shortest integer encoding')
            return mt, v, p
        if ai in (25, 26, 27):
            n = {25: 2, 26: 4, 27: 8}[ai]
            a, p = take(p, n)
            v = int.from_bytes(a, 'big')
            if v < (1 << (8 * n - 8 if n > 1 else 0)) or (n == 2 and v < 256) or (n == 4 and v < 65536) or (n == 8 and v < 2**32):
                st['violations'].append('non-shortest integer encoding')
            return mt, v, p
        if ai == 31: return mt, None, p
        raise Bad(f'reserved additional info {ai}')
    def item(p, depth):
        st['max_depth'] = max(st['max_depth'], depth)
        mt, v, p = head(p)
        if mt == 0: return ('uint', v), p
        if mt == 1: return ('nint', -1 - v), p
        if mt in (2, 3):
            chunks = []
            if v is None:
                st['violations'].append('indefinite-length string (not canonical)')
                while True:
                    if p >= len(buf): raise Trunc
                    if buf[p] == 0xFF: p += 1; break
                    cmt, cv, p = head(p)
                    st['items'] -= 1  # chunk headers are parts of the string, not items
                    if cmt != mt or cv is None: raise Bad('bad chunk')
                    cd, p = take(p, cv)
                    chunks.append(cd)
            else:
                cd, p = take(p, v)
                chunks.append(cd)
            data = b''.join(chunks)
            if mt == 2: return ('bytes', data.hex()), p
            try: return ('text', data.decode('utf-8')), p
            except UnicodeDecodeError:
                st['warnings'].append('invalid UTF-8 in text string')
                return ('text', '?invalid-utf8?'), p
        if mt == 4:
            out = []
            if v is None:
                st['violations'].append('indefinite-length array (not canonical)')
                while True:
                    if p >= len(buf): raise Trunc
                    if buf[p] == 0xFF: p += 1; break
                    it, p = item(p, depth + 1)
                    out.append(it)
            else:
                for _ in range(v):
                    it, p = item(p, depth + 1)
                    out.append(it)
            return ('array', out), p
        if mt == 5:
            pairs, keys = [], []
            def key():
                nonlocal p
                s0 = p
                it, p2 = item(p, depth + 1)
                p = p2
                return it, buf[s0:p2]
            if v is None:
                st['violations'].append('indefinite-length map (not canonical)')
                while True:
                    if p >= len(buf): raise Trunc
                    if buf[p] == 0xFF: p += 1; break
                    k, ke = key()
                    val, p = item(p, depth + 1)
                    pairs.append((k, val)); keys.append(ke)
            else:
                for _ in range(v):
                    k, ke = key()
                    val, p = item(p, depth + 1)
                    pairs.append((k, val)); keys.append(ke)
            for a, b in zip(keys, keys[1:]):
                if a == b: st['warnings'].append('duplicate map key')
                if a > b: st['violations'].append('map keys not in canonical order')
            return ('map', pairs), p
        if mt == 6:
            inner, p = item(p, depth + 1)
            return ('tag', v, inner), p
        if mt == 7:
            ai = st['last_ai']
            if v is None: raise Bad('stray break')
            if ai == 25:
                return ('float16', struct.unpack('>e', v.to_bytes(2, 'big'))[0]), p
            if ai == 26:
                return ('float32', struct.unpack('>f', v.to_bytes(4, 'big'))[0]), p
            if ai == 27:
                return ('float64', struct.unpack('>d', v.to_bytes(8, 'big'))[0]), p
            if v in (20, 21, 22, 23):
                return ('simple', {20: False, 21: True, 22: None, 23: 'undefined'}[v]), p
            return ('simple', v), p
        raise Bad('impossible')
    top = []
    while pos < len(buf):
        it, pos = item(pos, 1)
        top.append(it)
    return top

class Trunc(Exception): pass
class Bad(Exception): pass

def oracle(data):
    st = {'violations': [], 'warnings': [], 'items': 0, 'max_depth': 0}
    try:
        top = dec(data, st)
        err = None
    except Trunc:
        top, err = [], 'truncated: ran out of bytes'
    return {'top': top, 'error': err, 'warnings': st['warnings'],
            'violations': st['violations'], 'canonical': not st['violations'],
            'items': st['items'], 'max_depth': st['max_depth']}

# ---------- corpus ----------
expected = []

# 1. small: canonical map with nested array + map, bool, null
d1 = enc({1: 'one', 2: [1, 2, 3], 3: {4: True, 5: None}})
open('tests/corpus/small.cbor', 'wb').write(d1)
expected.append({'file': 'small.cbor', 'oracle': oracle(d1)})

# 2. floats: f16 1.5, f32 0.1, f64 pi, -inf, nan
f = (hdr(4, 5)
     + b'\xf9' + struct.pack('>e', 1.5)
     + b'\xfa' + struct.pack('>f', 0.1)
     + b'\xfb' + struct.pack('>d', 3.141592653589793)
     + b'\xfa' + struct.pack('>f', float('-inf'))
     + b'\xf9\x7e\x00')
open('tests/corpus/floats.cbor', 'wb').write(f)
expected.append({'file': 'floats.cbor', 'oracle': oracle(f)})

# 3. noncanon: non-shortest ints + unsorted map keys + indefinite text
nc = (bytes([0x18, 0x17])                      # 23 in 1-byte form (should be direct)
      + b'\x82' + enc('b') + enc('a')          # definite array ok
      + b'\xa2' + enc('z') + enc(1) + enc('a') + enc(2)  # unsorted keys
      + b'\x7f' + hdr(3, 3) + b'foo' + hdr(3, 3) + b'bar' + b'\xff')  # indefinite text
open('tests/corpus/noncanon.cbor', 'wb').write(nc)
expected.append({'file': 'noncanon.cbor', 'oracle': oracle(nc)})

# 4. tagged: datetime tag 0, epoch tag 1, bignum tag 2, uint64 max
tg = (hdr(4, 4)
      + hdr(6, 0) + enc('2026-10-06T20:00:00Z')
      + hdr(6, 1) + enc(1759867200)
      + hdr(6, 2) + hdr(2, 9) + (1).to_bytes(9, 'big')  # bignum 2^64
      + hdr(0, 2**64 - 1))
open('tests/corpus/tagged.cbor', 'wb').write(tg)
expected.append({'file': 'tagged.cbor', 'oracle': oracle(tg)})

# 5. dupkeys: map with duplicate key
dk = b'\xa2' + enc('x') + enc(1) + enc('x') + enc(2)
open('tests/corpus/dupkeys.cbor', 'wb').write(dk)
expected.append({'file': 'dupkeys.cbor', 'oracle': oracle(dk)})

# 6. truncated: cut tagged
tc = tg[:int(len(tg) * 0.5)]
open('tests/corpus/trunc.cbor', 'wb').write(tc)
expected.append({'file': 'trunc.cbor', 'expect_error': 'truncated'})

def sanitize(o):
    if isinstance(o, int) and not isinstance(o, bool) and abs(o) > 2**53:
        return str(o)
    if isinstance(o, float):
        if o != o: return 'NaN'
        if o == float('inf'): return 'Infinity'
        if o == float('-inf'): return '-Infinity'
        return o
    if isinstance(o, dict): return {k: sanitize(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)): return [sanitize(x) for x in o]
    return o

expected = [sanitize(e) for e in expected]

def default(o):
    if isinstance(o, bytes): return o.hex()
    if isinstance(o, float) and o != o: return 'NaN'
    raise TypeError(type(o))

json.dump({'items': expected}, open('tests/expected.json', 'w'), default=default, indent=1)
print('corpus:', [e['file'] for e in expected])
for e in expected:
    o = e.get('oracle')
    if o: print(e['file'], 'items:', o['items'], 'depth:', o['max_depth'], 'canonical:', o['canonical'], 'violations:', len(o['violations']), 'warnings:', o['warnings'])
