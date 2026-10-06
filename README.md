# CborLens

A browser-native CBOR (RFC 8949) inspector: full decode of any blob, plus the canonicality analysis that matters before you hash or sign it. No uploads - everything decodes locally.

**Live:** https://ilanis-agent.github.io/cborlens/

## Why

CBOR is the encoding inside COSE signatures, WebAuthn attestations, CWT tokens and half the IoT world. Two encoders can legitimately produce different bytes for the same data - which is exactly why deterministic encoding rules exist. CborLens decodes the blob and tells you whether it follows RFC 8949 core deterministic encoding: shortest-form integers, definite lengths, and length-first bytewise-sorted map keys.

## Engine

`engine.js` is a dependency-free decoder shared between the web app and the Node test runner: all seven major types, 64-bit integers via BigInt (exact above 2^53), definite and indefinite strings with chunk tracking, nested arrays and maps, semantic tags, simple values, and float16/32/64 (float16 decoded manually). Duplicate map keys are a warning; non-shortest integers, indefinite lengths, and unsorted keys are canonicality violations.

## Tests

```
python3 tests/build_corpus.py   # rebuilds corpus + independent python oracle decode
node tests/run_tests.js         # 74 checks
```

The corpus builder contains a complete second CBOR decoder in Python. Every structural fact (values, item counts, depth, canonicality verdict, duplicate keys) is computed by that independent decoder, and the JS engine must agree on all of it.

Corpus (`tests/corpus/`, mirrored as `.cbor.b64`):

| file | what it exercises |
| --- | --- |
| `small.cbor` | canonical nested map/array, bool, null |
| `floats.cbor` | float16 1.5, float32 0.1, float64 pi, -inf, NaN |
| `noncanon.cbor` | non-shortest int, unsorted map keys, indefinite text with chunks - 3 violations |
| `tagged.cbor` | datetime tag, epoch tag, bignum tag, uint64 max (exact via BigInt) |
| `dupkeys.cbor` | duplicate map key - warning, still decodable |
| `trunc.cbor` | cut bytes - hard truncation error |

## Limits

- Tag semantics are shown as tag numbers with the inner value; no registry of meanings beyond display.
- Byte strings show a hex preview, not full contents, in the tree (the hex dump shows the whole file).
- Canonicality follows RFC 8949 section 4.2.1 (core deterministic encoding); it does not enforce the optional "preferred serialization" rules for floats.

## Deploy

Static site; GitHub Pages serves `index.html` / `app.html` from the repo root.
