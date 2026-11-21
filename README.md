# eMuddler

A proof-of-concept tool for recovering EC private keys affected by the
October 2026 eMudhra intermediate CA key compromise (CVE-2026-111943,
CVE-2026-111944), in which a flawed key-generation ceremony produced
trivially small P-384 private scalars instead of properly random 384-bit
values. Where the vulnerable keys are small enough, the private scalar's
non-zero bytes are confined to the last byte (or last few bytes) of the
384-bit value, which makes brute-force recovery from the public key alone
computationally trivial — a 256-value search per byte, rather than a
~2^384 search.

## Background

In October 2026, eMudhra disclosed that eight intermediate Certificate
Authority (CA) private keys (six TLS and two code-signing) were
compromised due to an April 2025 key-generation script error that
produced trivially guessable keys.

**What happened:**

- **Weak P-384 keys.** A script flaw during an April 2025 key-generation
  ceremony produced tiny private key values (such as single- and
  two-digit integers) instead of properly random 384-bit keys, letting
  attackers derive the keys and forge certificates.
- **Revocation and distrust.** eMudhra revoked the eight intermediate
  certificates on October 18, 2026, Sectigo revoked related
  cross-certificates on October 19, and major browsers and OS vendors
  (Chrome, Mozilla, Apple, Microsoft) moved to block or untrust them.
- **Business impact.** eMudhra announced an exit from public TLS
  certificate issuance while stating its eSignature and enterprise
  products remained unaffected.

See also: [emudhra.we-have-a-problem.com](https://emudhra.we-have-a-problem.com/)

This tool was built to understand and reproduce the mechanics of that
disclosed flaw: given a vulnerable certificate's public key, and the
knowledge that the corresponding private scalar is a small integer
(effectively zero in all but its last byte(s)), recover the private key
by exhaustive search and verify it against the certificate's public key.

## Scope and limitations

This is **not** a general attack on ECDSA/EC private keys. Brute-forcing
an EC-384 scalar in the general case is a ~2^384 search and is
computationally infeasible. This tool only works because the specific
vulnerability class it targets produces scalars that are *not*
uniformly random — they are small integers, meaning almost every byte of
the 48-byte secp384r1 scalar is zero. That is what reduces the practical
search space to 256 candidates per unknown byte.

If a key was generated correctly (a uniformly random 384-bit scalar),
this tool cannot recover it. It only applies to certificates affected by
this class of weak key generation, or to test keys you've deliberately
constructed to resemble them.

## Requirements

- Python 3
- `openssl` on `PATH` (the script shells out to `openssl ec`, `openssl
  pkey`, and `openssl x509`)
  - On macOS, the system `openssl` is LibreSSL and does not support
    `-no_public`. Install OpenSSL 3 via Homebrew (`brew install
    openssl@3`) and point `--openssl` at
    `/opt/homebrew/opt/openssl@3/bin/openssl` if you need to strip the
    public key from a freshly generated key.

## Installation

```bash
git clone https://github.com/shaofeihuang/emuddler.git
cd emuddler
```

No dependencies beyond the Python standard library. The main script is
`emuddler.py` (rename `iterate.py` to this if you're carrying over the
version from earlier in this conversation).

## Usage

```
usage: emuddler.py [-h] [--openssl OPENSSL] [--start START] [--end END]
                    [--bootstrap] [--curve CURVE] [--outdir OUTDIR]
                    [--cert cert.pem] [-q]
                    [private_key.der]

positional arguments:
  private_key.der     input key in DER, e.g. ecdsa-secp384r1-key-nopub.der

options:
  -h, --help          show this help message and exit
  --openssl OPENSSL   path to the openssl binary (default: openssl)
  --start START       override scalar start offset in the DER file
  --end END           override scalar end offset (exclusive)
  --bootstrap         generate a fresh key pair and use it as the nopub
                      input
  --curve CURVE       curve for --bootstrap (default: secp384r1)
  --outdir OUTDIR     directory for --bootstrap output (default: .)
  --cert cert.pem     cert PEM to compare the recovered public key against
  -q, --quiet         suppress per-iteration output; print only the final
                      result
```

### 1. Generate a test key pair

```bash
python3 emuddler.py --bootstrap --curve secp384r1
```

This runs, under the hood:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 \
  -outform DER -out ecdsa-secp384r1-key.der
openssl ec -in ecdsa-secp384r1-key.der -no_public \
  -outform DER -out ecdsa-secp384r1-key-nopub.der
```

producing `ecdsa-secp384r1-key.der` (full key pair) and
`ecdsa-secp384r1-key-nopub.der` (private key only, no embedded public
key) in `--outdir`. For realistic testing of the vulnerable scenario,
manually zero out all but the last byte(s) of the scalar in the `-nopub`
file before recovery (or use `--start`/`--end` to tell the tool which
bytes to treat as unknown).

### 2. Recover the private key against a known public key / certificate

```bash
python3 emuddler.py ecdsa-secp384r1-key-nopub.der --cert EM-DV-TLS-CA-G3B.crt.pem
```

The script:

1. Parses the DER file to locate the private scalar (the `OCTET STRING`
   inside the `ECPrivateKey` `SEQUENCE`), without assuming a fixed header
   length, so it works across different curves and encodings.
2. Zeroes the entire scalar except the last byte.
3. For each value `0x00`–`0xff` in the last byte, writes a candidate DER
   key, runs `openssl ec -text -noout` on it, derives the public key with
   `openssl ec -pubout`, and compares it (base64 body only) against the
   public key extracted from `--cert` via `openssl x509 -pubkey -noout`.
4. Reports the first matching byte value in both hex and decimal, or
   reports that no match was found.

### 3. Quiet mode

```bash
python3 emuddler.py ecdsa-secp384r1-key-nopub.der --cert EM-DV-TLS-CA-G3B.crt.pem -q
```

Suppresses all per-iteration output and prints only:

```
*** MATCH FOUND: last byte = 9c (hex) / 156 (dec) ***
```

or

```
No match found across 00..ff.
```

### Overriding scalar offsets

If the automatic DER parser ever gets the offsets wrong for a given file
(e.g. an unusual encoding), or the vulnerable key has more than one
non-zero byte, you can force the search range manually:

```bash
python3 emuddler.py private_key.der --cert cert.pem --start 7 --end 55
```

`--end` is exclusive; the byte at `--end - 1` is the one that gets
iterated. Searching a wider range (more than one unknown byte) requires
extending the loop in the script to iterate over multiple byte positions
rather than just the last one.

## Example output

```
scalar bytes: offset 7..54 (last byte at offset 54, original value 00)
target public key (base64):
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4Dh...
===== last byte = 00 =====
[openssl exit 1] ... (all-zero scalar is not a valid private key)
===== last byte = 01 =====
priv:
    00:00:...:01
pub:
    04:...
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
...
*** MATCH FOUND: last byte = 9c (hex) / 156 (dec) ***
```

## Responsible use

The certificates affected by this specific vulnerability have already
been publicly disclosed, revoked, and distrusted by browsers and OS
vendors as of October 2026 — this tool is published for education,
detection tooling (e.g. verifying that a given certificate's key is or
isn't trivially weak), and security research into this incident, not to
target systems that have not already been identified as affected.

Do not use this tool, or any derivative of it, against certificates or
systems you do not own or do not have explicit authorization to test. If
you believe you have found a *new*, undisclosed instance of this or a
similar weak-key-generation issue, follow responsible disclosure and
report it directly to the affected CA rather than via a public tool or
repository.

## License

Copyright 2026 HUANG Shaofei

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
