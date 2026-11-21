#!/usr/bin/env python3
import argparse
import os
import subprocess
import tempfile

KEY_NAME = "ecdsa-secp384r1-key"  # replaces "zard"

def read_len(b, pos):
    first = b[pos]
    if first < 0x80:
        return first, pos + 1
    n = first & 0x7F
    return int.from_bytes(b[pos + 1:pos + 1 + n], "big"), pos + 1 + n

def find_scalar(b):
    if b[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    _, pos = read_len(b, 1)
    if b[pos:pos + 3] != b"\x02\x01\x01":
        raise ValueError("missing version INTEGER 1")
    pos += 3
    if b[pos] != 0x04:
        raise ValueError("missing OCTET STRING for private key")
    length, pos = read_len(b, pos + 1)
    return pos, pos + length

def normalize_pem(pem_text):
    lines = [l.strip() for l in pem_text.splitlines()]
    return "".join(l for l in lines if l and not l.startswith("-----"))

def bootstrap(openssl, curve, outdir, quiet):
    os.makedirs(outdir, exist_ok=True)
    full_der = os.path.join(outdir, f"{KEY_NAME}.der")
    nopub_der = os.path.join(outdir, f"{KEY_NAME}-nopub.der")

    subprocess.run(
        [openssl, "genpkey", "-algorithm", "EC",
         "-pkeyopt", f"ec_paramgen_curve:{curve}",
         "-outform", "DER", "-out", full_der],
        check=True,
    )
    subprocess.run(
        [openssl, "ec", "-in", full_der, "-no_public",
         "-outform", "DER", "-out", nopub_der],
        check=True,
    )
    if not quiet:
        print(f"bootstrapped key pair:")
        print(f"  full key:  {full_der}")
        print(f"  nopub key: {nopub_der}")
    return nopub_der

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--openssl", default="openssl")
    ap.add_argument("--start", type=int)
    ap.add_argument("--end", type=int)
    ap.add_argument("--bootstrap", action="store_true",
                     help="generate a fresh key pair and use it as the nopub input")
    ap.add_argument("--curve", default="secp384r1", help="curve for --bootstrap")
    ap.add_argument("--outdir", default=".", help="directory for --bootstrap output")
    ap.add_argument("-q", "--quiet", action="store_true",
                     help="suppress per-iteration output; print only the final result")
    ap.add_argument("--der", metavar="private_key.der", help="input key in DER, e.g. ecdsa-secp384r1-key-nopub.der")
    ap.add_argument("--cert", metavar="cert.pem", help="cert PEM to compare against")
    args = ap.parse_args()

    if args.bootstrap:
        der_path = bootstrap(args.openssl, args.curve, args.outdir, args.quiet)
    else:
        if not args.der:
            ap.error("private_key.der is required unless --bootstrap is given")
        der_path = args.der

    with open(der_path, "rb") as f:
        orig = f.read()

    start, end = find_scalar(orig)
    if args.start is not None:
        start = args.start
    if args.end is not None:
        end = args.end
    last = end - 1

    if not args.quiet:
        print(f"scalar bytes: offset {start}..{last} (last byte at offset {last}, "
              f"original value {orig[last]:02x})")

    if not args.cert:
        if not args.quiet:
            print("no cert given; skipping comparison, done after bootstrap/inspection.")
        return

    cert_pub = subprocess.run(
        [args.openssl, "x509", "-in", args.cert, "-pubkey", "-noout"],
        capture_output=True, text=True, check=True,
    ).stdout
    cert_pub_norm = normalize_pem(cert_pub)

    if not args.quiet:
        print("target public key (base64):")
        print(cert_pub_norm)
        print()

    found = False
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "candidate.der")
        for i in range(0x100):
            data = bytearray(orig)
            data[start:end] = bytes(end - start)
            data[last] = i
            with open(path, "wb") as f:
                f.write(data)

            if not args.quiet:
                print(f"===== last byte = {i:02x} =====")

            r = subprocess.run(
                [args.openssl, "ec", "-inform", "DER", "-in", path, "-text", "-noout"],
                capture_output=True, text=True,
            )
            if not args.quiet:
                print(r.stdout, end="")
            if r.returncode != 0:
                if not args.quiet:
                    print(f"[openssl exit {r.returncode}] {r.stderr.strip()}")
                continue

            p = subprocess.run(
                [args.openssl, "ec", "-inform", "DER", "-in", path,
                 "-pubout", "-outform", "PEM"],
                capture_output=True, text=True,
            )
            if p.returncode != 0:
                if not args.quiet:
                    print(f"[pubout error] {p.stderr.strip()}")
                continue

            cand_norm = normalize_pem(p.stdout)
            if not args.quiet:
                print(p.stdout, end="")

            if cand_norm == cert_pub_norm:
                found = True
                print(f"*** MATCH FOUND: last byte = {i:02x} (hex) / {i} (dec) ***")
                break

    if not found:
        print("No match found across 00..ff.")

if __name__ == "__main__":
    main()
