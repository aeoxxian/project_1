#!/usr/bin/env python3
"""Runs every protocol on localhost and checks the outputs.  python3 run_tests.py"""
import os
import subprocess
import sys
import time

import aes_ecb
import common as C

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = [26000]
results = []


def py(*a):
    return subprocess.Popen([sys.executable, os.path.join(HERE, a[0]), *a[1:]],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=HERE)


def run(bob_args, alice_args, name, checks, pre=None):
    PORT[0] += 1
    port = str(PORT[0])
    bob = py("bob.py", "--port", port, *bob_args)
    time.sleep(0.5)
    extra = pre(port) if pre else None
    alice = py("alice.py", "--port", extra or port, *alice_args)
    a_out, _ = alice.communicate(timeout=30)
    b_out, _ = bob.communicate(timeout=30)
    ok = all(c(a_out, b_out, alice.returncode) for c in checks)
    results.append(ok)
    print("%-34s %s" % (name, "PASS" if ok else "FAIL"))
    if not ok:
        print("--- Alice ---\n" + a_out + "--- Bob ---\n" + b_out)


def unit():
    for n in range(0, 2000):
        assert C.is_prime_trial(n) == C.is_prime_miller_rabin(n), n
    assert C.is_generator(2, 11) and not C.is_generator(3, 11)
    key = bytes(range(32))
    # FIPS-197 AES-256 test vector
    assert aes_ecb._py_ecb(key, bytes.fromhex("00112233445566778899aabbccddeeff"), True).hex() == \
        "8ea2b7ca516745bfeafc49904b496089"
    for m in ("", "hello", "a" * 16, "한글 OK"):
        assert aes_ecb.decrypt(key, aes_ecb.encrypt(key, m.encode())).decode() == m
        assert aes_ecb._py_ecb(key, aes_ecb.pad(m.encode()), True) == aes_ecb._raw_ecb(key, aes_ecb.pad(m.encode()), True)
    for _ in range(50):
        p, q, n, e, d = C.rsa_rsa = C.rsa_generate()
        assert all(C.rsa_verify(p, q, e, d).values())
        assert C.rsa_decrypt_bytes(C.rsa_encrypt_bytes(b"hello\xff", e, n), d, n) == b"hello\xff"
    assert C.decode_public(C.encode_public(12345, "base64")) == 12345
    assert C.dh_aes_key(0x0102) == bytes.fromhex("0102" * 16)
    print("%-34s PASS" % "unit tests (primes, AES, RSA, DH)")


def has(s):
    return lambda a, b, rc: s in a or s in b


def main():
    unit()
    run([], ["--protocol", "rsakey"], "Protocol I   (RSA keygen)",
        [lambda a, b, rc: "keypair is CORRECT" in a and rc == 0])
    run(["--message", "hello"], ["--protocol", "rsa", "--message", "world"], "Protocol II  (RSA + AES)",
        [lambda a, b, rc: "message from Bob: hello" in a and "message from Alice: world" in b and rc == 0])
    for fmt in ("base64", "int"):
        run(["--message", "hello", "--pubfmt", fmt], ["--protocol", "dh", "--message", "world", "--pubfmt", fmt],
            "Protocol III (DH + AES, %s)" % fmt,
            [lambda a, b, rc: "message from Bob: hello" in a and "message from Alice: world" in b and rc == 0])
    run(["--fault", "prime"], ["--protocol", "dh"], "Protocol IV-I (non-prime p)",
        [lambda a, b, rc: "incorrect prime number" in a and "received error message: incorrect prime number" in b and rc == 1])
    run(["--fault", "generator"], ["--protocol", "dh"], "Protocol IV-II (non-generator g)",
        [lambda a, b, rc: "incorrect generator" in a and "received error message: incorrect generator" in b and rc == 1])

    # Additional task I: Alice -> Eve -> Bob
    PORT[0] += 1
    bob_port, eve_port = str(PORT[0]), str(PORT[0] + 1000)
    bob = py("bob.py", "--port", bob_port, "--message", "hello")
    time.sleep(0.5)
    eve = py("eve.py", "--port", eve_port, "--bob-port", bob_port)
    time.sleep(0.5)
    alice = py("alice.py", "--port", eve_port, "--protocol", "rsa", "--message", "world")
    a_out, _ = alice.communicate(timeout=30)
    e_out, _ = eve.communicate(timeout=30)
    b_out, _ = bob.communicate(timeout=30)
    ok = ("'hello'" in e_out and "'world'" in e_out and "message from Bob: hello" in a_out
          and "message from Alice: world" in b_out)
    results.append(ok)
    print("%-34s %s" % ("Additional task I (Eve decrypts)", "PASS" if ok else "FAIL"))
    print("\n".join("    " + l for l in e_out.splitlines() if "***" in l or "factored" in l))
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
