#!/usr/bin/env python3
"""Runs every protocol on localhost and checks the outputs.  python3 run_tests.py"""
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import aes_ecb
import common as C

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = [26000]
results = []
START_DELAY = 0.5     # seconds for a freshly spawned process to start listening
PROC_TIMEOUT = 30


def py(*a):
    return subprocess.Popen([sys.executable, os.path.join(HERE, a[0]), *a[1:]],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=HERE)


def next_port():
    PORT[0] += 1
    return str(PORT[0])


def report(name, ok, *outputs):
    results.append(ok)
    print("%-40s %s" % (name, "PASS" if ok else "FAIL"))
    if not ok:
        for label, out in outputs:
            print("--- %s ---\n%s" % (label, out))


def run(bob_args, alice_args, name, check):
    port = next_port()
    bob = py("bob.py", "--port", port, *bob_args)
    time.sleep(START_DELAY)
    alice = py("alice.py", "--port", port, *alice_args)
    a_out, _ = alice.communicate(timeout=PROC_TIMEOUT)
    b_out, _ = bob.communicate(timeout=PROC_TIMEOUT)
    report(name, check(a_out, b_out, alice.returncode), ("Alice", a_out), ("Bob", b_out))


def run_with_eve(protocol, name, check):
    """Alice -> Eve -> Bob, returns (alice_out, eve_out, bob_out)."""
    bob_port, eve_port = next_port(), next_port()
    bob = py("bob.py", "--port", bob_port, "--message", "hello")
    time.sleep(START_DELAY)
    eve = py("eve.py", "--port", eve_port, "--bob-port", bob_port)
    time.sleep(START_DELAY)
    alice = py("alice.py", "--port", eve_port, "--protocol", protocol, "--message", "world")
    a_out, _ = alice.communicate(timeout=PROC_TIMEOUT)
    e_out, _ = eve.communicate(timeout=PROC_TIMEOUT)
    b_out, _ = bob.communicate(timeout=PROC_TIMEOUT)
    report(name, check(a_out, e_out, b_out), ("Alice", a_out), ("Eve", e_out), ("Bob", b_out))
    print("\n".join("    " + l for l in e_out.splitlines()
                    if "***" in l or "factored" in l or "discrete log" in l))


def raw_client(port, script):
    """Drive Bob with hand-made messages. script(stream) -> bool."""
    bob = py("bob.py", "--port", port, "--message", "hello")
    time.sleep(START_DELAY)
    st = C.MessageStream(socket.create_connection(("127.0.0.1", int(port))), "Bob")
    st.sock.settimeout(PROC_TIMEOUT)
    try:
        ok = script(st)
    finally:
        st.close()
    b_out, _ = bob.communicate(timeout=PROC_TIMEOUT)
    return ok, b_out


# ------------------------------------------------------------------ unit tests
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
        p, q, n, e, d = C.rsa_generate()
        assert all(C.rsa_verify(p, q, e, d).values())
        assert C.rsa_decrypt_bytes(C.rsa_encrypt_bytes(b"hello\xff", e, n), d, n) == b"hello\xff"
    assert C.decode_public(C.encode_public(12345, "base64")) == 12345
    assert C.dh_aes_key(0x0102) == bytes.fromhex("0102" * 16)
    print("%-40s PASS" % "unit tests (primes, AES, RSA, DH)")

    # DH parameter / public key validation shared by Alice and Bob
    p, g = C.dh_generate_params()
    assert C.dh_param_error(p, g) is None
    assert C.dh_param_error(C.dh_bad_prime(), 2) == "incorrect prime number"
    assert C.dh_param_error(p, C.dh_bad_generator(p)) == "incorrect generator"
    assert C.dh_param_error(397, 2) == "incorrect prime number"      # prime, but outside [400, 500]
    assert C.dh_param_error("401", 2) == "incorrect prime number"    # wrong JSON type
    assert C.dh_public_ok(1, p) and C.dh_public_ok(p - 1, p)
    assert not C.dh_public_ok(0, p) and not C.dh_public_ok(p, p) and not C.dh_public_ok("1", p)
    for _ in range(20):
        a, A = C.dh_keypair(p, g)
        assert C.discrete_log(g, A, p) == a
    print("%-40s PASS" % "unit tests (DH validation, discrete log)")

    # every accepted shape of the RSA-encrypted key decodes to the same list
    p, q, n, e, d = C.rsa_generate()
    aes_key = secrets.token_bytes(32)
    enc = C.rsa_encrypt_bytes(aes_key, e, n)
    shapes = {
        "list of ints": enc,
        "list of decimal strings": [str(x) for x in enc],
        "list of base64 strings": [C.encode_public(x, "base64") for x in enc],
        "base64(JSON list)": base64.b64encode(json.dumps(enc).encode()).decode(),
        "base64(fixed-width big-endian)": base64.b64encode(b"".join(x.to_bytes(3, "big") for x in enc)).decode(),
    }
    for name, value in shapes.items():
        assert C.decode_encrypted_key(value) == enc, name
        for field in ("encrypted_key", "encryption"):
            assert C.get_encrypted_key({field: value}) == enc, (name, field)
    assert C.rsa_decrypt_bytes(C.decode_encrypted_key(shapes["base64(JSON list)"]), d, n) == aes_key
    for bad in ("!!!", 42, [True], base64.b64encode(b"abc").decode()):
        try:
            C.decode_encrypted_key(bad)
        except (ValueError, TypeError):
            pass
        else:
            raise AssertionError("accepted bad encrypted key %r" % (bad,))
    print("%-40s PASS" % "unit tests (encrypted_key formats)")


# ----------------------------------------------------------- raw-client scripts
def alt_format_rsa(st):
    """Protocol II where the key travels as base64(JSON list) under 'encryption'."""
    st.send({"opcode": 0, "type": "RSA"})
    m, _ = st.recv()
    e, n = C.decode_public(m["public"]), m["parameter"]["n"]
    key = secrets.token_bytes(32)
    enc = C.rsa_encrypt_bytes(key, e, n)
    st.send({"opcode": 2, "type": "RSA",
             "encryption": base64.b64encode(json.dumps(enc).encode()).decode()})
    m, _ = st.recv()
    if m.get("opcode") != 2 or C.aes_decrypt_b64(key, m["encryption"]) != "hello":
        return False
    st.send({"opcode": 2, "type": "AES", "encryption": C.aes_encrypt_b64(key, "world")})
    time.sleep(START_DELAY)
    return True


def bad_dh_public(st):
    """Bob must answer opcode 3 when Alice's public key is not in Z_p^*."""
    st.send({"opcode": 0, "type": "DH"})
    m, _ = st.recv()
    st.send({"opcode": 1, "type": "DH", "public": 0})
    m, _ = st.recv()
    return m.get("opcode") == 3 and m.get("error") == "invalid public key"


def bad_dh_params_from_client(st):
    """If the client echoes its own (p, g), Bob validates them too."""
    st.send({"opcode": 0, "type": "DH"})
    m, _ = st.recv()
    st.send({"opcode": 1, "type": "DH", "public": 2,
             "parameter": {"p": C.dh_bad_prime(), "g": m["parameter"]["g"]}})
    m, _ = st.recv()
    return m.get("opcode") == 3 and m.get("error") == "incorrect prime number"


def short_key(st):
    """A 31-element key must be rejected with opcode 3 instead of a crash."""
    st.send({"opcode": 0, "type": "RSA"})
    m, _ = st.recv()
    st.send({"opcode": 2, "type": "RSA", "encrypted_key": [1] * 31})
    m, _ = st.recv()
    return m.get("opcode") == 3 and "32 elements" in m.get("error", "")


def main():
    unit()
    run([], ["--protocol", "rsakey"], "Protocol I   (RSA keygen)",
        lambda a, b, rc: "keypair is CORRECT" in a and rc == 0)
    run(["--message", "hello"], ["--protocol", "rsa", "--message", "world"], "Protocol II  (RSA + AES)",
        lambda a, b, rc: "message from Bob: hello" in a and "message from Alice: world" in b and rc == 0)
    for fmt in ("base64", "int"):
        run(["--message", "hello", "--pubfmt", fmt], ["--protocol", "dh", "--message", "world", "--pubfmt", fmt],
            "Protocol III (DH + AES, %s)" % fmt,
            lambda a, b, rc: "message from Bob: hello" in a and "message from Alice: world" in b and rc == 0)
    run(["--fault", "prime"], ["--protocol", "dh"], "Protocol IV-I (non-prime p)",
        lambda a, b, rc: "incorrect prime number" in a and "received error message: incorrect prime number" in b and rc == 1)
    run(["--fault", "generator"], ["--protocol", "dh"], "Protocol IV-II (non-generator g)",
        lambda a, b, rc: "incorrect generator" in a and "received error message: incorrect generator" in b and rc == 1)

    # Bob-side robustness against a hand-written client
    for name, script, check in (
        ("Protocol II  (alt. encrypted_key format)", alt_format_rsa,
         lambda b: "message from Alice: world" in b),
        ("Bob rejects invalid DH public key", bad_dh_public,
         lambda b: "ERROR: invalid public key" in b),
        ("Bob validates client-sent DH params", bad_dh_params_from_client,
         lambda b: "ERROR: incorrect prime number" in b),
        ("Bob rejects short encrypted_key", short_key,
         lambda b: "ERROR: encrypted key must have 32 elements" in b),
    ):
        ok, b_out = raw_client(next_port(), script)
        report(name, ok and check(b_out), ("Bob", b_out))

    # -l/--log mirrors the console output into a file
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "alice.log")
        port = next_port()
        bob = py("bob.py", "--port", port)
        time.sleep(START_DELAY)
        alice = py("alice.py", "--port", port, "--protocol", "rsakey", "--log", log)
        a_out, _ = alice.communicate(timeout=PROC_TIMEOUT)
        bob.communicate(timeout=PROC_TIMEOUT)
        with open(log, encoding="utf-8") as f:
            content = f.read()
        report("--log writes the console output", "keypair is CORRECT" in content and content == a_out,
               ("Alice", a_out), ("log", content))

    # Additional tasks I & II: Alice -> Eve -> Bob
    run_with_eve("rsa", "Additional task I  (Eve on RSA)",
                 lambda a, e, b: "'hello'" in e and "'world'" in e
                 and "message from Bob: hello" in a and "message from Alice: world" in b)
    run_with_eve("dh", "Additional task II (Eve on DH)",
                 lambda a, e, b: "'hello'" in e and "'world'" in e and "discrete log" in e
                 and "message from Bob: hello" in a and "message from Alice: world" in b)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
