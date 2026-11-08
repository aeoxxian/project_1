#!/usr/bin/env python3
"""Alice: the initiator (sends opcode 0 requests) for Protocols I - IV.

python3 alice.py --addr 127.0.0.1 --port 5555 --protocol rsakey   # Protocol I
python3 alice.py --addr 127.0.0.1 --port 5555 --protocol rsa      # Protocol II
python3 alice.py --addr 127.0.0.1 --port 5555 --protocol dh       # Protocol III / IV
"""

import argparse
import secrets
import sys

import common as C

ME = "Alice"


# ----------------------------------------------------------------- Protocol I
def protocol_rsakey(st, args):
    C.send(st, ME, {"opcode": 0, "type": "RSAKey"})
    m = C.expect(C.recv(st, ME), 0, "RSAKey")
    p, q = m["parameter"]["p"], m["parameter"]["q"]
    d, e = C.decode_public(m["private"]), C.decode_public(m["public"])

    print("\n=== RSA keypair received from Bob ===")
    print("p = %d, q = %d, n = %d" % (p, q, p * q))
    print("public  key e = %d" % e)
    print("private key d = %d" % d)
    checks = C.rsa_verify(p, q, e, d)
    for name, ok in checks.items():
        print("  [%s] %s" % ("OK" if ok else "FAIL", name))
    ok = all(checks.values())
    print("=> keypair is %s" % ("CORRECT" if ok else "INCORRECT"))
    return 0 if ok else 1


# ---------------------------------------------------------------- Protocol II
def protocol_rsa(st, args):
    C.send(st, ME, {"opcode": 0, "type": "RSA"})
    m = C.expect(C.recv(st, ME), 1, "RSA")
    e, n = C.decode_public(m["public"]), m["parameter"]["n"]
    print("\n[Alice] fetched public key: n = %d, e = %d" % (n, e))

    key = secrets.token_bytes(32)  # random AES-256 key
    enc_key = C.rsa_encrypt_bytes(key, e, n)  # one byte at a time
    print("[Alice] symmetric key (hex): %s" % key.hex())
    C.send(st, ME, {"opcode": 2, "type": "RSA", "encrypted_key": enc_key})
    return secure_chat(st, key, args, first=False)


# --------------------------------------------------------- Protocol III / IV
def protocol_dh(st, args):
    C.send(st, ME, {"opcode": 0, "type": "DH"})
    m = C.expect(C.recv(st, ME), 1, "DH")
    p, g = m["parameter"]["p"], m["parameter"]["g"]
    B = C.decode_public(m["public"])
    print("\n[Alice] received DH parameters: p = %d, g = %d, B = %d" % (p, g, B))

    # Protocol IV-I: primality test (and allowed range) on p
    if not (C.P_MIN <= p <= C.P_MAX and C.is_prime(p)):
        return abort(st, "incorrect prime number")
    print("[Alice] p is prime: OK")
    # Protocol IV-II: g must be a generator of Z_p^*
    if not C.is_generator(g, p):
        return abort(st, "incorrect generator")
    print("[Alice] g is a generator: OK")

    a, A = C.dh_keypair(p, g)
    # "auto": answer in the same format the peer used for its public key
    fmt = args.pubfmt
    if fmt == "auto":
        fmt = "int" if isinstance(m["public"], int) else "base64"
    print("[Alice] public key format: %s" % fmt)
    C.send(st, ME, {"opcode": 1, "type": "DH", "public": C.encode_public(A, fmt)})
    shared = pow(B, a, p)
    key = C.dh_aes_key(shared)
    print("[Alice] shared secret = %d, AES key = %s" % (shared, key.hex()))
    return secure_chat(st, key, args, first=False)


def abort(st, reason):
    C.send(st, ME, {"opcode": 3, "error": reason})
    print("[Alice] ERROR: %s -- quitting" % reason)
    return 1


# ------------------------------------------------------------ AES messaging
def secure_chat(st, key, args, first):
    """Bob speaks first; Alice decrypts, prints, then answers."""
    m = C.expect(C.recv(st, ME), 2, "AES")
    print(
        "[Alice] decrypted message from Bob: %s"
        % C.aes_decrypt_b64(key, m["encryption"])
    )
    text = C.get_message(args.message, "world", ME)
    C.send(
        st, ME, {"opcode": 2, "type": "AES", "encryption": C.aes_encrypt_b64(key, text)}
    )
    return 0


def main():
    ap = argparse.ArgumentParser(description="Alice (initiator)")
    ap.add_argument("-a", "--addr", default="127.0.0.1")
    ap.add_argument("-p", "--port", type=int, required=True)
    ap.add_argument("--protocol", choices=["rsakey", "rsa", "dh"], required=True)
    ap.add_argument("-m", "--message", help="message to send (default: ask / 'world')")
    ap.add_argument(
        "--pubfmt",
        choices=["auto", "int", "base64"],
        default="auto",
        help="encoding of the DH public key we send (default auto: mirror the peer's format)",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="seconds to wait for the peer (0 = forever)",
    )
    ap.add_argument(
        "-l", "--log", help="accepted for compatibility with the skeleton (ignored)"
    )
    ap.add_argument(
        "--listen", action="store_true", help="act as the TCP server instead"
    )
    args = ap.parse_args()

    st = C.open_stream(args.addr, args.port, args.listen, "Bob", args.timeout)
    try:
        rc = {"rsakey": protocol_rsakey, "rsa": protocol_rsa, "dh": protocol_dh}[
            args.protocol
        ](st, args)
    except C.PeerError as e:
        print("[Alice] received error message: %s" % e)
        rc = 1
    except TimeoutError:
        print(
            "[Alice] timed out: the peer stopped answering (did it reject our last message?)"
        )
        rc = 1
    except (OSError, ValueError, KeyError) as e:
        print("[Alice] protocol failure: %s" % e)
        rc = 1
    finally:
        st.close()
    sys.exit(rc)


if __name__ == "__main__":
    main()
