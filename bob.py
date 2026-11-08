#!/usr/bin/env python3
"""Bob: the responder (TCP server by default) for Protocols I - IV.

  python3 bob.py --port 5555
  python3 bob.py --port 5555 --fault prime        # Protocol IV-I  (send non-prime p)
  python3 bob.py --port 5555 --fault generator    # Protocol IV-II (send non-generator g)

Bob looks at the first request ({"opcode":0,"type":...}) and runs the matching protocol.
"""
import argparse
import sys

import common as C

ME = "Bob"


# ----------------------------------------------------------------- Protocol I
def protocol_rsakey(st, args):
    p, q, n, e, d = C.rsa_generate()
    print("[Bob] generated RSA keypair: p=%d q=%d n=%d e=%d d=%d" % (p, q, n, e, d))
    C.send(st, ME, {"opcode": 0, "type": "RSAKey", "private": d, "public": e,
                    "parameter": {"p": p, "q": q}})


# ---------------------------------------------------------------- Protocol II
def protocol_rsa(st, args):
    p, q, n, e, d = C.rsa_generate()
    print("[Bob] generated RSA keypair: p=%d q=%d n=%d e=%d d=%d" % (p, q, n, e, d))
    C.send(st, ME, {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}})

    m = C.expect(C.recv(st, ME), 2, "RSA")
    enc = m["encrypted_key"]
    if len(enc) != 32:
        raise ValueError("encrypted_key must have 32 elements, got %d" % len(enc))
    key = C.rsa_decrypt_bytes(enc, d, n)
    print("[Bob] decrypted symmetric key (hex): %s" % key.hex())
    secure_chat(st, key, args)


# --------------------------------------------------------- Protocol III / IV
def protocol_dh(st, args):
    if args.fault == "prime":
        p = C.dh_bad_prime()
        g = C.random.randrange(2, p - 1)
        print("[Bob] FAULT INJECTION: non-prime p = %d" % p)
    else:
        p, g = C.dh_generate_params()
        if args.fault == "generator":
            g = C.dh_bad_generator(p)
            print("[Bob] FAULT INJECTION: non-generator g = %d" % g)
    b, B = C.dh_keypair(p, g)
    print("[Bob] DH parameters: p=%d g=%d private=%d public=%d" % (p, g, b, B))
    C.send(st, ME, {"opcode": 1, "type": "DH", "public": C.encode_public(B, args.pubfmt),
                    "parameter": {"p": p, "g": g}})

    m = C.expect(C.recv(st, ME), 1, "DH")               # PeerError if Alice rejects
    A = C.decode_public(m["public"])
    shared = pow(A, b, p)
    key = C.dh_aes_key(shared)
    print("[Bob] shared secret = %d, AES key = %s" % (shared, key.hex()))
    secure_chat(st, key, args)


def secure_chat(st, key, args):
    """Bob speaks first; then decrypts and prints Alice's answer."""
    text = C.get_message(args.message, "hello", ME)
    C.send(st, ME, {"opcode": 2, "type": "AES", "encryption": C.aes_encrypt_b64(key, text)})
    m = C.expect(C.recv(st, ME), 2, "AES")
    print("[Bob] decrypted message from Alice: %s" % C.aes_decrypt_b64(key, m["encryption"]))


def serve(st, args):
    req = C.expect(C.recv(st, ME), 0)
    handler = {"RSAKey": protocol_rsakey, "RSA": protocol_rsa, "DH": protocol_dh}.get(req.get("type"))
    if handler is None:
        C.send(st, ME, {"opcode": 3, "error": "unknown type"})
        return 1
    handler(st, args)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Bob (responder)")
    ap.add_argument("-a", "--addr", default="0.0.0.0")
    ap.add_argument("-p", "--port", type=int, required=True)
    ap.add_argument("-m", "--message", help="message to send (default: ask / 'hello')")
    ap.add_argument("--fault", choices=["prime", "generator"],
                    help="DH error test: send a non-prime p or a non-generator g")
    ap.add_argument("--pubfmt", choices=["int", "base64"], default="int",
                    help="encoding of the DH public key we send (default int, as in the professor's logs)")
    ap.add_argument("--timeout", type=float, default=30, help="seconds to wait for the peer (0 = forever)")
    ap.add_argument("-l", "--log", help="accepted for compatibility with the skeleton (ignored)")
    ap.add_argument("--connect", action="store_true", help="act as the TCP client instead")
    ap.add_argument("--forever", action="store_true", help="keep serving new connections")
    args = ap.parse_args()

    rc = 0
    while True:
        st = C.open_stream(args.addr, args.port, not args.connect, "Alice", args.timeout)
        try:
            rc = serve(st, args)
        except C.PeerError as e:
            print("[Bob] received error message: %s" % e)
        except TimeoutError:
            print("[Bob] timed out: the peer stopped answering")
            rc = 1
        except (OSError, ValueError, KeyError) as e:
            print("[Bob] protocol failure: %s" % e)
            rc = 1
        finally:
            st.close()
        if not args.forever or args.connect:
            break
    sys.exit(rc)


if __name__ == "__main__":
    main()
