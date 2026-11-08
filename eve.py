#!/usr/bin/env python3
"""Additional Tasks I & II: passive attacker (Eve) on Protocol II (RSA) and III (DH).

Eve sits between Alice and Bob and forwards every message UNCHANGED, but she
reads them.  Both attacks work because the primes are tiny (400 <= p, q <= 500).

Protocol II (RSA + AES):
  1. Bob's public key (e, n) is sent in clear. n < 250000 is factored instantly
     by trial division -> p, q -> phi -> d = e^-1 mod phi.
  2. With d she decrypts the RSA-encrypted 32-byte AES key (byte by byte).

Protocol III (DH + AES):
  1. p, g and Bob's public key B = g^b are sent in clear, then Alice's A = g^a.
  2. p <= 500, so the discrete log a = log_g(A) is found by brute force.
  3. shared = B^a mod p -> AES key (2-byte big-endian, repeated to 32 bytes).

With the AES key she decrypts every AES message in both directions.

  python3 bob.py  --port 5555
  python3 eve.py  --port 6666 --bob-addr 127.0.0.1 --bob-port 5555
  python3 alice.py --addr 127.0.0.1 --port 6666 --protocol rsa    # or --protocol dh
"""
import argparse
import socket
import threading

import common as C

state = {}
lock = threading.Lock()


def factor(n):
    for p in range(2, int(n ** 0.5) + 1):
        if n % p == 0:
            return p, n // p
    raise ValueError("n is prime?")


def log(text):
    print("[Eve] %s" % text, flush=True)


# ------------------------------------------------------------------- RSA
def learn_rsa_public(msg):
    e, n = C.decode_public(msg["public"]), msg["parameter"]["n"]
    p, q = factor(n)
    d = pow(e, -1, (p - 1) * (q - 1))
    state.update(e=e, n=n, d=d)
    log("RSA public key: n=%d e=%d -> factored n = %d * %d, recovered d = %d" % (n, e, p, q, d))


def learn_rsa_key(msg):
    key = C.rsa_decrypt_bytes(C.get_encrypted_key(msg), state["d"], state["n"])
    state["key"] = key
    log("decrypted AES key: %s" % key.hex())


# -------------------------------------------------------------------- DH
def learn_dh_params(msg):
    p, g = msg["parameter"]["p"], msg["parameter"]["g"]
    B = C.decode_public(msg["public"])
    state.update(p=p, g=g, B=B)
    log("DH parameters: p=%d g=%d, Bob's public key B=%d" % (p, g, B))


def learn_dh_alice(msg):
    p, g, B = state["p"], state["g"], state["B"]
    A = C.decode_public(msg["public"])
    a = C.discrete_log(g, A, p)                  # brute force: p <= 500
    shared = pow(B, a, p)
    state["key"] = C.dh_aes_key(shared)
    log("Alice's public key A=%d -> discrete log a=%d (g^a = A mod p)" % (A, a))
    log("shared secret B^a mod p = %d, AES key: %s" % (shared, state["key"].hex()))


# ------------------------------------------------------------------- AES
def read_aes(msg, direction):
    text = C.aes_decrypt_b64(state["key"], msg["encryption"])
    log("*** %s : %r ***" % (direction, text))


def inspect(msg, direction):
    """Learn from one message (Alice->Bob or Bob->Alice)."""
    if not isinstance(msg, dict):
        return
    op, typ = msg.get("opcode"), msg.get("type")
    with lock:
        if op == 1 and typ == "RSA":                           # Bob's public key
            learn_rsa_public(msg)
        elif op == 2 and typ == "RSA" and "d" in state:        # RSA-encrypted AES key
            learn_rsa_key(msg)
        elif op == 1 and typ == "DH" and "parameter" in msg:   # Bob: p, g, B
            learn_dh_params(msg)
        elif op == 1 and typ == "DH" and "p" in state:         # Alice: A
            learn_dh_alice(msg)
        elif op == 2 and typ == "AES" and "key" in state:      # AES messages
            read_aes(msg, direction)
        elif op == 3:
            log("peer error: %s" % msg.get("error"))


def relay(src, dst, direction):
    try:
        while True:
            msg, raw = src.recv()
            log("%s: %s" % (direction, raw))
            try:
                inspect(msg, direction)
            except Exception as e:                           # never break the relay
                log("could not analyse message: %s" % e)
            dst.sock.sendall(raw.encode())                   # forward untouched
    except (ConnectionError, OSError):
        pass
    finally:
        dst.close()
        src.close()


def main():
    ap = argparse.ArgumentParser(description="Eve (passive attacker on Protocol II / III)")
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True, help="port Alice connects to")
    ap.add_argument("--bob-addr", default="127.0.0.1")
    ap.add_argument("--bob-port", type=int, required=True)
    ap.add_argument("-l", "--log", help="also write the console output to this file")
    args = ap.parse_args()
    C.setup_log(args.log)

    alice = C.open_stream(args.addr, args.port, True, "Alice")
    bob = C.MessageStream(socket.create_connection((args.bob_addr, args.bob_port)), "Bob")
    t1 = threading.Thread(target=relay, args=(alice, bob, "Alice -> Bob"))
    t2 = threading.Thread(target=relay, args=(bob, alice, "Bob -> Alice"))
    t1.start(); t2.start(); t1.join(); t2.join()


if __name__ == "__main__":
    main()
