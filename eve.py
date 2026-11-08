#!/usr/bin/env python3
"""Additional Task I: passive attacker (Eve) on Protocol II (RSA + AES).

Eve sits between Alice and Bob and forwards every message UNCHANGED, but she
reads them:
  1. Bob's public key (e, n) is sent in clear. Since 400 <= p,q <= 500, n < 250000
     can be factored instantly by trial division -> p, q -> phi -> d = e^-1 mod phi.
  2. With d she decrypts the RSA-encrypted 32-byte AES key (byte by byte).
  3. With the AES key she decrypts every AES message in both directions.

  python3 bob.py  --port 5555
  python3 eve.py  --port 6666 --bob-addr 127.0.0.1 --bob-port 5555
  python3 alice.py --addr 127.0.0.1 --port 6666 --protocol rsa
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


def inspect(msg, direction):
    """Learn from one message (Alice->Bob or Bob->Alice)."""
    if not isinstance(msg, dict):
        return
    op, typ = msg.get("opcode"), msg.get("type")
    with lock:
        if op == 1 and typ == "RSA":                        # Bob's public key
            e, n = C.decode_public(msg["public"]), msg["parameter"]["n"]
            p, q = factor(n)
            d = pow(e, -1, (p - 1) * (q - 1))
            state.update(e=e, n=n, d=d)
            print("[Eve] public key: n=%d e=%d -> factored n = %d * %d, recovered d = %d"
                  % (n, e, p, q, d), flush=True)
        elif op == 2 and typ == "RSA" and "d" in state:     # RSA-encrypted AES key
            state["key"] = C.rsa_decrypt_bytes(msg["encrypted_key"], state["d"], state["n"])
            print("[Eve] decrypted AES key: %s" % state["key"].hex(), flush=True)
        elif op == 2 and typ == "AES" and "key" in state:   # AES messages
            text = C.aes_decrypt_b64(state["key"], msg["encryption"])
            print("[Eve] *** %s : %r ***" % (direction, text), flush=True)


def relay(src, dst, direction):
    try:
        while True:
            msg, raw = src.recv()
            print("[Eve] %s: %s" % (direction, raw), flush=True)
            try:
                inspect(msg, direction)
            except Exception as e:                           # never break the relay
                print("[Eve] could not analyse message: %s" % e, flush=True)
            dst.sock.sendall(raw.encode())                   # forward untouched
    except (ConnectionError, OSError):
        pass
    finally:
        dst.close()
        src.close()


def main():
    ap = argparse.ArgumentParser(description="Eve (passive attacker on Protocol II)")
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True, help="port Alice connects to")
    ap.add_argument("--bob-addr", default="127.0.0.1")
    ap.add_argument("--bob-port", type=int, required=True)
    args = ap.parse_args()

    alice = C.open_stream(args.addr, args.port, True, "Alice")
    bob = C.MessageStream(socket.create_connection((args.bob_addr, args.bob_port)), "Bob")
    t1 = threading.Thread(target=relay, args=(alice, bob, "Alice -> Bob"))
    t2 = threading.Thread(target=relay, args=(bob, alice, "Bob -> Alice"))
    t1.start(); t2.start(); t1.join(); t2.join()


if __name__ == "__main__":
    main()
