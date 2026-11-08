"""Shared helpers: networking (JSON), number theory, RSA, DH, encodings."""
import base64
import codecs
import json
import math
import random
import socket
import sys

import aes_ecb

P_MIN, P_MAX = 400, 500          # allowed range for the primes
AES_KEY_LEN = 32                 # AES-256 key size in bytes

# ------------------------------------------------------------------ logging
class _Tee:
    """Writes to several streams at once (console + log file)."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)

    def flush(self):
        for st in self.streams:
            st.flush()

    def isatty(self):
        return self.streams[0].isatty()


def setup_log(path):
    """Mirror everything printed to stdout into `path` (-l/--log)."""
    if not path:
        return
    f = open(path, "a", encoding="utf-8")
    sys.stdout = _Tee(sys.stdout, f)


# ------------------------------------------------------------------ JSON net
class MessageStream:
    """Sends/receives JSON objects over a TCP socket.

    No length prefix is used (the skeleton just sends JSON text), so the
    receiver extracts complete JSON objects from a buffer; this also copes
    with several messages arriving in one recv() or one split over several.
    """

    def __init__(self, sock, name="peer"):
        self.sock, self.name = sock, name
        self.buf = ""
        self.dec = codecs.getincrementaldecoder("utf-8")()
        self.json = json.JSONDecoder()

    def send(self, obj):
        self.sock.sendall(json.dumps(obj).encode())

    def recv(self):
        """Return (object, raw_text) of the next message."""
        while True:
            stripped = self.buf.lstrip()
            if stripped:
                try:
                    obj, end = self.json.raw_decode(stripped)
                    self.buf = stripped[end:]
                    return obj, stripped[:end]
                except json.JSONDecodeError:
                    pass                      # incomplete: read more
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError("connection closed by %s" % self.name)
            self.buf += self.dec.decode(data)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def open_stream(addr, port, listen, name="peer", timeout=None):
    """Listen for one connection (listen=True) or connect to addr:port.

    timeout: seconds to wait for each recv() (None/0 = wait forever).
    """
    if listen:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((addr, port))
        srv.listen(1)
        print("[*] listening on %s:%d ..." % (addr, port), flush=True)
        conn, peer = srv.accept()
        srv.close()
        print("[*] connection from %s:%d" % peer, flush=True)
        conn.settimeout(timeout or None)
        return MessageStream(conn, name)
    s = socket.create_connection((addr, port))
    s.settimeout(timeout or None)
    print("[*] connected to %s:%d" % (addr, port), flush=True)
    return MessageStream(s, name)


def send(stream, me, obj):
    print("[%s] send: %s" % (me, json.dumps(obj)), flush=True)
    stream.send(obj)


def recv(stream, me):
    obj, raw = stream.recv()
    print("[%s] recv: %s" % (me, raw), flush=True)
    return obj


class PeerError(Exception):
    """The peer sent {"opcode": 3, "error": ...}."""


def expect(msg, opcode, mtype=None):
    """Check a received message; raise PeerError for opcode 3."""
    if not isinstance(msg, dict) or "opcode" not in msg:
        raise ValueError("malformed message: %r" % (msg,))
    if msg["opcode"] == 3:
        raise PeerError(msg.get("error", "unknown error"))
    if msg["opcode"] != opcode or (mtype is not None and msg.get("type") != mtype):
        raise ValueError("unexpected message (wanted opcode=%s type=%s): %r" % (opcode, mtype, msg))
    return msg


# ------------------------------------------------------------- number theory
def is_prime_trial(n):
    """Primality test #1: trial division up to sqrt(n)."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def is_prime_miller_rabin(n, rounds=20):
    """Primality test #2: Miller-Rabin."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        x = pow(random.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


is_prime = is_prime_trial


def prime_factors(n):
    fs, d = set(), 2
    while d * d <= n:
        while n % d == 0:
            fs.add(d)
            n //= d
        d += 1
    if n > 1:
        fs.add(n)
    return fs


def is_generator(g, p):
    """g generates Z_p^* iff g^((p-1)/q) != 1 (mod p) for every prime q | p-1."""
    if not (1 < g < p):
        return False
    return all(pow(g, (p - 1) // q, p) != 1 for q in prime_factors(p - 1))


def random_prime(lo=P_MIN, hi=P_MAX, exclude=()):
    return random.choice([x for x in range(lo, hi + 1) if is_prime(x) and x not in exclude])


# ---------------------------------------------------------------------- RSA
def rsa_generate():
    """Return (p, q, n, e, d) with 400 <= p,q <= 500."""
    p = random_prime()
    q = random_prime(exclude=(p,))
    n, phi = p * q, (p - 1) * (q - 1)
    while True:
        e = random.randrange(3, phi)
        if math.gcd(e, phi) == 1:
            break
    return p, q, n, e, pow(e, -1, phi)


def rsa_verify(p, q, e, d):
    """Return a dict of check name -> bool for the keypair."""
    ok_range = P_MIN <= p <= P_MAX and P_MIN <= q <= P_MAX
    prime_p, prime_q = is_prime(p), is_prime(q)
    phi = (p - 1) * (q - 1)
    return {
        "p is prime": prime_p,
        "q is prime": prime_q,
        "p, q in [%d, %d]" % (P_MIN, P_MAX): ok_range,
        "p != q": p != q,
        "gcd(e, phi) == 1": math.gcd(e, phi) == 1,
        "e*d == 1 (mod phi)": (e * d) % phi == 1,
    }


def rsa_encrypt_bytes(data, e, n):
    """RSA is applied one byte (letter) at a time -> list of ints."""
    return [pow(b, e, n) for b in data]


def rsa_decrypt_bytes(cipher, d, n):
    return bytes(pow(c, d, n) for c in cipher)


# ----------------------------------------------------------------------- DH
def dh_generate_params():
    p = random_prime()
    gens = [g for g in range(2, p) if is_generator(g, p)]
    return p, random.choice(gens)


def dh_keypair(p, g):
    a = random.randrange(2, p - 1)
    return a, pow(g, a, p)


def dh_bad_prime():
    """A composite number in the allowed range (for Protocol IV-I)."""
    return random.choice([x for x in range(P_MIN, P_MAX + 1) if not is_prime(x) and x % 2])


def dh_bad_generator(p):
    """A non-generator of Z_p^* (for Protocol IV-II)."""
    return random.choice([g for g in range(2, p - 1) if not is_generator(g, p)])


def dh_aes_key(shared):
    """2-byte big-endian shared secret repeated to 32 bytes."""
    return shared.to_bytes(2, byteorder="big") * 16


def dh_param_error(p, g):
    """Protocol IV checks on received DH parameters -> error string or None."""
    if not isinstance(p, int) or not isinstance(g, int):
        return "incorrect prime number"
    if not (P_MIN <= p <= P_MAX and is_prime(p)):
        return "incorrect prime number"
    if not is_generator(g, p):
        return "incorrect generator"
    return None


def dh_public_ok(x, p):
    """A DH public key must be an element of Z_p^* (0 < x < p)."""
    return isinstance(x, int) and 0 < x < p


def discrete_log(g, h, p):
    """Smallest x with g^x == h (mod p). p <= 500, so brute force is instant."""
    cur = 1
    for x in range(p):
        if cur == h:
            return x
        cur = cur * g % p
    raise ValueError("no discrete log of %d base %d mod %d" % (h, g, p))


# ---------------------------------------------------------------- encodings
def encode_public(value, fmt):
    """fmt 'int' -> integer, 'base64' -> base64 of the big-endian bytes."""
    if fmt == "int":
        return value
    return base64.b64encode(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")).decode()


def decode_public(value):
    """Accept either an integer or a base64 string."""
    if isinstance(value, int):
        return value
    return int.from_bytes(base64.b64decode(value), "big")


def _decode_cipher_element(v):
    """One RSA ciphertext: int, decimal string or base64 big-endian string."""
    if isinstance(v, bool):
        raise ValueError("bad ciphertext element %r" % (v,))
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        if v.strip().lstrip("-").isdigit():
            return int(v)
        return int.from_bytes(base64.b64decode(v), "big")
    raise ValueError("bad ciphertext element %r" % (v,))


def decode_encrypted_key(value):
    """Return the RSA-encrypted AES key as a list of ints.

    The spec says `encrypted_key` is a JSON list of 32 integers, but the slides
    also draw it as a base64 string under `encryption`, so accept all of:
      * list of ints                              [189924, 237239, ...]
      * list of decimal / base64 strings          ["189924", ...] / ["Ag4=", ...]
      * base64 string containing a JSON list      "WzE4OTkyNCwgMj..."
      * base64 string of 32 fixed-width big-endian integers
    """
    if isinstance(value, list):
        return [_decode_cipher_element(v) for v in value]
    if isinstance(value, str):
        raw = base64.b64decode(value)
        try:
            parsed = json.loads(raw.decode())
            if isinstance(parsed, list):
                return decode_encrypted_key(parsed)
        except (ValueError, UnicodeDecodeError):
            pass
        if not raw or len(raw) % AES_KEY_LEN:
            raise ValueError("cannot split %d bytes into %d ciphertexts" % (len(raw), AES_KEY_LEN))
        width = len(raw) // AES_KEY_LEN
        return [int.from_bytes(raw[i:i + width], "big") for i in range(0, len(raw), width)]
    raise ValueError("encrypted key must be a list or a base64 string")


def get_encrypted_key(msg):
    """Pull the RSA-encrypted key out of an opcode-2/RSA message (any field name)."""
    for field in ("encrypted_key", "encryption", "key"):
        if field in msg:
            return decode_encrypted_key(msg[field])
    raise KeyError("encrypted_key")


def aes_encrypt_b64(key, text):
    return base64.b64encode(aes_ecb.encrypt(key, text.encode())).decode()


def aes_decrypt_b64(key, b64):
    return aes_ecb.decrypt(key, base64.b64decode(b64)).decode()


def get_message(arg, default, who):
    """--message value, else ask on a terminal, else the default."""
    if arg is not None:
        return arg
    if sys.stdin.isatty():
        return input("[%s] input message: " % who) or default
    return default
