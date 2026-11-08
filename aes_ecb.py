"""AES-256-ECB helper.

Uses PyCrypto/PyCryptodome (``Crypto``) if installed, then ``cryptography``,
and finally falls back to a small pure-Python AES so the project always runs.
Padding: PKCS#7.
"""

BLOCK = 16


def pad(data: bytes) -> bytes:
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK:
        raise ValueError("bad ciphertext length")
    n = data[-1]
    if 1 <= n <= BLOCK and data.endswith(bytes([n]) * n):
        return data[:-n]
    raise ValueError("bad padding (wrong key?)")


# ---------------------------------------------------------------- pure python
def _build_sbox():
    sbox = [0] * 256
    p = q = 1
    rotl = lambda x, s: ((x << s) | (x >> (8 - s))) & 0xFF
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV[_v] = _i


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return r & 0xFF


def _expand_key(key: bytes):
    nk, nr = len(key) // 4, len(key) // 4 + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    flat = bytes(b for word in w for b in word)
    return [list(flat[16 * r:16 * r + 16]) for r in range(nr + 1)], nr


def _shift(s, inv):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            if inv:
                out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
            else:
                out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _mix(s, coef):
    out = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out[4 * c + r] = (_gmul(col[0], coef[(0 - r) % 4]) ^ _gmul(col[1], coef[(1 - r) % 4]) ^
                              _gmul(col[2], coef[(2 - r) % 4]) ^ _gmul(col[3], coef[(3 - r) % 4]))
    return out


_MIX, _IMIX = (2, 3, 1, 1), (14, 11, 13, 9)


def _enc_block(block, rks, nr):
    s = [a ^ b for a, b in zip(block, rks[0])]
    for r in range(1, nr + 1):
        s = _shift([_SBOX[b] for b in s], False)
        if r != nr:
            s = _mix(s, _MIX)
        s = [a ^ b for a, b in zip(s, rks[r])]
    return bytes(s)


def _dec_block(block, rks, nr):
    s = [a ^ b for a, b in zip(block, rks[nr])]
    for r in range(nr - 1, -1, -1):
        s = [_INV[b] for b in _shift(s, True)]
        s = [a ^ b for a, b in zip(s, rks[r])]
        if r != 0:
            s = _mix(s, _IMIX)
    return bytes(s)


def _py_ecb(key, data, encrypt):
    rks, nr = _expand_key(key)
    f = _enc_block if encrypt else _dec_block
    return b"".join(f(list(data[i:i + 16]), rks, nr) for i in range(0, len(data), 16))


# ------------------------------------------------------------------ backends
def _raw_ecb(key: bytes, data: bytes, encrypt: bool) -> bytes:
    try:
        from Crypto.Cipher import AES  # pycrypto / pycryptodome
        c = AES.new(key, AES.MODE_ECB)
        return c.encrypt(data) if encrypt else c.decrypt(data)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.ECB())
        x = c.encryptor() if encrypt else c.decryptor()
        return x.update(data) + x.finalize()
    except ImportError:
        return _py_ecb(key, data, encrypt)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 needs a 32-byte key")
    return _raw_ecb(key, pad(plaintext), True)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 needs a 32-byte key")
    return unpad(_raw_ecb(key, ciphertext, False))
