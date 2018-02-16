from Crypto.Hash import SHA256
from ecdsa import SigningKey, NIST256p, VerifyingKey

# Take in bytes, output SHA256(bytes)
def hash_sha_256(b):
    h = SHA256.new()
    h.update(b)
    return h.digest()

def gen_privkey():
    sk = SigningKey.generate(curve=NIST256p)
    return sk

def gen_pubkey_from_bytes(b):
    vk = VerifyingKey.from_string(b, curve=NIST256p)
    return vk

def gen_pubkey(privkey):
    return privkey.get_verifying_key()

def sign(privkey, message):
    return privkey.sign(message)

def verify(pubkey, h, sig):
    return pubkey.verify(sig, h)
