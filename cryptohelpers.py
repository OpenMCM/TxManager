from Crypto.Hash import SHA256
from ecdsa import SigningKey, NIST256p

# Take in bytes, output SHA256(bytes)
def hash(bytes):
    h = SHA256.new()
    h.update(bytes)
    return h.digest()

def gen_privkey():
    sk = SigningKey.generate(curve=NIST256p)
    return sk

def gen_pubkey(privkey):
    return privkey.get_verifying_key()

def sign(privkey, message):
    return privkey.sign(message)
