from Crypto.Hash import SHA256

# Take in bytes, output SHA256(bytes)
def hash(bytes):
    h = SHA256.new()
    h.update(bytes)
    return h.digest()
