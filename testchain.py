from txhashchain import *
from transaction import *
from cryptohelpers import *

txHC = TXHashChain()

alice_sk = gen_privkey()
alice_vk = gen_pubkey(alice_sk)
alice_ad = hash_sha_256(alice_vk.to_string())
alice_adp = hash_sha_256(bytearray(alice_vk.to_string()))

print("Alice's addr: ", alice_ad)
print("Alice's addrp: ", alice_adp, "\n")


print("Just making sure we can convert pubkeys to and from bytes")
print("Alice's pubkey: ", alice_vk.to_string())
print("Alice's telephone-d pubkey: ", gen_pubkey_from_bytes(bytearray(alice_vk.to_string())).to_string())

# Alice authorizes herself to mint AliceCoin
# This transaction takes the form:
#   coincolor: [
#       deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
#   ]
#   authed_minters: [
#       <alice_ad>
#   ]
#   Note that authed_minters doesn't have a signature! The txHC should ignore
#   this because the color deadbeef x 8 has never been authorized before.
print()
print("Constructing color section...")
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

print("Constructing authed_minters section...")
authed_datum = Datum([bytearray(alice_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])

print("Constructing transaction...")
tx_auth_alice = Transaction([color_section, authed_section])
print("Final transaction bytes: \n", tx_auth_alice.tx_to_bytes(), "\n\n")

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_auth_alice)):
    print("Successfully inserted transaction!")
else:
    print("Transaction insertion failed!")

# Alice mints 2 AC, sends to herself
mint_outputs_datum = Datum([bytearray(alice_ad), bytearray(b"\xde\xad\xbe\xef" * 8), bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])
print("Mint outputs hash: ", hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())))

sig_mnt_hash_sha_256 = Datum([hash_sha_256(bytes(mint_outputs_section.sx_to_bytes()))])


sig = sign(alice_sk, hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())))

print("Test verifying: ", verify(alice_vk, hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())), sig))

print("Signing: ", sig)

sig_mnt_datum = Datum([alice_vk.to_string(), bytes(sign(alice_sk, hash_sha_256(mint_outputs_section.sx_to_bytes()))), hash_sha_256(tx_auth_alice.tx_to_bytes())])
#sig_mnt_datum = Datum([bytearray(sig)])

print("Datum: ", sig_mnt_datum.dx_to_bytes())
sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

print("Section bytes:\n", sig_mnt_section.sx_to_bytes(), "\n\n")
tx_mnt_two = Transaction([mint_outputs_section, sig_mnt_section])
print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_mnt_two)):
    print("Successfully inserted transaction!")
else:
    print("Transaction insertion failed!")
