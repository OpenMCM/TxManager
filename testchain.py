from txhashchain import *
from transaction import *
from cryptohelpers import *

txHC = TXHashChain()

alice_sk = gen_privkey()
alice_vk = gen_pubkey(alice_sk)
alice_ad = hash(alice_vk.to_string())
alice_adp = hash(bytearray(alice_vk.to_string()))

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
