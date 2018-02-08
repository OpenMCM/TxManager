from txhashchain import *
from transaction import *
from cryptohelpers import *

txHC = TXHashChain()

alice_sk = gen_privkey()
alice_vk = gen_pubkey(alice_sk)
alice_ad = hash_sha_256(alice_vk.to_string())
alice_adp = hash_sha_256(bytearray(alice_vk.to_string()))

bob_sk = gen_privkey()
bob_vk = gen_pubkey(bob_sk)
bob_ad = hash_sha_256(bob_vk.to_string())
bob_adp = hash_sha_256(bytearray(bob_vk.to_string()))

alice_coin_color = bytearray(b"\xde\xad\xbe\xef" * 8)

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
tx_auth_alice_hash = hash_sha_256(tx_auth_alice.tx_to_bytes())
print("Final transaction bytes: \n", tx_auth_alice.tx_to_bytes(), "\n\n")

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_auth_alice)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice mints 2 AC, sends to herself
mint_outputs_datum = Datum([bytearray(alice_ad), alice_coin_color, bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_mnt_hash_sha_256 = Datum([hash_sha_256(bytes(mint_outputs_section.sx_to_bytes()))])


sig = sign(alice_sk, hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())))

sig_mnt_datum = Datum([alice_vk.to_string(), bytes(sign(alice_sk, hash_sha_256(mint_outputs_section.sx_to_bytes()))), hash_sha_256(tx_auth_alice.tx_to_bytes())])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([mint_outputs_section, sig_mnt_section])
tx_mnt_two_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())
print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_mnt_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice sends 1 AC to Bob, 1 AC to herself
inputs_datum = Datum([tx_mnt_two_hash, bytes([sectionType.MINT_OUTPUTS.value]), b'\x00\x00\x00\x00'])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum_alice = Datum([alice_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_datum_bob = Datum([bob_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum_alice, outputs_datum_bob])

section_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()

tx_transfer_hash = hash_sha_256(bytes(section_bytes))

sig_transfer = sign(alice_sk, tx_transfer_hash)
sig_transfer_datum = Datum([alice_vk.to_string(), bytes(sig_transfer)])
sig_hash_datum = Datum([tx_transfer_hash])
sig_transfer_section = Section(sectionType.SIGNATURES, [sig_hash_datum, sig_transfer_datum])

tx_transfer = Transaction([inputs_section, outputs_section, sig_transfer_section])
tx_transfer_hash = hash_sha_256(bytes(tx_transfer.tx_to_bytes()))

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_transfer)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob sends his AC to Alice
inputs_transfer_two = Datum([tx_transfer_hash, bytes([sectionType.OUTPUTS.value]), bytearray(b"\x00\x00\x00\x01")])
inputs_section_two = Section(sectionType.INPUTS, [inputs_transfer_two])

outputs_transfer_two = Datum([alice_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section_two = Section(sectionType.OUTPUTS, [outputs_transfer_two])

section_bytes_two = inputs_section_two.sx_to_bytes() + outputs_section_two.sx_to_bytes()
tx_transfer_two_hash = hash_sha_256(section_bytes_two)

sig_transfer_two = sign(bob_sk, tx_transfer_two_hash)
sig_transfer_two_datum = Datum([bob_vk.to_string(), bytes(sig_transfer_two)])
sig_hash_two_datum = Datum([tx_transfer_two_hash])
sig_transfer_two_section = Section(sectionType.SIGNATURES, [sig_hash_two_datum, sig_transfer_two_datum])

tx_transfer_two = Transaction([inputs_section_two, outputs_section_two, sig_transfer_two_section])
tx_transfer_two_hash = hash_sha_256(bytes(tx_transfer_two.tx_to_bytes()))

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_transfer_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob, quoting the original transaction, tries to send his old AC back to himself
inputs_transfer_two = Datum([tx_transfer_hash, bytes([sectionType.OUTPUTS.value]), bytearray(b"\x00\x00\x00\x01")])
inputs_section_two = Section(sectionType.INPUTS, [inputs_transfer_two])

outputs_transfer_two = Datum([bob_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section_two = Section(sectionType.OUTPUTS, [outputs_transfer_two])

section_bytes_two = inputs_section_two.sx_to_bytes() + outputs_section_two.sx_to_bytes()
tx_transfer_two_hash = hash_sha_256(section_bytes_two)

sig_transfer_two = sign(bob_sk, tx_transfer_two_hash)
sig_transfer_two_datum = Datum([bob_vk.to_string(), bytes(sig_transfer_two)])
sig_hash_two_datum = Datum([tx_transfer_two_hash])
sig_transfer_two_section = Section(sectionType.SIGNATURES, [sig_hash_two_datum, sig_transfer_two_datum])

tx_transfer_two = Transaction([inputs_section_two, outputs_section_two, sig_transfer_two_section])
tx_transfer_two_hash = hash_sha_256(bytes(tx_transfer_two.tx_to_bytes()))

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_transfer_two)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Bob, quoting the original transaction, tries to send one of Alice's coins to himself
inputs_transfer_three = Datum([tx_transfer_hash, bytes([sectionType.OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section_three = Section(sectionType.INPUTS, [inputs_transfer_three])

outputs_transfer_three = Datum([bob_ad, alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
outputs_section_three = Section(sectionType.OUTPUTS, [outputs_transfer_three])

section_bytes_three = inputs_section_three.sx_to_bytes() + outputs_section_three.sx_to_bytes()
tx_transfer_three_hash = hash_sha_256(section_bytes_three)

sig_transfer_three = sign(bob_sk, tx_transfer_three_hash)
sig_transfer_three_datum = Datum([bob_vk.to_string(), bytes(sig_transfer_three)])
sig_hash_three_datum = Datum([tx_transfer_three_hash])
sig_transfer_three_section = Section(sectionType.SIGNATURES, [sig_hash_three_datum, sig_transfer_three_datum])

tx_transfer_three = Transaction([inputs_section_three, outputs_section_three, sig_transfer_three_section])
tx_transfer_three_hash = hash_sha_256(bytes(tx_transfer_three.tx_to_bytes()))

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_transfer_three)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Bob authorizes himself to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

authed_datum = Datum([bytearray(bob_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])

tx_auth_bob = Transaction([color_section, authed_section])

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_auth_bob)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")

# Alice authorizes Bob to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

authed_datum = Datum([bytearray(bob_ad)])

bob_addr_hash = hash_sha_256(bytes(bob_ad + b"\n"))
alice_auth_bob_sig = sign(alice_sk, bob_addr_hash)
alice_auth_bob_sig_datum = Datum([alice_vk.to_string(), alice_auth_bob_sig, tx_auth_alice_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum, alice_auth_bob_sig_datum])

tx_auth_bob_forreal = Transaction([color_section, authed_section])

print("Inserting transaction into hash chain...")
if(txHC.insert_tx(tx_auth_bob_forreal)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")
