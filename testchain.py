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

charlie_sk = gen_privkey()
charlie_vk = gen_pubkey(charlie_sk)
charlie_ad = hash_sha_256(charlie_vk.to_string())
charlie_adp = hash_sha_256(bytearray(charlie_vk.to_string()))

mallory_sk = gen_privkey()
mallory_vk = gen_pubkey(mallory_sk)
mallory_ad = hash_sha_256(mallory_vk.to_string())
mallory_adp = hash_sha_256(bytearray(mallory_vk.to_string()))

alice_coin_color = bytearray(b"\xde\xad\xbe\xef" * 8)
alice_coin_prime_color = bytearray(b"\x00\xc0\xff\xee" * 8)

print("Alice's pubkey: ", alice_vk.to_string())
print("Alice's addr: ", alice_ad)

print("Bob's pubkey: ", bob_vk.to_string())
print("Bob's address: ", bob_ad)

print("Charlie's pubkey: ", charlie_vk.to_string())
print("Charlie's address: ", charlie_ad)

print("Mallory's pubkey: ", mallory_vk.to_string())
print("Mallory's address: ", mallory_ad)

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
tx_auth_bob_forreal_hash = hash_sha_256(tx_auth_bob_forreal.tx_to_bytes())

if(txHC.insert_tx(tx_auth_bob_forreal)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob mints 1 AC, sends to self
mint_outputs_datum = Datum([bytearray(bob_ad), alice_coin_color, bytearray(b"\x00\x01\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_mnt_hash_sha_256 = Datum([hash_sha_256(bytes(mint_outputs_section.sx_to_bytes()))])


sig = sign(alice_sk, hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())))

sig_mnt_datum = Datum([bob_vk.to_string(), bytes(sign(bob_sk, hash_sha_256(mint_outputs_section.sx_to_bytes()))), hash_sha_256(tx_auth_bob_forreal.tx_to_bytes())])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([mint_outputs_section, sig_mnt_section])
tx_mnt_two_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())
tx_bob_gets_back_hash = tx_mnt_two_hash

if(txHC.insert_tx(tx_mnt_two)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")


# Bob deauthorizes himself to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

deauthed_datum = Datum([bytearray(bob_ad)])

bob_addr_hash = hash_sha_256(bytes(bob_ad + b"\n"))
bob_deauth_bob_sig = sign(bob_sk, bob_addr_hash)
bob_deauth_bob_sig_datum = Datum([bob_vk.to_string(), bob_deauth_bob_sig, tx_auth_bob_forreal_hash])

deauthed_section = Section(sectionType.DEAUTHED_MINTERS, [deauthed_datum, bob_deauth_bob_sig_datum])

tx_bob_deauth_bob = Transaction([color_section, deauthed_section])

if(txHC.insert_tx(tx_bob_deauth_bob)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Bob mints 2 AC, sends to self
mint_outputs_datum = Datum([bytearray(bob_ad), alice_coin_color, bytearray(b"\x00\x02\x00\x00")])
mint_outputs_section = Section(sectionType.MINT_OUTPUTS, [mint_outputs_datum])

sig_mnt_hash_sha_256 = Datum([hash_sha_256(bytes(mint_outputs_section.sx_to_bytes()))])


sig = sign(alice_sk, hash_sha_256(bytes(mint_outputs_section.sx_to_bytes())))

sig_mnt_datum = Datum([bob_vk.to_string(), bytes(sign(bob_sk, hash_sha_256(mint_outputs_section.sx_to_bytes()))), hash_sha_256(tx_auth_bob_forreal.tx_to_bytes())])

sig_mnt_section = Section(sectionType.SIG_MINT, [sig_mnt_hash_sha_256, sig_mnt_datum])

tx_mnt_two = Transaction([mint_outputs_section, sig_mnt_section])
tx_mnt_two_hash = hash_sha_256(tx_mnt_two.tx_to_bytes())

if(txHC.insert_tx(tx_mnt_two)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")


# Alice authorizes Charlie to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

authed_datum = Datum([bytearray(charlie_ad)])

charlie_addr_hash = hash_sha_256(bytes(charlie_ad + b"\n"))
alice_auth_charlie_sig = sign(alice_sk, charlie_addr_hash)
alice_auth_charlie_sig_datum = Datum([alice_vk.to_string(), alice_auth_charlie_sig, tx_auth_alice_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum, alice_auth_charlie_sig_datum])

tx_auth_charlie_forreal = Transaction([color_section, authed_section])
tx_auth_charlie_forreal_hash = hash_sha_256(tx_auth_charlie_forreal.tx_to_bytes())

if(txHC.insert_tx(tx_auth_charlie_forreal)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Charlie deauthorizes Alice to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

deauthed_datum = Datum([bytearray(alice_ad)])

alice_addr_hash = hash_sha_256(bytes(alice_ad + b"\n"))
charlie_deauth_alice_sig = sign(charlie_sk, alice_addr_hash)
charlie_deauth_alice_sig_datum = Datum([charlie_vk.to_string(), charlie_deauth_alice_sig, tx_auth_charlie_forreal_hash])

deauthed_section = Section(sectionType.DEAUTHED_MINTERS, [deauthed_datum, charlie_deauth_alice_sig_datum])

tx_charlie_deauth_alice = Transaction([color_section, deauthed_section])

if(txHC.insert_tx(tx_charlie_deauth_alice)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Charlie authorizes Mallory to mint AliceCoin
color_datum = Datum([bytearray(b"\xde\xad\xbe\xef" * 8)])
color_section = Section(sectionType.COINCOLOR, [color_datum])

deauthed_datum = Datum([bytearray(mallory_ad)])

mallory_addr_hash = hash_sha_256(bytes(mallory_ad + b"\n"))
charlie_auth_mallory_sig = sign(charlie_sk, mallory_addr_hash)
charlie_auth_mallory_sig_datum = Datum([charlie_vk.to_string(), charlie_auth_mallory_sig, tx_auth_charlie_forreal_hash])

authed_section = Section(sectionType.AUTHED_MINTERS, [deauthed_datum, charlie_auth_mallory_sig_datum])

tx_charlie_auth_mallory = Transaction([color_section, authed_section])

if(txHC.insert_tx(tx_charlie_auth_mallory)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Alice authorizes herself to mint AliceCoinPrime
color_datum = Datum([alice_coin_prime_color])
color_section = Section(sectionType.COINCOLOR, [color_datum])
authed_datum = Datum([bytearray(alice_ad)])
authed_section = Section(sectionType.AUTHED_MINTERS, [authed_datum])
tx_auth_alice = Transaction([color_section, authed_section])
tx_auth_alice_hash = hash_sha_256(tx_auth_alice.tx_to_bytes())


if(txHC.insert_tx(tx_auth_alice)):
    print("Success -- transaction accepted")
else:
    print("Failure -- transaction rejected")

# Mallory tries to steal Bob's AliceCoin
inputs_datum = Datum([tx_bob_gets_back_hash, bytes([sectionType.MINT_OUTPUTS.value]), bytearray(b"\x00\x00\x00\x00")])
inputs_section = Section(sectionType.INPUTS, [inputs_datum])

outputs_datum = Datum([mallory_ad, alice_coin_color, b"\x00\x01\x00\x00"])
outputs_section = Section(sectionType.OUTPUTS, [outputs_datum])

in_out_bytes = inputs_section.sx_to_bytes() + outputs_section.sx_to_bytes()
sx_hash = hash_sha_256(bytes(in_out_bytes))

sec_hash_datum = Datum([sx_hash])
sig_datum = Datum([mallory_vk.to_string(), sign(mallory_sk, sx_hash)])
sig_section = Section(sectionType.SIGNATURES, [sec_hash_datum, sig_datum])

tx = Transaction([inputs_section, outputs_section, sig_section])

if(txHC.insert_tx(tx)):
    print("Failure -- transaction accepted")
else:
    print("Success -- transaction rejected")
