

from junosencoder import JunosEncoder

# Known plaintext
e1 = JunosEncoder("DetteGårIkkeLenger")
print("Secret:", e1.secret)
print("Plaintext:", e1.plaintext)
assert e1.secret.startswith("$9$")


# We are able to hash the string
print("SHA256 of known plaintext:", e1.sha256)
assert e1.sha256.startswith("$5$")

print("SHA512 of knonw plaintext:", e1.sha512)
assert e1.sha512.startswith("$6$")

# Known cryptotext
e2 = JunosEncoder("$9$JuZUiPfz/A0z3A0IErl8X-bgJ.m5FnCUjmTQnAt1RhyK8Vb2ZGiwY")
print("Known secret:", e2.secret)
print("Decoded secret:", e2.plaintext)
assert(e2.plaintext == e1.plaintext)

print("SHA256 of known cryptotext:", e2.sha256)
assert e2.sha256.startswith("$5$")
assert e2.sha256 != e1.sha256

print("SHA512 of known cryptotext:", e2.sha512)
assert e2.sha512.startswith("$6$")
assert e2.sha512 != e1.sha512


# Ensure that we can decrypt previously encrypted text
e3 = JunosEncoder(e1.secret)
assert(e3.secret == e1.secret)
print("Redecoded secret text:", e3.plaintext)
assert(e3.plaintext == e1.plaintext)

# Ensure that we can encrypt decrypted text again
e4 = JunosEncoder(e2.plaintext)
assert(e4.plaintext == e1.plaintext)

# And that the cryptotects different
print("Reencoded decoded text:", e4.secret)
assert(e4.secret != e1.secret)
