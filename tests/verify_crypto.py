import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = b'\x01' * 32
aesgcm = AESGCM(key)
nonce = os.urandom(12)
data = b"hello world"
aad = b""

ct = aesgcm.encrypt(nonce, data, aad)
# ct includes tag at the end

print(f"Key: {key.hex()}")
print(f"Nonce: {nonce.hex()}")
print(f"CT+Tag: {ct.hex()}")
print(f"Tag: {ct[-16:].hex()}")
print(f"CT: {ct[:-16].hex()}")

# Decrypt
pt = aesgcm.decrypt(nonce, ct, aad)
print(f"Decrypted: {pt}")
