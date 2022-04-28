import os
import hashlib

# First we need secure source of randomness
# valid entropy bit sizes [128, 160, 192, 224, 256]
entropyBitSize = 128
# secure source of randomness
entropyBytes = os.urandom(entropyBitSize // 8) # Byte has 8 bits
print("Entropy:", entropyBytes.hex())

# we convert our entropy bytes to bit array so its easier to work with
from bitarray import bitarray
entropyBits = bitarray()
entropyBits.frombytes(entropyBytes)
print("Entropy bits:", entropyBits)

# we need to add checksum bits at the of our are entropy
checksumLen = entropyBitSize // 32 # checksum length depends on the length of entropy
print("checksum size:", checksumLen)

# We need to take a hash of our entropy
hashBytes = hashlib.sha256(entropyBytes).digest()
print("hashed bytes:", hashBytes.hex())

hashBits = bitarray()
hashBits.frombytes(hashBytes)
checksum = hashBits[:checksumLen]
print("checksum bits:", checksum)

# Add checksum bits at the end of entropy
entropyBits.extend(checksum)
print("entropy length:", len(entropyBits))

# Get indexed from bits
indexes = list()
from bitarray.util import ba2int

for idx in range(len(entropyBits) // 11):
    startIdx = idx * 11
    endIdx = startIdx + 11
    wordIndex = ba2int(entropyBits[startIdx:endIdx])
    indexes.append(wordIndex)

print(indexes)

# Load bip 39 words
fileObj = open("bip-0039/english.txt", "r")
words = fileObj.read().splitlines()
fileObj.close()
print("words len:", len(words))

# Map indexes onto words
mnemonic = list(map(lambda idx: words[idx] , indexes))
print("mnemonic:", mnemonic)

# Generate salt
password = ""
salt = "mnemonic" + password

# Finally, we derive seed
mnemonicStr = ' '.join(mnemonic)
seed = hashlib.pbkdf2_hmac(
    "sha512",
    mnemonicStr.encode("utf-8"),
    salt.encode("utf-8"),
    2048
)

print("seed len:", len(seed))
print("seed hex:", seed.hex())
print("priv key:", seed[0:32].hex())
print("chain co:", seed[32:64].hex())
