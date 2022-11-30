from aes import Encrypt, Decrypt

# arquivo = open('Readme.txt', "r", encoding="utf-8")

# plaintext = arquivo.read()

# arquivo.close()

plaintext = "Texto a ser Criptografado"

key = "0123456789abcdef0123456789abcdef"

method = "cbc"

initVector = "fe5567e8d769550852182cdf69d74bb1"

seeProcess = False

cypherTxt = Encrypt(plaintext, key, method, seeProcess, initVector)

decryptCypherTxt = Decrypt(cypherTxt, key, method, seeProcess, initVector)

print(cypherTxt)
print()
print(decryptCypherTxt)