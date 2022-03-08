import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

key = base64.b64encode(b'2'*16)
iv = base64.b64encode(os.urandom(12))
print (iv)
print (key)
aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend)
aesEncryptor = aesCipher.encryptor()

datos = b'Carlos Ramsses ransojdfoajfioheiphfiophbioaehbfiogbioudfasd Martinez'
padder = padding.PKCS7(128).padder()
c = padder.update(datos)
print(c)
c += padder.finalize()
print(c)
cifrado = aesEncryptor.update(c)
aesEncryptor.finalize()
print(cifrado)

aesDecryptor = aesCipher.decryptor()
unpadder = padding.PKCS7(128).unpadder()
plano = aesDecryptor.update(cifrado)
print(plano)
aesDecryptor.finalize()
datos = unpadder.update(plano)
datos += unpadder.finalize()
print(datos)