from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generar llave privada
def generar_privada():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Extraer llave publica de llave privada
def generar_publica(llave):
    return llave.public_key()

# Convertir llave privada a bytes, sin cifrar los bytes
# Obviamente a partir de los bytes se puede guardar en un archivo binario
def convertir_llave_privada_bytes(llave):
    private_key_bytes = llave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    return private_key_bytes

# Convertir la llave publica en bytes
def convertir_llave_publica_bytes(llave):
    public_key_bytes = llave.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key_bytes

# Convertir la llave privada de bytes a objeto llave
# Como no se cifraron los bytes no hace falta un password
def convertir_bytes_llave_privada(binario):
    private_key = serialization.load_pem_private_key(
        binario,
        backend=default_backend(),
        password=None)
    return private_key

# Convertir la llave publica de bytes a objeto llave
def convertir_bytes_llave_publica(binario):
    public_key = serialization.load_pem_public_key(
        binario,
        backend=default_backend())
    return public_key


def guardar_binario(ruta, binario):
    with open(ruta, 'bw') as archivo:
        archivo.write(binario)

        
def recuperar_publica_from_path(path):
    with open(path, 'rb') as archivo:
        binario = archivo.read()
    return convertir_bytes_llave_publica(binario)


def recuperar_privada_from_path(path):
    with open(path, 'rb') as archivo:
        binario = archivo.read()
    return convertir_bytes_llave_privada(binario)



if __name__ == '__main__':
    llave_privada = generar_privada()
    llave_publica = generar_publica(llave_privada)
    privada_binario = convertir_llave_privada_bytes(llave_privada)
    publico_binario = convertir_llave_publica_bytes(llave_publica)
    guardar_binario('privada.pem', privada_binario)
    guardar_binario('publica.pem', publico_binario)
