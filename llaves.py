from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sys
import argparse


def llavePrivada():
    # Generar llave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    return private_key

def llavePrivadaBytes(private_key):
    # Convertir llave privada a bytes, sin cifrar los bytes
    # Obviamente a partir de los bytes se puede guardar en un archivo binario
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return private_key_bytes

def publicKeyBytes(public_key):
    # Convertir la llave publica en bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_bytes

def savePEM(path_private_key, path_public_key, private_key, public_key):
    ruta1 = path_private_key + "private.pem"
    priv = open(ruta1, "wb")
    priv.write(private_key)
    priv.close()

    ruta2 = path_public_key + "public.pem"
    pub = open(ruta2, "wb")
    pub.write(public_key)
    pub.close()



if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--privada", help="ruta de llave privada", required=True)
    all_args.add_argument("-o", "--publica", help="Ruta de llave publica", required=True)
    args = vars(all_args.parse_args())
    publica = args['publica']
    privada = args['privada']


    private_key = llavePrivada()

    # Extraer llave publica de llave privada
    public_key = private_key.public_key()

    private_key_bytes = llavePrivadaBytes(private_key)
    public_key_bytes = publicKeyBytes(public_key)


    savePEM(publica, privada, private_key_bytes, public_key_bytes)
