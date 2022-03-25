from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import argparse



#Estas funciones son inseguras
def simple_rsa_encrypt(m, publickey):


    ciphertext1 = publickey.encrypt(
    m,
    padding.OAEP(
        mgf = padding.MGF1(algorithm = hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None)) # se usa rara vez dejar None

    return ciphertext1




def simple_rsa_decrypt(c, privatekey):


    recovered1 = privatekey.decrypt(
    c,
    padding.OAEP(
        mgf = padding.MGF1(algorithm = hashes.SHA256()),
        algorithm = hashes.SHA256(),
    label = None))


    return recovered1




def publicBytesToKey(public_key_bytes):
    # Convertir la llave publica de bytes a objeto llave
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    return public_key

def privateBytesToKey(private_key_bytes):
    # Convertir la llave privada de bytes a objeto llave
    # Como no se cifraron los bytes no hace falta un password
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        backend=default_backend(),
        password=None
    )

    return private_key


if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--operacion", help="Aplicar operación, cifrar/descifrar", required=True)
    all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
    all_args.add_argument("-l", "--llave", help="Ruta de llave", required=True)
    args = vars(all_args.parse_args())
    operacion = args['operacion']
    entrada = args['input']
    salida = args['output']
    llave = args['llave']


    file = open(entrada, "rb")
    texto = file.read()
    file.close()

    file2 = open(llave, "rb")
    llave = file2.read()
    file2.close()


    if operacion == 'cifrar':
        llave = publicBytesToKey(llave)
        cifrado =   simple_rsa_encrypt(texto, llave)
        file3 = open(salida, "wb")
        file3.write(cifrado)
        file3.close()
    elif operacion == 'descifrar':
        llave = privateBytesToKey(llave)
        cifrado =   simple_rsa_decrypt(texto, llave)
        file3 = open(salida, "wb")
        file3.write(cifrado)
        file3.close()

    else: 
        print("Recuerda que las operaciones validas son cifrar/descifrar")
