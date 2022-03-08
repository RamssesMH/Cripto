#python3 ctr.py -p cifrar -i entrada.txt -o salida.txt -l '8VRIXx9HWXnbh0yoZECkDw==' -v 'rzzkk9W0NflHX97ZLNAV3A=='
#comando usado

import argparse
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def cifrar(path_entrada, path_salida, llave, iv):
    """
    Cifrado.

    Keyword Arguments:
    returns: bin
    """
    aesCipher = Cipher(algorithms.AES(llave),
                   modes.CTR(iv),
                   backend = default_backend)
    aesEncryptor = aesCipher.encryptor()
    salida = open(path_salida, 'wb')
    for buffer in open(path_entrada, 'rb'):
        cifrado = aesEncryptor.update(buffer)
        salida.write(cifrado) 


    
    aesEncryptor.finalize()
    salida.close()


def descifrar(path_entrada, path_salida, llave, iv):
    """
    Descifrar.

    Keyword Arguments:
    returns: bin
    """
    aesCipher = Cipher(algorithms.AES(llave),
                   modes.CTR(iv),
                   backend = default_backend)
    aesDecryptor = aesCipher.encryptor()
    salida = open(path_salida, 'wb')
    plano = b''
    for buffer in open(path_entrada, 'rb'):
        salida.write(plano)
        plano = aesDecryptor.update(buffer)
        


    
    aesDecryptor.finalize()
    salida.close()



if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
    all_args.add_argument("-l", "--llave", help="Llave", required=True)   
    all_args.add_argument("-v", "--iv", help="Iv", required=True)
    args = vars(all_args.parse_args())
    operacion = args['Operacion']

    # Preparar llave recibida en base64
    llave = base64.b64decode(args['llave'])
    iv = base64.b64decode(args['iv'])
    print (llave)
    print(iv)
    if len(llave) != 16:
        print('La llave de entrada debe ser de 16 bytes')
        print (len(llave))
        exit()
    if len(iv) != 16:
        print('El iv de entrada debe ser de 16 bytes')
        print (len(iv))
        exit()
    
    if operacion == 'cifrar':
        cifrar(args['input'], args['output'], llave, iv)
    elif operacion == 'descifrar':
        descifrar(args['input'], args['output'], llave, iv)
    else: 
        print("Recuerda que las operaciones validas son cifrar/descifrar")
