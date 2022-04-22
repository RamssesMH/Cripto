"""
cliente.

Emisor del protocolo agree upon transmission para el intercambio de un mensaje protegido
"""

import sys 
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

import llaves 

MENSAJE = b'HOLA mundo, mensaje protegido'
DELIMITADOR = b'\r\n'


def conectar_servidor(host, puerto):
    # socket para IP v4
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()


def generar_llaves():
    aes = os.urandom(16)
    iv = os.urandom(16)
    mac = os.urandom(128)
    return aes, iv, mac


def cifrar_llaves(aes, iv, mac, llave_publica_receptor):
    ciphertext1 = llave_publica_receptor.encrypt(
      aes + iv + mac,
      padding.OAEP(
          mgf = padding.MGF1(algorithm = hashes.SHA256()),
          algorithm = hashes.SHA256(),
          label = None))
    return ciphertext1


def firmar_llaves(aes, iv, mac, llave_privada):
    mensaje = aes + iv + mac
    signature = llave_privada.sign(mensaje,
                                   padding.PSS(
                                       mgf=padding.MGF1(hashes.SHA256()),
                                       salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())
    return signature


def cifrar_mensaje(aes, iv, mensaje):
    aesCipher = Cipher(algorithms.AES(aes),
                     modes.CTR(iv),
                     backend = default_backend)
    aesEncryptor = aesCipher.encryptor()
    cifrado = aesEncryptor.update(mensaje)
    aesEncryptor.finalize()
    return cifrado


def calcular_hmac(binario, mac):
    codigo = hmac.HMAC(mac, hashes.SHA256(), backend = default_backend())
    codigo.update(binario)
    return codigo.finalize()


def proteger_mensaje(llave_privada_propia, llave_publica_receptor, mensaje=MENSAJE):
    aes, iv, mac = generar_llaves()
    llaves_cifradas = cifrar_llaves(aes, iv, mac, llave_publica_receptor) # paso 1
    firma = firmar_llaves(aes, iv, mac, llave_privada_propia) # paso 2
    mensaje_cifrado = cifrar_mensaje(aes, iv, mensaje) # paso 3
    codigo_mac = calcular_hmac(llaves_cifradas + firma + mensaje_cifrado, mac) # paso 4
    # print (len(firma))
    print( 'codigo mac-------------------------------------------------------------------------')
    print (codigo_mac)
    print( 'codigo mac-------------------------------------------------------------------------')
    return llaves_cifradas + firma +mensaje_cifrado +codigo_mac


def enviar_mensaje(socket, llave_privada_propia, llave_publica_receptor, mensaje=MENSAJE):
    protegido = proteger_mensaje(llave_privada_propia, llave_publica_receptor, mensaje)
    # print(protegido)
    socket.send(protegido+DELIMITADOR)
    socket.close()
    
    

if __name__ == '__main__':
    socket = conectar_servidor(sys.argv[1], int(sys.argv[2]))
    
    llave_publica_path = sys.argv[3] # ruta de archivo en formato PEM
    llave_publica_receptor = llaves.recuperar_publica_from_path(llave_publica_path)
    llave_privada_propia_path = sys.argv[4]
    llave_privada_propia = llaves.recuperar_privada_from_path(llave_privada_propia_path)
    enviar_mensaje(socket, llave_privada_propia, llave_publica_receptor)
    print('Mensaje enviado')
