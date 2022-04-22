"""
Servidor.

Servidor de un chat. Es una implementación incompleta:
- Falta manejo de exclusión mutua
- Falta poder desconectar de forma limpia clientes
- Falta poder identificar clientes
"""



import threading
import sys 
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

import mensajes
import llaves

def descifrar_llaves(text, llave_publica_receptor):
    deciphertext1 = llave_publica_receptor.decrypt(text,
      padding.OAEP(
          mgf = padding.MGF1(algorithm = hashes.SHA256()),
          algorithm = hashes.SHA256(),
          label = None))
    return deciphertext1


def descifrar_mensaje(aes, iv, mensaje):
    aesCipher = Cipher(algorithms.AES(aes),
                     modes.CTR(iv),
                     backend = default_backend)
    aesDecryptor = aesCipher.decryptor()
    texto = aesDecryptor.update(mensaje)
    aesDecryptor.finalize()
    return texto

def calcular_hmac(binario, mac):
    codigo = hmac.HMAC(mac, hashes.SHA256(), backend = default_backend())
    codigo.update(binario)
    return codigo.finalize()

def firmar_llaves(aes, iv, mac, llave_privada):
    mensaje = aes + iv + mac
    signature = llave_privada.sign(mensaje,
                                   padding.PSS(
                                       mgf=padding.MGF1(hashes.SHA256()),
                                       salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())
    return signature


def crear_socket_servidor(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('', int(puerto)))  # hace el bind en cualquier interfaz disponible
    return servidor


def broadcast(mensaje, clientes, llave_publica_receptor, llave_privada_propia):
    print( 'Mensaje cifrado: ', mensaje )

    llaves_cifradas = mensaje[:256]
    mensaje = mensaje[256:]

    firma = mensaje[:256]
    mensaje = mensaje[256:]

    mac = mensaje[29:]

    mensaje_cifrado = mensaje[:29]
    llaves= descifrar_llaves(llaves_cifradas, llave_publica_receptor)
    aes= llaves[:16]
    # print("llaves: ", llaves)
    # print(b"aes: ",aes)
    llaves = llaves[16:]
    iv= llaves[:16]
    # print(b"iv: ",iv)
    llaves = llaves[16:]
    mac= llaves
    # print(b"mac: ",mac)

    firmas = firmar_llaves(aes, iv, mac, llave_publica_receptor) # paso 2
    print( 'llaves firmadas-------------------------------------------------------------------------')
    print (firmas)
    print( 'llaves firmadas-------------------------------------------------------------------------')


    mensaje_descifrado = descifrar_mensaje(aes, iv, mensaje_cifrado) # paso 3
    print( 'mensaje-------------------------------------------------------------------------')
    print (mensaje_descifrado)
    print( 'mensaje-------------------------------------------------------------------------')
    codigo_mac = calcular_hmac(llaves_cifradas + firma + mensaje_cifrado, mac) # paso 4
    print( 'codigo mac-------------------------------------------------------------------------')
    print (codigo_mac)
    print( 'codigo mac-------------------------------------------------------------------------')

    return 0
    


        
# Hilo para leer mensajes de clientes
def atencion(cliente, clientes, llave_publica_receptor, llave_privada_propia):
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        if mensaje.strip() == b'exit':
            cliente.close()
            return
        broadcast(mensaje, clientes, llave_publica_receptor, llave_privada_propia)
    

def escuchar(servidor, llave_publica_receptor, llave_privada_propia):
    servidor.listen(5) # peticiones de conexion simultaneas
    clientes = []
    while True:
        cliente, _ = servidor.accept() # bloqueante, hasta que llegue una peticion
        clientes.append(cliente)
        hiloAtencion = threading.Thread(target=atencion, args=
                                        (cliente, clientes, llave_publica_receptor, llave_privada_propia)) # se crea un hilo de atención por cliente
        hiloAtencion.start()


if __name__ == '__main__':
    
    servidor = crear_socket_servidor(sys.argv[1])

    llave_publica_path = sys.argv[2] # ruta de archivo en formato PEM
    llave_publica_receptor = llaves.recuperar_privada_from_path(llave_publica_path)
    llave_privada_propia_path = sys.argv[3]
    llave_privada_propia = llaves.recuperar_publica_from_path(llave_privada_propia_path)

    print('Escuchando...')
    escuchar(servidor, llave_publica_receptor, llave_privada_propia)

