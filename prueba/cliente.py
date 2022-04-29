from traceback import print_tb
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import time
import socket
import threading
import sys
import json

import mensajes

def conectar_servidor(host, puerto):
    # socket para IPv4
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()

# def recuperarOriginal(msg):
#     for elemento in msg:
#         if len(elemento) == 2: #Si la longitud es = 2 entonces es el cliente, sino, son las llaves
#             tp = tuple(elemento)
#             llaves.append(tp)
#         else:
#             llave = bytes(elemento)
#             llaves.append(llave)
#     return llaves

def exchange(publica_Servidor, mypriv):
    # shared_key_emisor = mypriv.exchange(publica_Servidor) # esto es binario
    shared_key_emisor = mypriv.exchange(ec.ECDH(), publica_Servidor)

    return shared_key_emisor

def recuperarObjeto(llave):
    # regresar a objeto llave
    public_key_recuperada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    
    return public_key_recuperada

def leer_mensajes(cliente):
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        if mensaje.startswith(b"<->"):
            msg = mensaje.split(b"/////")
            try:
                if len(msg) == 4:
                    llaves_publicas.append(msg[1])
                    llaves_publicas.append(msg[2])
                    publica_objeto = recuperarObjeto(llaves_publicas[1])

                    try:
                        publica_objeto.verify(msg[3] , llaves_publicas[0], ec.ECDSA(hashes.SHA256 ()))
                        print('FIRMA VALIDA')
                    except:
                        raise RuntimeError('NO SE HA PODIDO VERIFICAR EL CERTIFICADO.')

                    publica_objeto = recuperarObjeto(llaves_publicas[0])
                    secret = exchange(publica_objeto, myprivkey)
                    secreto.append(secret)

                    derived_key = HKDF(algorithm = hashes.SHA256(),
                        length = 16, 
                        salt = None,
                        info = b'handshake data', # tiene que ser lo mismo de los dos lados
                        backend = default_backend()).derive(secret)

                    #llave CTR
                    keyctr = derived_key
                    parametros.append(keyctr)
                    iv = os.urandom(16)
                    parametros.append(iv)
                    mensaje = b'LLAVECTR' + keyctr
                    mensajes.mandar_mensaje(cliente, mensaje)

                    time.sleep(0.2)

                    #llave HMAC
                    derived_key = HKDF(algorithm = hashes.SHA256(),
                        length = 128, 
                        salt = None,
                        info = b'handshake data', # tiene que ser lo mismo de los dos lados
                        backend = default_backend()).derive(secret)
                    
                    mac = derived_key
                    parametros.append(mac)
                    mensaje = b'HMAC' + mac
                    mensajes.mandar_mensaje(cliente, mensaje)

                    llaves.append(keyctr)
                    llaves.append(iv)
                    llaves.append(mac)

                    time.sleep(0.2)
                    #IV
                    mensaje = b'IV' + iv
                    mensajes.mandar_mensaje(cliente, mensaje)
            except json.JSONDecodeError:
                #Procesar mensajes que no son la lista de llaves
                print("")
        else:
            msg = mensaje.split(b"/////")
            bandera=0

            if bandera==0:
                mensajeq=decifrar(msg[1],parametros[0],parametros[1])
                if mensajeq.startswith(b"-->"):
                    print('\n')
                    mensajeq = mensajeq.decode('utf-8')
                    print(mensajeq)
                    bandera=1


def cifrar(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesEncryptor = aesCipher.encryptor()
    cipher = aesEncryptor.update(mensaje)
    aesEncryptor.finalize()

    return cipher

def hashedMac(mensaje, mac):
    h = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)

    return h.finalize().hex()

def serializar(pubkey):
    key = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return key

def decifrar(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesDecryptor = aesCipher.decryptor()
    mensaje = aesDecryptor.update(mensaje)
    aesDecryptor.finalize()

    return mensaje

def enviar_mensaje_loop(cliente, nick, pubdh):
    #DH Pubkey
    pubdh = serializar(pubdh)
    mensajes.mandar_mensaje(cliente, pubdh)

    mensaje = b''
    mensaje2= b''
    while not b'exit' in mensaje2:
        mensaje = input('-->'+nick+': ')
        msg = f'-->{nick}: {mensaje}'
        mensaje = msg.encode('utf-8')
        # print(mensaje)

        #Se obtiene el mensaje cifrado
        mensaje = cifrar(mensaje, parametros[0], parametros[1])

        #Se manda el mensaje cifrado a la funcion de hmac para aplicar hmac
        hmacc = hashedMac(mensaje, parametros[2])
        hmacc = hmacc.encode('utf-8')
        # print(hmacc)
        mensaje = mensaje+b"/////"+hmacc
        #Decifrar para que el ciclo while detecte las palabras
        mensaje2 = decifrar(mensaje, parametros[0], parametros[1])


        mensajes.mandar_mensaje(cliente, mensaje)
    
    print('Conexión cerrada.')
    cliente.close()


if __name__ == '__main__':
    host = sys.argv[1]
    puerto = sys.argv[2]
    cliente = conectar_servidor(host, puerto)

    #Diffie-Hellman
    myprivkey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    # Esta es la que se tiene que intercambiar
    mypubkey = myprivkey.public_key()
    # parameters = dh.generate_parameters(generator = 2, key_size = 2048, backend = default_backend())
    # myprivkey = parameters.generate_private_key()

    # Esta es la que se tiene que intercambiar
    # mypubkey = myprivkey.public_key()
    
    #lista de llaves de clientes recuperada del servidor
    llaves = []

    #Credenciales recibidas del servidor para autenticar mensajes y decifrar
    authServ = []
    llaves_publicas = []
    parametros = []
    secreto = []

    nick = input('Introduce tu Nick para esta conversacion: ')
    print('Introduce "exit" para salir')

    hilo = threading.Thread(target=leer_mensajes, args=(cliente, ))
    hilo.daemon = True
    hilo.start()
    enviar_mensaje_loop(cliente, nick, mypubkey)
