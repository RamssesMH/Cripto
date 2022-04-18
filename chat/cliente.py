from re import I
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import time
import socket
import threading
import sys
import json

import mensajes

def conectar_servidor(host, puerto):
    # socket para IP v4
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()

def recuperarOriginal(msg):
    for elemento in msg:
        if len(elemento) == 2: #Si la longitud es = 2 entonces es el cliente, sino, son las llaves
            tp = tuple(elemento)
            llaves.append(tp)
        else:
            llave = bytes(elemento)
            llaves.append(llave)
    return llaves

def leer_mensajes(cliente):
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        if len(mensaje)>=700:
            try:
                msg = mensaje.decode('utf-8')

                    # print(msg)
                    # print(type(msg))
                    #La lista recupera su formato original, pasa de ser STR a LISTA
                msg = json.loads(msg)
                    # print(msg)
                    # print(type(msg))

                    # Convertir el unicode de las llaves a su binario respectivo y la direccion de host a su tupla respectiva para obtener
                    #la misma lista que se encuentra en el servidor
                try:
                    llaves.clear() #Limpiar arreglo para que no se dupliquen
                except:
                    pass
                llaves = recuperarOriginal(msg)
            except json.JSONDecodeError:
                    #Procesar mensajes que no son la lista de llaves
                # msg=decifrar(msg,llaves[1],llaves[3])
                print(msg)
        else:
            banderas=0
            llctr=1
            llhash=2
            lliv=3

            mensaje=mensaje.split(b"/////")
            mensajecif=mensaje[0]
            mac=mensaje[1]
            mac = mac.decode('utf-8')
            while banderas==0:
                if llhash<len(llaves):
                    maccif = hashedMac(mensajecif, llaves[llhash])
                    if maccif==mac:
                        mensajeq=decifrar(mensaje[0],llaves[llctr],llaves[lliv])
                        if mensajeq.startswith(b"-->"):
                            print('\n')
                            mensajeq = mensajeq.decode('utf-8')
                            print(mensajeq)
                            banderas=1
                        else :
                            llctr=llctr+4
                            
                            lliv=lliv+4
                    else:
                        llhash=llhash+4
                else:
                    print("El mensaje esta corrupto")
                    banderas=1

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

def decifrar(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesDecryptor = aesCipher.decryptor()
    mensaje = aesDecryptor.update(mensaje)
    aesDecryptor.finalize()

    return mensaje

def enviar_mensaje_loop(cliente, nick):
    #llave CTR
    keyctr = os.urandom(16)
    iv = os.urandom(16)
    mensaje = b'LLAVECTR' + keyctr
    mensajes.mandar_mensaje(cliente, mensaje)

    time.sleep(0.2)
    #llave HMAC
    b = 128 #tamaño de bloque de sha256
    mac = os.urandom(b)
    mensaje = b'HMAC' + mac
    mensajes.mandar_mensaje(cliente, mensaje)

    time.sleep(0.2)
    #IV
    mensaje = b'IV' + iv
    mensajes.mandar_mensaje(cliente, mensaje)

    mensaje = b''
    mensaje2= b''
    while not b'exit' in mensaje2:
        mensaje = input('-->'+nick+': ')
        msg = f'-->{nick}: {mensaje}'
        mensaje = msg.encode('utf-8')
        # print(mensaje)

        # #Se obtiene el mensaje cifrado
        mensaje = cifrar(mensaje, keyctr, iv)

        #Se manda el mensaje cifrado a la funcion de hmac para aplicar hmac
        hmacc = hashedMac(mensaje, mac)
        hmacc= hmacc.encode('utf-8')
        # print(hmacc)
        mensaje = mensaje+b"/////"+hmacc
        #Decifrar para que el ciclo while detecte las palabras
        mensaje2 = decifrar(mensaje, keyctr, iv)


        mensajes.mandar_mensaje(cliente, mensaje)
    
    print('Conexión cerrada.')
    cliente.close()


if __name__ == '__main__':
    host = sys.argv[1]
    puerto = sys.argv[2]
    cliente = conectar_servidor(host, puerto)
    
    #lista de llaves de clientes recuperada del servidor
    llaves = []

    nick = input('Introduce tu Nick para esta conversacion: ')
    print('Introduce "exit" para salir')

    hilo = threading.Thread(target=leer_mensajes, args=(cliente, ))
    hilo.daemon = True
    hilo.start()
    enviar_mensaje_loop(cliente, nick)
