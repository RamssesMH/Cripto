"""
Servidor.

Servidor de un chat. Es una implementación incompleta:
- Falta manejo de exclusión mutua
"""
from traceback import print_tb
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import socket
import threading
import sys
import json
import os
import functools
import operator

import mensajes


def crear_socket_servidor(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('', int(puerto)))  # hace el bind en cualquier interfaz disponible
    return servidor


def broadcast(mensaje, clientes):
    for cliente in clientes:
        mensajes.mandar_mensaje(cliente, mensaje)

# def broadcastllaves(data, cliente):
#     #Convertir las llaves CTR y MAC en unicode por que BYTES no es serializable para enviar por sockets con json
#     #Se reestructura la lista
#     for elemento in data:
#         if type(elemento) == bytes:
#             ucode = list(elemento)
#             enviar.append(ucode)
#         else:
#             enviar.append(elemento)
    
#     # print(enviar)
#     datos = json.dumps(enviar) #Json es el modulo que permite enviar listas completas
#     # print(datos)
#     #limpiar la lista para que unicamente aparezcan los clientes conectados
#     enviar.clear()
#     msg = datos.encode('utf-8')
#     # print(msg)
#     # for cliente in clientes:
#     mensajes.mandar_mensaje(cliente, msg)

def decifrar(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesDecryptor = aesCipher.decryptor()
    mensaje = aesDecryptor.update(mensaje)
    aesDecryptor.finalize()

    return mensaje

def cifrarServ(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesEncryptor = aesCipher.encryptor()
    cipher = aesEncryptor.update(mensaje)
    aesEncryptor.finalize()

    return cipher


def hashedMac(mensaje, mac):
    h = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)

    return h.finalize().hex()

def serializar(ecpubkey):
    key = ecpubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return key

def exchange(publica_cliente, mypriv):
    # shared_key_emisor = mypriv.exchange(publica_cliente) # esto es binario
    shared_key_emisor = mypriv.exchange(ec.ECDH(), publica_cliente)

    return shared_key_emisor

def recuperarObjeto(llave):
    # regresar a objeto llave
    public_key_recuperada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    
    return public_key_recuperada
        
# Hilo para leer mensajes de clientes
def atencion(cliente, clientes, addr, keyctr, iv, mac):
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        if len(mensaje.split(b"/////")) < 2:
            if mensaje.startswith(b'LLAVECTR'):
                for c in data:
                    if addr == c:
                        data.append(mensaje[-16:]) #Después del socket del cliente se hace append a la llave CTR
            elif mensaje.startswith(b'HMAC'):
                for c in data:
                    if addr == c:
                        data.append(mensaje[-128:])#Después de la llave CTR se hace append a la llave MAC
            elif mensaje.startswith(b'IV'):
                for c in data:
                    if addr == c:
                        data.append(mensaje[-16:])#Después de la llave HMAC se hace append al iv
            elif mensaje.startswith(b'-----BEGIN PUBLIC KEY-----'):
                for c in data:
                    if addr == c:
                        llave = recuperarObjeto(mensaje)
                        secret = exchange(llave, myprivkey)
                        data.append(secret)
        else:
            ## Se tiene que decifrar aqui el mensaje para ver que se pueda hacer la comprobación de startswith
            mensajeog = mensaje.split(b"/////")
            if addr in data:
                lugar = data.index(addr)
                keyctr = data[lugar+2]
                iv = data[lugar+4]
            mensaje = decifrar(mensajeog[0], keyctr, iv)
            print (mensaje)
            if mensaje.strip().endswith(b'exit'):
                
                #Quitar al cliente de la lista de data asi como sus llaves
                for c in data:
                    if addr == c:
                        lugar = data.index(addr)
                        data.pop(lugar) #Se elimina el cliente
                        data.pop(lugar) #Se elimina la secreto compartido
                        data.pop(lugar) #Se elimina la llave CTR
                        data.pop(lugar) #Se elimina la llave MAC
                        data.pop(lugar) #Se elimina el IV
                #Eeliminar al cliente de las conexiones
                if cliente in clientes:
                    clientes.remove(cliente)
                #Cerrar su conexión
                print(f'\nEl cliente {cliente} ha salido.')
                cliente.close()
                return
            else:

                print("datos----------------------------------------")
                print(data)
                i = 0
                while len(data)> i:
                    print (i)
                    print("datos----------------------------------------")
                    if data[i] == addr:
                        i= i+5
                    else:
                        kct= i+2
                        liv= i+4
                        print(mensaje)
                        print(data[kct])
                        print(data[liv])
                        print (clientes)
                        mensajecif=cifrarServ(mensaje ,data[kct], data[liv])
                        i=i+5






                        # Cifrar el mensaje con las llaves del servidor
                        #Se aplica mac al mensaje cifrado
                        mc = hashedMac(mensajecif, mac)
                        mac_encoded = mc.encode('utf-8')
                        #convertir tupla de dirección de cliente a json
                        adr = json.dumps(addr).encode('utf-8')
                        # Se reconstruye nuevamente el mensaje para ser transmitido como se recibio originalmente pero con las credenciales del servidor
                        mensaje = adr+b"/////"+mensajecif+b"/////"+mac_encoded
                        #Mandar mensaje a todos excepto al cliente que envio el mensaje
                        mensajecif = mensaje.split(b"/////")
                        # if msg[0] == 




                        if cliente in clientes:
                            clientes.remove(cliente)
                        broadcast(mensaje, clientes)
                        clientes.append(cliente)
    

def escuchar(servidor, keyctr, iv, mac, myecprivkey, pubkey, ecpubkey):
    servidor.listen(5) # peticiones de conexion simultaneas
    while True:
        cliente, addr = servidor.accept() # bloqueante, hasta que llegue una peticion
        clientes.append(cliente)
        data.append(addr) #Se añade primeramente al arreglo data el cliente
        print(f'\nConexion con {addr} establecida.')

        #Serializar el objeto
        pubkey_serialized = serializar(pubkey)
        ecpubkey_serialized = serializar(ecpubkey)

        #firmar la llave efímera
        signature = myecprivkey.sign(pubkey_serialized, ec.ECDSA(hashes.SHA256()))

        msg = b"<->" + b"/////" + pubkey_serialized + b"/////" + ecpubkey_serialized + b"/////" + signature
        mensajes.mandar_mensaje(cliente, msg)
        hiloAtencion = threading.Thread(target=atencion, args=(cliente, clientes, addr, keyctr, iv, mac)) # se crea un hilo de atención por cliente
        hiloAtencion.start()


if __name__ == '__main__':
    
    servidor = crear_socket_servidor(sys.argv[1])

    #------Diffie-Hellman----------- EFIMERAS
    myprivkey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    # Esta es la que se tiene que intercambiar
    mypubkey = myprivkey.public_key()

    #-----Llaves EC---------- NO EFIMERAS
    myecprivkey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    myecpubkey = myecprivkey.public_key()

    #Llave ctr de servidor e IV
    keyctr = os.urandom(16)
    iv = os.urandom(16)

    #Llave mac de servidor
    b = 128 #tamaño de bloque de sha256
    mac = os.urandom(b)

    clientes = [] #almacena las conexiones de los clientes unicamente
    data = [] #almacena el socket del cliente, secreto,  su llavectr, su llave hmac, su IV
    enviar = [] #almacena los mismos datos que data pero parseados en unicode para su transmisión por sockets
    secreto = []
    print('Escuchando...')
    escuchar(servidor, keyctr, iv, mac, myecprivkey, mypubkey, myecpubkey)
