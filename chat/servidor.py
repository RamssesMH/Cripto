"""
Servidor.

Servidor de un chat. Es una implementación incompleta:
- Falta manejo de exclusión mutua
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import socket
import threading
import sys
import json
import os

import mensajes


def crear_socket_servidor(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('', int(puerto)))  # hace el bind en cualquier interfaz disponible
    return servidor


def broadcast(mensaje, clientes):
    for cliente in clientes:
        mensajes.mandar_mensaje(cliente, mensaje)

def broadcastllaves(data, clientes):
    #Convertir las llaves CTR y MAC en unicode por que BYTES no es serializable para enviar por sockets con json
    #Se reestructura la lista
    for elemento in data:
        if type(elemento) == bytes:
            ucode = list(elemento)
            enviar.append(ucode)
        else:
            enviar.append(elemento)
    
    # print(enviar)
    datos = json.dumps(enviar) #Json es el modulo que permite enviar listas completas
    # print(datos)
    #limpiar la lista para que unicamente aparezcan los clientes conectados
    enviar.clear()
    msg = datos.encode('utf-8')
    # print(msg)
    for cliente in clientes:
        mensajes.mandar_mensaje(cliente, msg)
        
# Hilo para leer mensajes de clientes
def atencion(cliente, clientes, addr):
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        ## Se tiene que decifrar aqui el mensaje para ver que se pueda hacer la comprobación de startswith
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

            #Mandar las llaves a todos, hasta al cliente que envio el mensaje
            #VOLVER A CIFRAR EL MENSAJE ---
            broadcastllaves(data, clientes)
        elif mensaje.strip().endswith(b'exit'):
            #Quitar al cliente de la lista de data asi como sus llaves
            for c in data:
                if addr == c:
                    lugar = data.index(addr)
                    data.pop(lugar) #Se elimina el cliente
                    data.pop(lugar) #Se elimina la llave CTR
                    data.pop(lugar) #Se elimina la llave HMAC
            #Mandar la lista de llaves actualizadas a todos excepto al que escribio exit y eliminar al cliente de las conexiones
            if cliente in clientes:
                clientes.remove(cliente)
            broadcastllaves(data, clientes)
            #Cerrar su conexión
            print(f'\nEl cliente {cliente} ha salido.')
            cliente.close()
            return
        else:
            #Mandar mensaje a todos excepto al cliente que envio el mensaje
            if cliente in clientes:
                clientes.remove(cliente)
            broadcast(mensaje, clientes)
            clientes.append(cliente)
    

def escuchar(servidor):
    servidor.listen(5) # peticiones de conexion simultaneas
    while True:
        cliente, addr = servidor.accept() # bloqueante, hasta que llegue una peticion
        clientes.append(cliente)
        data.append(addr) #Se añade primeramente al arreglo data el cliente
        print(f'\nConexion con {addr} establecida.')
        hiloAtencion = threading.Thread(target=atencion, args=(cliente, clientes, addr)) # se crea un hilo de atención por cliente
        hiloAtencion.start()


if __name__ == '__main__':
    
    servidor = crear_socket_servidor(sys.argv[1])
    clientes = [] #almacena las conexiones de los clientes unicamente
    data = [] #almacena el socket del cliente, su llavectr, su llave hmac, su IV y su hmac hash
    enviar = [] #almacena los mismos datos que data pero parseados en unicode para su transmisión por sockets
    print('Escuchando...')
    escuchar(servidor)
