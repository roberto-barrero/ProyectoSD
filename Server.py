# Un servidor que recibe un mensaje de los clientes y lo envía al destinatario.

# Los clientes se conectan al servidor a través de un socket, y cada cliente utiliza un par de claves
# RSA para encriptar y desencriptar una clave AES.

# La clave AES se utiliza para encriptar y desencriptar los mensajes enviados entre los clientes.

# El servidor es responsable de enviar la clave AES al destinatario del mensaje.

# El servidor también es responsable de almacenar los mensajes en una base de datos y de enviar los
# mensajes al destinatario cuando están en línea.

# El servidor también es responsable de almacenar las claves públicas de los clientes en una base de
# datos y de enviar las claves públicas a los clientes cuando están en línea.

# El servidor no es responsable de crear ni almacenar las claves privadas de los clientes.

# Importar las bibliotecas necesarias
import socket
import sys
import threading
import time
import os
import sqlite3
import datetime
import random
import hashlib
import base64
import json
import traceback

# Importar las bibliotecas de encriptación
import rsa
import ecdsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Crear un mensaje


def generateMessage(message, aes_key, aes_iv) -> str:
    cipher = AES.new(aes_key, AES.MODE_EAX, aes_iv)
    ciphertext = cipher.encrypt(message.encode())
    return json.dumps({'message': ciphertext.hex(), 'signature': ecdsa_private_key.sign(ciphertext, hashfunc=hashlib.sha256).hex()}).encode()


# Desencriptar un mensaje con la llave privada compartida
def decryptMessage(response, recipient_ECDSA_public_key, aes_key, aes_iv) -> str:
    cipher = AES.new(aes_key, AES.MODE_EAX, aes_iv)
    data = json.loads(response.decode())
    try:
        signature = bytes.fromhex(data["signature"])
        ciphertext = bytes.fromhex(data["message"])
        if recipient_ECDSA_public_key.verify(signature, ciphertext, hashfunc=hashlib.sha256):
            return cipher.decrypt(ciphertext).decode()
        else:
            return False
    except:
        return False

# Funcion para crear un socket


def create_socket():
    try:
        global host
        global port
        global s

        # La dirección IP es la dirección IP del servidor
        host = '127.0.0.1'

        # El puerto en el que se escucha la conexión
        port = 9999

        # Crear un socket
        s = socket.socket()

    except socket.error as msg:
        print("Socket creation error: " + str(msg))

# La funcion para enlazar el socket


def bind_socket():
    try:
        global host
        global port
        global s

        # Enlace del socket
        s.bind((host, port))

        # Escuchar el socket
        s.listen(5)

    except socket.error as msg:
        print("Socket binding error: " + str(msg) + "\n" + "Retrying...")
        bind_socket()


# Generar las claves pública y privada RSA del servidor
public_key, private_key = rsa.newkeys(1024)

# Generar la clave AES y el vector de inicialización
aes_key = os.urandom(16)
aes_iv = os.urandom(16)

# Generar la clave privada y pública ECDSA del servidor
ecdsa_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
ecdsa_public_key = ecdsa_private_key.get_verifying_key()

connected_clients = {}
public_keys = []

# La funcion para aceptar las conexiones entrantes


def accept_connections():
    print("Listening...")
    # The infinite loop that is used to accept connections from multiple clients
    while True:

        # Accepting a connection from a client
        conn, address = s.accept()

        # Creating a thread for the client
        thread = threading.Thread(target=handle_client, args=(conn, address))

        # Starting the thread
        thread.start()

# La funcion para manejar los clientes


def handle_client(conn, address):
    try:
        # Recibir la clave pública RSA del cliente
        client_public_key_bytes = conn.recv(1024)
        print("Recibiendo la clave pública RSA del cliente " +
              str(address), client_public_key_bytes)
        client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_bytes)

        # Responder al cliente con la clave pública RSA del servidor
        print("Enviando la clave pública RSA del servidor al cliente " +
              str(address), public_key.save_pkcs1())
        conn.send(public_key.save_pkcs1())

        # Recibir la clave pública ECDSA del cliente
        ecdsa_response = conn.recv(1024)
        unencrypted = rsa.decrypt(ecdsa_response, private_key)
        client_ecdsa_public_key = ecdsa.VerifyingKey.from_string(
            unencrypted, curve=ecdsa.SECP256k1)
        print("Recibiendo la clave pública ECDSA del cliente " +
              str(address), client_ecdsa_public_key.to_string().hex())

        # Responder al cliente con la clave pública ECDSA del servidor
        print("Enviando la clave pública ECDSA del servidor al cliente " +
              str(address), ecdsa_public_key.to_string().hex())
        conn.send(rsa.encrypt(
            ecdsa_public_key.to_string(), client_public_key))

        # Recibir la clave AES del cliente
        bytes_msg = conn.recv(1024)
        print("Recibiendo la clave AES del cliente ", bytes_msg)

        msg = json.loads(bytes_msg.decode())
        print("Mensaje recibido: ", msg["signature"], msg["message"])

        signature = bytes.fromhex(msg["signature"])
        cipheredtext = bytes.fromhex(msg["message"])

        if client_ecdsa_public_key.verify(signature, cipheredtext, hashfunc=hashlib.sha256):
            message = json.loads(rsa.decrypt(
                cipheredtext, private_key))
            client_aes_key = bytes.fromhex(message["aes_key"])
            client_aes_iv = bytes.fromhex(message["aes_iv"])
        else:
            print("Error: The signature is invalid.")
            conn.send(json.dumps({'message': rsa.encrypt(
                "Error: The signature is invalid.", client_public_key)}))
            conn.close()

        # Responder al cliente con una confirmación
        conn.send(generateMessage("OK", client_aes_key, client_aes_iv))

        # Recibir los puertos del cliente
        bytes_msg = conn.recv(1024)
        message = json.loads(decryptMessage(
            bytes_msg, client_ecdsa_public_key, client_aes_key, client_aes_iv))
        client_sender_port = message["send"]
        client_receiver_port = message["receive"]
        print("Puertos recibidos: ", client_sender_port, client_receiver_port)

        # Responder al cliente con una confirmación
        conn.send(generateMessage("OK", client_aes_key, client_aes_iv))

        # Recibir el nombre de usuario del cliente
        bytes_msg = conn.recv(1024)
        print("Recibiendo el nombre de usuario del cliente ", bytes_msg)
        username = decryptMessage(
            bytes_msg, client_ecdsa_public_key, client_aes_key, client_aes_iv)
        print("Nombre de usuario recibido: ", username)

        # Responder al cliente con una confirmación
        conn.send(generateMessage(
            username, client_aes_key, client_aes_iv))

        # Almacenar la informacion del cliente
        connected_clients[username] = {"address": address, "public_key": client_public_key.save_pkcs1().hex(
        ), "ecdsa_public_key": client_ecdsa_public_key.to_string().hex(), "aes_key": client_aes_key.hex(), "aes_iv": client_aes_iv.hex(), "send_port": client_sender_port, "receive_port": client_receiver_port}

        # Recibir destinatario del cliente
        bytes_msg = conn.recv(1024)
        recipient = decryptMessage(
            bytes_msg, client_ecdsa_public_key, client_aes_key, client_aes_iv)
        print("Destinatario recibido: ", recipient)

        if recipient == 'server':
            while True:
                # Responder al cliente con OK
                conn.send(generateMessage("OK", client_aes_key, client_aes_iv))

                # Recibir el mensaje del cliente
                bytes_msg = conn.recv(1024)
                print("Recibiendo el mensaje del cliente ", bytes_msg)
                message = decryptMessage(
                    bytes_msg, client_ecdsa_public_key, client_aes_key, client_aes_iv)
                if message == 'exit':
                    print("Cerrando conexxion...")
                    break
                else:
                    print("Mensaje recibido: ", message)
        else:
            try:
                connected_clients[recipient]
                conn.send(generateMessage(
                    json.dumps(connected_clients[recipient]), client_aes_key, client_aes_iv))
            except:
                conn.send(generateMessage(
                    "Error: The recipient is not connected.", client_aes_key, client_aes_iv))
                while True:
                    # Responder al cliente con la información del destinatario o con un error si el destinatario no esta conectado
                    try:
                        connected_clients[recipient]
                        conn.send(generateMessage(
                            json.dumps(connected_clients[recipient]), client_aes_key, client_aes_iv))
                        break
                    except:
                        None

        # Cerrar la conexión con el cliente
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        print("-- " + username + " has disconnected --\n\n")
        connected_clients.pop(recipient)

    except Exception as e:
        print("Error: The client " + str(address) + " has disconnected.\n\n")
        conn.close()
        print(e)
        traceback.print_exc()


def main():
    create_socket()
    bind_socket()
    accept_connections()


main()
