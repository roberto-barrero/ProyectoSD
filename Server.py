# A server that receives a message from a clients and sends it to the recipient

# The clients are connected to the server via a socket, and each client uses an RSA key pair to encrypt and decrypt an AES key.
# The AES key is used to encrypt and decrypt the messages sent between the clients.
# The server is responsible for sending the AES key to the recipient of the message.

# The server is also responsible for storing the messages in a database, and for sending the messages to the recipient when they are online.
# The server is also responsible for storing the public keys of the clients in a database, and for sending the public keys to the clients when they are online.
# The server is not responsible for creating or storing the private keys of the clients.

# Importing libraries
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

# Importing the RSA library
import rsa
import ecdsa

# Importing the AES library
from Crypto.Cipher import AES

# Importing the SHA-256 library
from Crypto.Hash import SHA256

# The function that is used to create a socket


def create_socket():
    try:
        global host
        global port
        global s

        # The host is the IP address of the server
        host = '127.0.0.1'

        # The port is the port number that the server is listening on
        port = 9999

        # Creating a socket
        s = socket.socket()

    except socket.error as msg:
        print("Socket creation error: " + str(msg))

# The function that is used to bind the socket to the port


def bind_socket():
    try:
        global host
        global port
        global s

        # Binding the socket to the port
        s.bind((host, port))

        # Listening for connections
        s.listen(5)

    except socket.error as msg:
        print("Socket binding error: " + str(msg) + "\n" + "Retrying...")
        bind_socket()


# Generating the public and private RSA keys of the server
public_key, private_key = rsa.newkeys(1024)

# Generating the public and private AES keys of the server
aes_key = os.urandom(16)
aes_iv = os.urandom(16)

# Generattin the public and private ECDSA keys of the server
ecdsa_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
ecdsa_public_key = ecdsa_private_key.get_verifying_key()

connected_clients = []
public_keys = []

# The function that is used to accept connections from multiple clients


def accept_connections():
    print("Listening...")
    # The infinite loop that is used to accept connections from multiple clients
    while True:

        # Accepting a connection from a client
        conn, address = s.accept()

        # Storing the IP address and port number of the client in a list
        connected_clients.append(address)

        # Creating a thread for the client
        thread = threading.Thread(target=handle_client, args=(conn, address))

        # Starting the thread
        thread.start()

# The function that is used to handle a client


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

        # Almacenar la clave pública RSA del cliente en una lista
        public_keys.append((address, public_key))
        cipher = AES.new(client_aes_key, AES.MODE_EAX, client_aes_iv)

        # Responder al cliente con una confirmación
        conn.send(generateMessage("OK", cipher))

        # Responding to the client with the public keys of the other clients
        # conn.send(generateMessage(json.dumps(public_keys), cipher))
        # The infinite loop that is used to handle a client
        while True:
            None
    except Exception as e:
        print("Error: The client " + str(address) + " has disconnected.\n\n")
        conn.close()
        print(e)
        traceback.print_exc()

# The function that is used to create a message for a client


def generateMessage(message, cipher):
    ciphertext = cipher.encrypt(message.encode())
    return json.dumps({'message': ciphertext.hex(), 'signature': ecdsa_private_key.sign(ciphertext, hashfunc=hashlib.sha256).hex()}).encode()


def main():
    create_socket()
    bind_socket()
    accept_connections()


main()
