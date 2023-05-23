
# Un cliente para el servidor de mensajes que envía y recibe mensajes de otros clientes a través del servidor.

# El cliente es un programa de línea de comandos simple que toma el nombre de usuario del cliente y el nombre
# de usuario del destinatario como argumentos de línea de comandos. El cliente luego envía un mensaje al servidor,
# que luego envía el mensaje al cliente destinatario. El cliente destinatario luego envía un mensaje de vuelta al
# servidor, que luego envía el mensaje de vuelta al cliente original. El cliente luego imprime el mensaje en la consola.

# Los mensajes se envían como objetos JSON. El objeto JSON contiene el nombre de usuario del remitente, el nombre de
# usuario del destinatario y el propio mensaje.

# Los mensajes se encriptan utilizando RSA. El cliente genera un par de claves pública y privada. Luego, el cliente
# envía la clave pública al servidor. El servidor luego envía la clave pública al cliente destinatario. El cliente
# destinatario utiliza la clave pública para desencriptar el mensaje. Luego, el cliente destinatario envía el mensaje
# de vuelta al servidor, que luego lo envía de vuelta al cliente original. El cliente original luego desencripta el mensaje
#  utilizando la clave privada.

# El cliente también utiliza una función hash para hashear el mensaje. Luego, el cliente envía el hash al servidor. El
# servidor luego envía el hash al cliente destinatario. El cliente destinatario luego hashea el mensaje y compara el hash
# con el hash enviado por el servidor. Si los hashes coinciden, el cliente destinatario envía el mensaje de vuelta al
# servidor, que luego lo envía de vuelta al cliente original. El cliente original luego hashea el mensaje y compara el hash
#  con el hash enviado por el servidor. Si los hashes coinciden, el cliente imprime el mensaje en la consola.

# Los hashes se firman utilizando ECDSA. El cliente genera un par de claves pública y privada. Luego, el cliente envía la
# clave pública al servidor. El servidor luego envía la clave pública al cliente destinatario. El cliente destinatario utiliza
# la clave pública para verificar la firma del mensaje. Luego, el cliente destinatario envía el mensaje de vuelta al servidor,
# que luego lo envía de vuelta al cliente original. El cliente original luego verifica la firma del mensaje utilizando la
# clave pública del cliente destinatario.

import threading
import rsa
import socket
import sys
import json
import hashlib
import ecdsa
import time
import os
from Crypto.Cipher import AES
from colorama import Fore

# El cliente genera un par de llaves RSA publica y privada.
public_key, private_key = rsa.newkeys(1024)

# El cliente genera un par de llaves ECDSA publica y privada.
ecdsa_private_key = ecdsa.SigningKey.generate(
    curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
ecdsa_public_key = ecdsa_private_key.get_verifying_key()

# El cliente genera una llave AES.
aes_key = os.urandom(16)
aes_iv = os.urandom(16)

# Generar un mensaje cifrado y firmado


def generateMessage(recipient, message) -> str:
    cipher = AES.new(aes_key, AES.MODE_EAX, aes_iv)
    ciphertext = cipher.encrypt(message.encode())
    signature = ecdsa_private_key.sign(ciphertext, hashfunc=hashlib.sha256)
    return json.dumps({'recipient': recipient, 'message': ciphertext.hex(), 'signature': signature.hex()}).encode()

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

# # Enviar un mensage directamente al destino


# def send_messages(client_socket):
#     while True:
#         message = input("Enviar: ")
#         client_socket.sendall(message.encode())

# # Recibir un mensaje directamente del destino


# def receive_messages(client_socket):
#     while True:
#         response = client_socket.recv(1024)
#         print(f"Recibido: {response.decode()}")


# Crear un socket para enviar y recibir mensajes directamente
direct_client_socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
direct_client_socket_rcv = socket.socket()

# Enlazar el socket a un puerto
direct_client_socket_send.bind(("localhost", 0))
direct_client_socket_rcv.bind(("localhost", 0))

# Obtener el puerto del socket
direct_client_port_send = direct_client_socket_send.getsockname()[1]

# Obtener el puerto del socket
direct_client_port_rcv = direct_client_socket_rcv.getsockname()[1]


# El cliente se conecta al servidor.
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 9999))

# Imprimir filtro de Wireshark
print(Fore.RED + " tcp.port eq", direct_client_port_send,
      "or tcp.port eq", direct_client_port_rcv, "or tcp.port eq 9999")
Fore.WHITE
input("Presione enter para continuar...")
# El cliente envia la llave publica al servidor.
print(Fore.WHITE + "\nEnviando la clave RSA publica", public_key.save_pkcs1())
client_socket.send(public_key.save_pkcs1())

# El cliente recibe la llave publica del servidor.
server_public_key_bytes = client_socket.recv(1024)
print("\nRecibiendo la clave RSA publica", server_public_key_bytes)
server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_bytes)

# El cliente envia la llave publica ECDSA al servidor.
print("\nEnviando la clave ECDSA publica: ",
      ecdsa_public_key.to_string().hex())
client_socket.send(rsa.encrypt(
    ecdsa_public_key.to_string(), server_public_key))

# El cliente recibe la llave publica ECDSA del servidor.
ecsda_response = client_socket.recv(1024)
server_ecdsa_public_key = ecdsa.VerifyingKey.from_string(
    rsa.decrypt(ecsda_response, private_key), curve=ecdsa.SECP256k1)
print("\nRecibiendo la clave ECDSA publica",
      server_ecdsa_public_key.to_string().hex())

# El cliente envia la llave AES al servidor.
print("\nEnviando la clave AES: ", aes_key.hex(), aes_iv.hex())
ciphertext = rsa.encrypt(json.dumps(
    {"aes_key": aes_key.hex(), "aes_iv": aes_iv.hex()}).encode(), server_public_key)
json_message = json.dumps({"message": ciphertext.hex(), "signature": ecdsa_private_key.sign(
    ciphertext, hashfunc=hashlib.sha256).hex()})
client_socket.send(json_message.encode())

# El cliente recibe una confirmacion del servidor.
if decryptMessage(client_socket.recv(1024), server_ecdsa_public_key, aes_key, aes_iv) == "OK":
    None

# El cliente envía los puertos al servidor.
client_socket.send(generateMessage('server', json.dumps(
    {"send": str(direct_client_port_send), "receive": str(direct_client_port_rcv)})))

# El cliente recibe una confirmacion del servidor.
if decryptMessage(client_socket.recv(1024), server_ecdsa_public_key, aes_key, aes_iv) == "OK":
    print("\nConexión establecida con el servidor.")

# El cliente envia el nombre de usuario del cliente al servidor.
username = input("\nIniciar sesion como: ")
client_socket.send(generateMessage(
    'server', username))

# El cliente recibe una confirmacion del servidor.
if decryptMessage(client_socket.recv(1024), server_ecdsa_public_key, aes_key, aes_iv) == username:
    print("\nSesion iniciada como: ", username)
else:
    print("\nSesion no iniciada.")

# El cliente envia el nombre de usuario del destinatario al servidor.
recipient = input("\nEnviar mensajes a: ")

client_socket.send(generateMessage(
    'server', recipient))
if recipient == 'server':
    # Enviar y recibir mensajes indefinidamente
    while True:
        message = input("\nEnter message: ")
        client_socket.send(generateMessage(
            recipient, message))
        print(decryptMessage(client_socket.recv(1024),
              server_ecdsa_public_key, aes_key, aes_iv))

else:
    # El cliente recibe la informacion del destinatario del servidor.
    recipient_info = json.loads(decryptMessage(
        client_socket.recv(8192), server_ecdsa_public_key, aes_key, aes_iv))
    # print("Informacion completa del destinatario: ", recipient_info)
    recipient_RSA_public_key = rsa.PublicKey.load_pkcs1(
        bytes.fromhex(recipient_info["public_key"]))
    recipient_ECDSA_public_key = ecdsa.VerifyingKey.from_string(
        bytes.fromhex(recipient_info["ecdsa_public_key"]), curve=ecdsa.SECP256k1)
    recipient_aes_key = bytes.fromhex(recipient_info["aes_key"])
    recipient_aes_iv = bytes.fromhex(recipient_info["aes_iv"])
    recipient_address = recipient_info["address"]
    recipient_sender_port = int(recipient_info["send_port"])
    recipient_receiver_port = int(recipient_info["receive_port"])


def send_messages(socket, address):
    # Connect to the other client and send messages
    socket.connect((address[0], recipient_receiver_port))
    while True:
        message = input(Fore.GREEN + "Enviar: ")
        socket.sendall(generateMessage(recipient, message))


def receive_messages(socket: socket.socket):
    print(socket, type(socket))
    socket.listen(5)

    # Accept connections from other clients
    conn, address = socket.accept()

    # Receive messages from other clients
    while True:
        msg_bytes = conn.recv(1024)
        msg = decryptMessage(
            msg_bytes, recipient_ECDSA_public_key, recipient_aes_key, recipient_aes_iv)
        print(Fore.BLUE + "Mensaje de", recipient, ": ", msg + Fore.GREEN)


# El cliente comienza a escuchar en el puerto del socket

threading.Thread(target=receive_messages, args=(
    direct_client_socket_rcv,)).start()

# Espera 10 segundos para que el otro cliente comience a escuchar en el puerto del socket
time.sleep(10)

# Comienza a enviar y recibir mensajes con el otro cliente
threading.Thread(target=send_messages, args=(
    direct_client_socket_send, recipient_address)).start()
