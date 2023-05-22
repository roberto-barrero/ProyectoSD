# A client for the message server that sends and receives messages
# from other clients through the server.

# The client is a simple command line program that takes the username of the client and the username of the recipient
# as command line arguments. The client then sends a message to the server, which then sends the message to the
# recipient client. The recipient client then sends a message back to the server, which then sends the message back
# to the original client. The client then prints the message to the console.

# The messages are sent as JSON objects. The JSON object contains the username of the sender, the username of the
# recipient, and the message itself.

# The messages are encrypted using RSA. The client generates a public and private key pair. The client then sends the
# public key to the server. The server then sends the public key to the recipient client. The recipient client then
# uses the public key to decrypt the message. The recipient client then sends the message back to the server, which
# then sends the message back to the original client. The original client then decrypts the message using the private
# key.

# The client also uses a hash function to hash the message. The client then sends the hash to the server. The server
# then sends the hash to the recipient client. The recipient client then hashes the message and compares the hash to
# the hash sent by the server. If the hashes match, then the recipient client sends the message back to the server,
# which then sends the message back to the original client. The original client then hashes the message and compares
# the hash to the hash sent by the server. If the hashes match, then the client prints the message to the console.

# The hashes are signed using ECDSA. The client generates a public and private key pair. The client then sends the
# public key to the server. The server then sends the public key to the recipient client. The recipient client then
# uses the public key to verify the signature of the message. The recipient client then sends the message back to the
# server, which then sends the message back to the original client. The original client then verifies the signature
# of the message using the public key of the recipient client.

import rsa
import socket
import sys
import json
import hashlib
import ecdsa
import time
import os
from Crypto.Cipher import AES

# # The client takes the username of the client and the username of the recipient as command line arguments.
# if len(sys.argv) != 3:
#     print("Usage: python3 Client.py <username> <recipient>")
#     sys.exit()

# El cliente genera un par de llaves RSA publica y privada.
public_key, private_key = rsa.newkeys(1024)

# El cliente genera un par de llaves ECDSA publica y privada.
ecdsa_private_key = ecdsa.SigningKey.generate(
    curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
ecdsa_public_key = ecdsa_private_key.get_verifying_key()

# El cliente genera una llave AES.
aes_key = os.urandom(16)
aes_iv = os.urandom(16)

cipher = AES.new(aes_key, AES.MODE_EAX, aes_iv)


# Generar un mensaje cifrado y firmado
def generateMessage(recipient, message):
    ciphertext = cipher.encrypt(message)
    signature = ecdsa_private_key.sign(ciphertext)
    return json.dumps({'recipient': recipient, 'message': ciphertext, 'signature': signature})

# Desencriptar un mensaje con la llave privada compartida


def decryptMessage(response, recipient_ECDSA_public_key) -> str:
    data = json.loads(response.decode())
    try:
        signature = bytes.fromhex(data["signature"])
        ciphertext = bytes.fromhex(data["message"])
        if recipient_ECDSA_public_key.verify(bytes.fromhex(data["signature"]), ciphertext, hashfunc=hashlib.sha256):
            return cipher.decrypt(ciphertext).decode()
        else:
            return False
    except:
        return False


# El cliente se conecta al servidor.
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 9999))

# El cliente envia la llave publica al servidor.
print("Enviando la clave RSA publica", public_key.save_pkcs1())
client_socket.send(public_key.save_pkcs1())

# El cliente recibe la llave publica del servidor.
server_public_key_bytes = client_socket.recv(1024)
print("Recibiendo la clave RSA publica", server_public_key_bytes)
server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_bytes)

# El cliente envia la llave publica ECDSA al servidor.
print("Enviando la clave ECDSA publica: ", ecdsa_public_key.to_string().hex())
client_socket.send(rsa.encrypt(
    ecdsa_public_key.to_string(), server_public_key))

# El cliente recibe la llave publica ECDSA del servidor.
ecsda_response = client_socket.recv(1024)
server_ecdsa_public_key = ecdsa.VerifyingKey.from_string(
    rsa.decrypt(ecsda_response, private_key), curve=ecdsa.SECP256k1)
print("Recibiendo la clave ECDSA publica",
      server_ecdsa_public_key.to_string().hex())

# El cliente envia la llave AES al servidor.
print("Enviando la clave AES: ", aes_key.hex(), aes_iv.hex())
ciphertext = rsa.encrypt(json.dumps(
    {"aes_key": aes_key.hex(), "aes_iv": aes_iv.hex()}).encode(), server_public_key)
json_message = json.dumps({"message": ciphertext.hex(), "signature": ecdsa_private_key.sign(
    ciphertext, hashfunc=hashlib.sha256).hex()})
client_socket.send(json_message.encode())

# El cliente recibe una confirmacion del servidor.
if decryptMessage(client_socket.recv(1024), server_ecdsa_public_key) == "OK":
    print("Connection established.")

# # The cliente envia el nombre de usuario del cliente al servidor.
# client_socket.send(sys.argv[1].encode())

# # The cliente envia el nombre de usuario del destinatario al servidor.
# client_socket.send(sys.argv[2].encode())

# # The cliente recibe la llave publica RSA del destinatario del servidor.
# recipient_RSA_public_key = client_socket.recv(1024)

# # The cliente recibe la llave publica ECDSA del destinatario del servidor.
# recipient_ECDSA_public_key = client_socket.recv(1024)

# # The client receives the username of the recipient from the server.
# recipient = client_socket.recv(1024).decode()

# # The cliente encripta el mensaje con la llave publica RSA del destinatario.
# message = input("Enter message: ")
# ciphertext = rsa.encrypt(
#     message.encode(), rsa.PublicKey.load_pkcs1(recipient_RSA_public_key))

# # The cliente firma el mensaje con la llave privada ECDSA del cliente.
# signature = sk.sign(ciphertext)

# # The client sends the message to the server.
# client_socket.send(ciphertext.encode())

# # The client receives the message from the server.
# message = client_socket.recv(1024).decode()

# # The client receives the signature of the message from the server.
# signature = client_socket.recv(1024)

# # The client receives the hash of the message from the server.
# hash = client_socket.recv(1024)

# # The client verifies the signature of the message using the public key of the recipient client.
# try:
#     rsa.verify(message.encode(), signature,
#                rsa.PublicKey.load_pkcs1(recipient_public_key))
#     print("Signature verified")
# except:
#     print("Signature not verified")

# # The client hashes the message.
# hash_object = hashlib.sha256(message.encode())
# hash = hash_object.hexdigest()

# # The client compares the hash to the hash sent by the server.
# if hash == hash.decode():
#     print("Hashes match")
# else:
#     print("Hashes do not match")

# # The client sends the message back to the server.
# client_socket.send(message.encode())

# # The client sends the signature of the message back to the server.
# client_socket.send(signature)

# # The client sends the hash of the message back to the server.
# client_socket.send(hash.encode())

# # The client receives the message from the server.
# message = client_socket.recv(1024).decode()

# # The client receives the signature of the message from the server.
# signature = client_socket.recv(1024)

# # The client receives the hash of the message from the server.
# hash = client_socket.recv(1024)

# # The client verifies the signature of the message using the public key of the recipient client.
# try:
#     rsa.verify(message.encode(), signature,
#                rsa.PublicKey.load_pkcs1(recipient_public_key))
#     print("Signature verified")
# except:
#     print("Signature not verified")

# The client hashes the message.

# hash_object = hashlib.sha256(message.encode())
# hash = hash_object.hexdigest()

# # The client compares the hash to the hash sent by the server.
# if hash == hash.decode():
#     print("Hashes match")
# else:
#     print("Hashes do not match")

# # The client prints the message to the console.
# print(message)

# # The client closes the connection to the server.
# client_socket.close()

# # The client waits for 5 seconds.
# time.sleep(5)

# Encriptar un mensaje con la llave publica del destinatario

# def encrypt(message, public_key):
#     return rsa.encrypt(message.encode("ascii"), public_key)


# # Desencriptar un mensaje con la llave privada del destinatario
# def decrypt(ciphertext, key):
#     try:
#         return rsa.decrypt(ciphertext, key).decode('ascii')
#     except:
#         return False

# # Firmar un mensaje con la llave privada del emisor


# def sign(message, private_key):
#     return ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).sign(message.encode("ascii"))

# # Verificar la firma de un mensaje con la llave publica del emisor


# def verify(message, signature, public_key):
#     try:
#         return ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1).verify(signature, message)
#     except:
#         return False
# Lorem ipsum dolor sit amet, consectetur adipiscing elit. In sit amet ligula at odio posuere pharetra ut ut risus. Curabitur sit amet lectus arcu. Curabitur eget imperdiet urna, sodales laoreet enim. Curabitur at posuere tortor. Nunc in mattis tellus, quis volutpat sem. Integer ultricies sed magna eu volutpat. Quisque arcu lectus, porttitor in ex at, feugiat consectetur turpis. Pellentesque auctor, ante et consequat sollicitudin, diam turpis facilisis ligula, eu sodales leo erat eget leo. Etiam quis faucibus quam. Quisque rutrum, nulla in placerat varius, nunc metus tincidunt augue, nec vehicula diam magna ut felis. Proin eget nisi vel odio ornare molestie. Aliquam eu sodales enim, eget tincidunt libero. Pellentesque eu blandit ante. Aenean vestibulum urna at volutpat iaculis. Duis hendrerit, nibh sed congue tempor, leo nunc finibus est, ut laoreet felis urna ut lorem. Proin mi elit, iaculis convallis ligula vel, aliquam varius metus. Aliquam posuere nulla nisl, a convallis elit bibendum ac. Praesent fermentum non nibh a fermentum. Fusce eleifend velit id vehicula molestie. Quisque iaculis ipsum vel sem posuere rhoncus. Ut egestas augue in sagittis viverra. Cras iaculis leo at elit facilisis dictum id nec massa. Suspendisse vulputate turpis non maximus interdum. Aliquam et lacinia eros. Fusce vel felis aliquet, commodo lectus a, maximus eros. Proin sit amet ornare tellus. Maecenas semper sed turpis ut varius. Proin non justo lorem. Cras vehicula tortor in purus lobortis ornare eu eget sapien. Curabitur vel feugiat arcu, quis rhoncus metus. Sed finibus mi sit amet porttitor egestas. Proin euismod nisi nec ligula commodo, ut rhoncus orci ultricies. Suspendisse non elit sit amet felis commodo semper id sed eros. Aliquam vel quam metus. Nullam blandit eget nunc vel accumsan. Sed feugiat, metus quis dapibus eleifend, eros ligula vulputate lacus, et ultricies felis odio ac eros. Vestibulum vel nibh eget neque consectetur iaculis eu sit amet lorem. Sed a erat mollis, feugiat sem nec, ultricies mauris. Nunc a purus sed orci elementum fermentum. Quisque urna est, pretium convallis neque convallis, pellentesque aliquet felis. Vivamus sed ante sit amet ipsum imperdiet ornare. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Donec tincidunt massa justo, sit amet cursus lectus ultricies sit amet. Aliquam erat volutpat. Mauris vestibulum diam nisl, in commodo nunc ornare vitae. In ut justo nec nulla tempor fermentum ut et sapien. Pellentesque quam lectus, pharetra ac tristique in, porttitor eleifend urna. Quisque rutrum egestas nisl, in sollicitudin purus tempor ut. Vestibulum facilisis justo orci, eget hendrerit tellus lacinia id. Donec ac justo ac sapien pretium aliquam a id libero. Vivamus sagittis auctor diam a molestie. Nullam luctus consectetur ante, sodales lacinia sapien. Nullam venenatis pharetra dui, ac porta justo pulvinar a. Etiam lectus nunc, mollis vitae est in, blandit facilisis lacus. Donec consectetur scelerisque purus, eget bibendum arcu vestibulum ut. Maecenas congue bibendum imperdiet. Vivamus ornare dui a tellus scelerisque vulputate. Aenean eu urna libero. Etiam tristique et ex vitae pellentesque. Sed in vestibulum arcu. Vivamus eleifend nulla sed nulla pellentesque, a consectetur elit vulputate. Ut iaculis mauris semper, luctus lorem id, lacinia sapien. Maecenas a turpis sem. Aliquam sagittis tellus diam, quis auctor tortor mattis non.
