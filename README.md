# ProyectoSD

## Descripción

El sistema consiste en una aplicación de mensajes entre dos clientes. Para realizar la conexión entre los clientes, existe un servidor al que se conectan los clientes para obtener la información de el destinatario y poder conectarse directamente.

El servidor actúa como un intermediario que obtiene la información de un cliente y la almacena hasta que otro cliente la solicite para conectarse a él.

La conexión entre el servidor, los clientes, y entre clientes, es cifrada progresivamente. El protocolo de conexión de un cliente al servidor es el siguiente:

1. El cliente envía al servidor su clave pública RSA de 1024 bits.
2. El servidor responde con su clave pública RSA de 1024 bits.
3. El cliente envía al servidor su clave pública ECDSA, cifrada con la clave pública del servidor.
4. El servidor responde con su clave pública ECDSA, cifrada con la clave pública del cliente.
5. El cliente envía al servidor la clave compartida para el cifrado AES, junto con el vector de inicialización, cifrado con la clave pública del servidor y firmado con la clave privada del servidor.
6. Si el servidor confirma que la firma es válida, responde al cliente con un mensaje de confirmación. A partir de este punto, los mensajes son cifrados con AES en vez de RSA, y son firmados con las respectivas claves privadas.
7. Si cliente verifica el mensaje de confirmación del servidor, envía la información de los puertos destinados para el envío y recepción de mensajes con otro cliente.
8. El servidor responde con un mensaje de confirmación.

Una vez establecida la conexión entre el servidor y el cliente, éste le solicita al servidor la información del cliente destino, para poder realizar la conexión directamente.

Si existe algún usuario que coincida con el solicitado, el servidor envía su información (llave RSA, ECDSA, AES, y puertos) y la descarta. Una vez enviada la información, el trabajo del servidor ha terminado, por lo que cierra la conexión con el cliente. Si no existe un cliente que coincida, el servidor espera a que se conecte, y posteriormente envía la información al cliente solicitante. El cliente solicitante se queda a la espera de la información hasta que el servidor responda, es decir, hasta que se registre un usuario que coincida con el solicitado.

Posteriormente, el cliente comienza a escuchar mensajes en el puerto destinado a ello, e intenta abrir una conexión con el cliente destino hasta que se establezca la conexión.

El cliente destino, por su parte, realiza el mismo proceso que el otro cliente, y no acepta conexiónes hasta que no haya recibido la información de conexión de su cliente destino.

Una vez ambos clientes están escuchando, se establece la conexión bidireccional, y dado que cuentan con un puerto para envío y un puerto para recepción, el flujo de información no necesariamente es secuencial, si no que un cliente puede enviar tantos mensajes como quiera sin necesidad de esperar por una respuesta.

Adicionalmente, el cliente puede enviar mensajes al servidor, el cual responde siempre a los mensajes con "OK".

## Instalación

Para instalar el sistema, sólo es necesario tener instalado Python 3.8 o más reciente y el instalador de paquetes pip

1. Descargue el código fuente
2. Instale los módulos necesarios

   > Opcional
   >
   > Cree un entorno virtual de python ejecutando
   >
   > ```bash
   > python -m venv ./venv
   > ```
   >
   > Y actívelo con
   >
   > ```bash
   > ./venv/Scripts/activate
   > ```

   ```bash
   pip install -r requirements.txt
   ```

## Uso

Una vez instalados los módulos requeridos, basta con iniciar el servidor y un cliente, ejecutando en terminales diferenteS:

```bash
python Server.py
```

y

```bash
python Client.py
```

El cliente imprime los puertos asignados y espera la acción del usuario para iniciar el protocolo. El envío y recepción de mensajes del protocolo se realiza automáticamente, imprimiendo la información enviada y recibida durante el proceso.

Una vez establecida la conexión segura, el usuario introduce un nombre con el cual será identificado por el resto de clientes, y posteriormente solicita la información de otro cliente, o del servidor en este caso, introduciendo 'server' como usuario a enviar los mensajes.

Cuando dos usuarios están conectados y solicitan conectarse entre sí, una vez el servidor haya enviado la información del otro cliente, cada cliente hace la respectiva conexión, y se da inicio a la conversación entre los dos clientes, siendo que los mensajes están firmados por el cliente que envía, y cifrados con la clave AES del cliente que recibe.
