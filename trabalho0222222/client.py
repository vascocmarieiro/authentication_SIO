import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import aes
import chacha20
import PyKCS11
import binascii
import sign
import cert
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import datetime
import otp_client



logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.cifra=None
        self.hah=None
        self.bloco=None
        self.chave=None
        self.signature=None
        self.chal=None
        self.chall=False
        self.aut=None

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        
        
        aux ='1'
        while aux !='0':
            print("Tipo de autenticacao")
            self.aut = input ("Introduza a autenticacao: ")
            if self.aut=="CC":
                w=otp_client.otp()
                self._send({"type":"CC", "val":base64.b64encode(w).decode()})
                aux='0'
            elif self.aut=="OTP":
                w=otp_client.otp()
                self._send({"type":"OTP", "val":base64.b64encode(w).decode()})
                aux='0'
        
        
        
        #self.cifra = input("Introduza cifra: ")

        #self.bloco = input("Introduza bloco: ")
        #self.hah = input("Introduza hash: ")
        
        #message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah}
        #self._send(message)

        #self.state = STATE_OPEN
        aux ='1'
        while aux !='0':
            print("cifra: AES ou CHACHA20")
        

            self.cifra = input ("Introduza a cifra: ")

            if self.cifra == "AES":
                self.bloco= input ("Bloco: CBC ou CTR ")
                if self.bloco =="CBC":
                    self.hah= input ("HASH: SHA224 ou SHA256 ")
                    if self.hah=="SHA224":
                        message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah, 'sign':self.signature}
                        self._send(message)
                        self.state = STATE_OPEN
                        aux='0'
                    elif self.hah=="SHA256":
                        message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah}
                        self._send(message)
                        self.state = STATE_OPEN
                        aux='0'
                    else :
                        print("invalido")
                        aux='1'
                elif self.bloco=="CTR":
                    self.hah= input ("HASH: SHA224 ou SHA256 ")
                    if self.hah=="SHA224":
                        message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah}
                        self._send(message)
                        self.state = STATE_OPEN
                        aux='0'
                    elif self.hah=="SHA256":
                        message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah}
                        self._send(message)
                        self.state = STATE_OPEN
                        aux='0'
                    else :
                        print("invalido")
                        aux='1'
                else:
                    print("invalido")
                    aux='1'
            elif self.cifra =="CHACHA20":
                self.hah= input ("HASH: SHA224 ou SHA256 ")
                if self.hah=="SHA224":
                    message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah}
                    self._send(message)
                    self.state = STATE_OPEN
                    aux='0'
                elif self.hah=="SHA256":
                    message = {'type': 'OPEN', 'file_name': self.file_name , 'tipo':self.cifra, 'b':self.bloco, 'hah':self.hah}
                    self._send(message)
                    self.state = STATE_OPEN
                    aux='0'
                else :
                    print("invalido")
                    aux='1'

        
            else:
                print("invalido")
                aux='1'

       
    def verfi(self, sign, message):
        with open("certificate.pem", "rb") as f:
            t=x509.load_pem_x509_certificate(f.read(),default_backend())
        
        if t.not_valid_before < datetime.datetime.utcnow() < t.not_valid_after:
            try:
                t.public_key().verify(t.signature, t.tbs_certificate_bytes, padding.PKCS1v15(),t.signature_hash_algorithm)
            except InvalidSignature:
                return False
        else:
            return False
        try:
            t.public_key().verify(sign,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except: InvalidSignature
        return True


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        print(data)
        sign=data[-256:]
        #servidor está sempre a assinar
        data = data[:len(data)-256]
        x=self.verfi(sign, data)
        if x==False:
            self.loop.stop() 

        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

   

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.chave=message["pk"].encode()
                server_pub = serialization.load_pem_public_key(self.chave,backend=default_backend())
                self.chave=server_pub
                #print(self.chave)
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return
        elif mtype=="challenge":
            
            t=message["random"]
            t=sign.sign(t)
            c=cert.accessCert()
            self._send({"type":"challenge",'challengeAss': base64.b64encode(t).decode(), "certificado":base64.b64encode(c).decode()})
            self.chall=True
        elif mtype == 'Challenge OK':
            self.chall=True
        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        #self.transport.close()
        #self.loop.stop()
        
        
       

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:

        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
       
         
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        if self.state == STATE_OPEN and self.chall==True:
            if self.cifra == "AES":
                message_b=aes.generate(message_b, self.bloco, self.hah, self.chave)
            if self.cifra=="CHACHA20":
                message_b=chacha20.generate(message_b,self.hah, self.chave)
            if self.aut=="CC":
                message_b+=sign.sign(message_b)
            self.state=STATE_DATA
            
        elif self.state== STATE_OPEN and self.chall==False:
            pass

        elif self.state== STATE_DATA:
            if self.cifra == "AES":
                message_b=aes.generate(message_b, self.bloco, self.hah, self.chave)
            if self.cifra=="CHACHA20":
                message_b=chacha20.generate(message_b,self.hah, self.chave)

        self.transport.write(message_b)
        
        
    
    


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()

