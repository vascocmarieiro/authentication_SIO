import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import aes
import chacha20
import cert
import random
import string
from cryptography import x509
from cryptography.exceptions import InvalidSignature
import otp_server




logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE= 3

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''
		self.tipo=None 
		self.b=None 
		self.h=None
		self.private_key=None
		self.d=None
		self.x=None
		self.cert=None
		self.str="dsfhfdkzh"
		self.chall=False
		self.aut=None
		self.val=None

	

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT
		

	def sign_message(self, message):
		private_key=rsa.load_pem("private_key.pem","vasco")
		signature = private_key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
		return signature
		

	def data_received(self, data: bytes) -> None:
		if self.state == STATE_OPEN and self.chall==True: 
			print(data)
			sign=data[-256:]
			y=cert.verificaEC(self.cert)
			if y== True:
				data = data[:len(data)-256]
				print(sign)
				if self.tipo=="AES":
					data=aes.decrypt(data, self.b, self.h, self.private_key)
				if self.tipo=="CHACHA20":
					data=chacha20.decrypt(data, self.h, self.private_key)
				print(data)
			else:
				print("Nao confiavel")
		elif self.state == STATE_OPEN and self.chall==False:
			pass
		elif self.state ==STATE_DATA:
			print(data)
			if self.tipo=="AES":
				data=aes.decrypt(data, self.b, self.h, self.private_key)
			if self.tipo=="CHACHA20":
				data=chacha20.decrypt(data, self.h, self.private_key)

		"""
        Called when data is received from the client.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
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
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()

		if mtype == 'OPEN':
			ret = self.process_open(message)
		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)
		elif mtype=='CHALLENGE':
			ret=self.challenge_open(message)
		elif mtype == 'CC':
			ret=self.fun_cc(message)
		elif mtype== 'OTP':
			ret=self.fun_otp(message)
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()

	def fun_cc(self, message: str) -> bool:
		self.val=base64.b64decode(message["val"])
		s=otp_server.otp(self.val)
		if s is True:
			message={"type":"challenge", "random":self.str}
			self._send(message)
			return True
		else:
			self.transport.close()


	def fun_otp(self, message: str) -> bool:
		self.val=base64.b64decode(message["val"])
		print(self.val)
		s=otp_server.otp(self.val)
		if s is True:
			message={"type":'Challenge OK'}
			self._send(message)
			return True
		else:
			print("invalido")
			self.transport.close()






	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False
		
		print(message)
		
		
		self.tipo=message["tipo"]
		self.b=message["b"]
		self.h=message["hah"]	

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self.private_key, public_key = rsa.generate_rsa()
		public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
		self._send({'type': 'OK', 'pk':public_pem.decode()})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			print("ficheiro")
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True
	def challenge_open(self, message : str) -> bool:
		print(message)
		t=base64.b64decode(message['challengeAss'])
		self.cert=x509.load_der_x509_certificate(base64.b64decode(message["certificado"]), default_backend())
			
		print(t)
		print(self.cert)
		try:
			self.cert.public_key().verify(t, bytes(self.str, encoding='utf-8'), padding.PKCS1v15(), hashes.SHA1())
		except InvalidSignature:
			self.transport.close()
			
		self.chall=True
		#self._send({"type":'Challenge OK'})
		return True

	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		return True


	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		print(message)
		
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()

		if self.state==STATE_CONNECT:
			print("Assinar")
			message_b+=self.sign_message(message_b)
		self.transport.write(message_b)
	


def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


