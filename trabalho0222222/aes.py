import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rsa import generate_rsa, encrypt_rsa, decrypt_rsa
import base64

def generate(message,bloco,hah,pu):
	backend = default_backend()
	#file = open("testfile10.txt","wb") 
	salt = os.urandom(16)
	iv = os.urandom(16)
	#file.write(salt)
	#file.write(iv)
	#file.close()
	
	if hah=="SHA256":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
	elif hah=="SHA224":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA224(),length=32,salt=salt,iterations=100000,backend=backend)
	key = kdf.derive(b"my great password")
	if bloco=="CBC":
		padder = padding.PKCS7(128).padder()
		message = padder.update(message)
		message += padder.finalize()
		#unpadder = padding.PKCS7(128).unpadder()
		#message = unpadder.update(message)
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	elif bloco=="CTR":
		cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
	encryptor = cipher.encryptor()
	ct = encryptor.update(message) + encryptor.finalize()
	
	h = encrypt_rsa(pu, salt + iv)
	final = base64.b64encode(h + ct)
	return final
	
	

def decrypt(ct,bloco,hah, pr):
	backend = default_backend()
	#file = open(testfile,"rb") 
	#salt=file.read(16)
	#iv=file.read(16)
	ct=base64.b64decode(ct)
	h= decrypt_rsa(ct[:256],pr)
	
	salt = h[:16]
	iv = h[16:32]
	ct = ct[256:]
	
	if hah=="SHA256":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
	elif hah=="SHA224":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA224(),length=32,salt=salt,iterations=100000,backend=backend)
	key = kdf.derive(b"my great password")
	if bloco=="CBC":
		
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		decryptor = cipher.decryptor()
		t= decryptor.update(ct) + decryptor.finalize()
		unpadder = padding.PKCS7(128).unpadder()
		ct = unpadder.update(t)
		ct += unpadder.finalize()
		return ct
	elif bloco=="CTR":
		cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
		decryptor = cipher.decryptor()
		t= decryptor.update(ct) + decryptor.finalize()
		return t
	
def pad(mesage):
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(mesage)
	padded_data += padder.finalize()
	unpadder = padding.PKCS7(128).unpadder()
	data = unpadder.update(padded_data)
	return data
	
	

	
#pr , pu = generate_rsa() 	
#hah="SHA224" #pode ser sha256
#mensagem = b"testeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#bloco="CBC" #pode sr cbc
#if bloco=="CBC":
#	m=pad(mensagem)
#	enc =generate(m,bloco,hah, pu)
#elif bloco=="CTR":
#	enc =generate(mensagem,bloco,hah, pu)
#print(enc)
#dec=decrypt(enc, bloco,hah, pr)
#print(dec)
