import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rsa import generate_rsa, encrypt_rsa, decrypt_rsa
import base64


def generate(message,hah, pu):
	backend = default_backend()
	salt = os.urandom(16)
	
	nonce = os.urandom(16)
	
		
	if hah=="SHA256":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
	elif hah=="SHA224":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA224(),length=32,salt=salt,iterations=100000,backend=backend)
	
	key = kdf.derive(b"my great password")
	algorithm = algorithms.ChaCha20(key, nonce)
	cipher = Cipher(algorithm, mode=None, backend=default_backend())
	encryptor = cipher.encryptor()
	ct = encryptor.update(message)
	
	h = encrypt_rsa(pu, salt + nonce)
	final = base64.b64encode(h + ct)
	return final
	
	

def decrypt(ct,hah,pr):
	backend = default_backend()
	ct=base64.b64decode(ct)
	h= decrypt_rsa(ct[:256],pr)
	
	salt = h[:16]
	nonce = h[16:32]
	ct = ct[256:]
	
	
	if hah=="SHA256":	
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=backend)
	elif hah=="SHA224":
		kdf = PBKDF2HMAC(algorithm=hashes.SHA224(),length=32,salt=salt,iterations=100000,backend=backend)
	key = kdf.derive(b"my great password")
	algorithm = algorithms.ChaCha20(key, nonce)
	cipher = Cipher(algorithm, mode=None, backend=default_backend())
	decryptor = cipher.decryptor()
	t=decryptor.update(ct)
	return t
	
#pr , pu = generate_rsa() 	
	
#hah="SHA224" #pode ser sha256
#mensagem = b"testeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#c = generate(mensagem,hah,pu)
#print(c)
#dec=decrypt(c,hah,pr)
#print(dec)
