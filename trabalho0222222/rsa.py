from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def generate_rsa():
	private_key = rsa.generate_private_key( public_exponent=65537, key_size=2048, backend=default_backend())
	public_key = private_key.public_key()
	return private_key, public_key


def store_privateKey(private_key, password):
	pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(str.encode(password)))
	with open('private_key.pem', 'wb') as f:
		f.write(pem)
	

def store_publicKey(public_key):
	pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	with open('public_key.pem', 'wb') as f:
		f.write(pem)





def encrypt_rsa(public_key, message):
	encrypted = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	#print (encrypted)
	return encrypted


def decrypt_rsa(enc, private_key):
	original_message = private_key.decrypt(enc, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))
	print (original_message)
	return original_message

def load_pem(path, password):
	with open(path, "rb") as key_file:
		private_key = serialization.load_pem_private_key(key_file.read(),password=str.encode(password), backend=default_backend())
	print(private_key)
	return private_key



#path="private_key.pem"
password="vasco"
#message = b'encrypt me!'
#private_key, public_key = generate_rsa()
#store_publicKey(public_key)
#store_privateKey(private_key, password)
#enc = encrypt_rsa(public_key, message)
#dec = decrypt_rsa(enc, private_key)
#load_pem(path, password)
