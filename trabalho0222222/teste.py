from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography.x509 import ocsp, load_pem_x509_certificate
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import load_pem_public_key


#key = rsa.generate_private_key( public_exponent=65537, key_size=2048, backend=default_backend())


def generate_rsa():
	private_key = rsa.generate_private_key( public_exponent=65537, key_size=2048, backend=default_backend())
	public_key = private_key.public_key()
	return private_key, public_key

def store_privateKey(key, password):
    with open("private_key.pem", "wb") as f:
    	f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(str.encode(password)),))


def store_publicKey(public_key):
	pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	with open('public_key.pem', 'wb') as f:
		f.write(pem)

def load_pem(path, password):
	with open(path, "rb") as key_file:
		private_key = serialization.load_pem_private_key(key_file.read(),password=str.encode(password), backend=default_backend())
	return private_key

def generate_cert(key):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(key, hashes.SHA256(), default_backend())
    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open("certificate.pem", "rb") as c:
        certificate=c.read()

path="private_key.pem"
password="vasco"
private_key, public_key = generate_rsa()
store_publicKey(public_key)
store_privateKey(private_key, password)
private_k=load_pem(path, password)
generate_cert(private_k)


