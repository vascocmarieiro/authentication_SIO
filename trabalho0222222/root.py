from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import rsa


private_key, public_key = rsa.generate_rsa()

def save_key (private_key) :
    with open("key.pem", "wb") as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(b"vasco"),))
	f.close()
def generate_cert(private_key):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(private_key, hashes.SHA256(), default_backend())
    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
	f.close()

private_key, public_key = rsa.generate_rsa()
save_key
generate_cert