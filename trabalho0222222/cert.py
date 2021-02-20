import PyKCS11
import binascii
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from  cryptography.x509.oid import *
import datetime


def verificaEC(ca):
    try:
        if ca.not_valid_before < datetime.datetime.utcnow() < ca.not_valid_after:
            cn = ca.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuerid = cn[0].value[-4:]
            c= open("/home/user/Desktop/teste/guiao06/PTEID/pem/EC de Aute ticacao do Cartao de Cidadao "+issuerid+".pem", "rb")
            print(c)
            issuer_public_key=x509.load_pem_x509_certificate(c.read(), default_backend())
            #print(issuer_public_key)
            cert_to_check = ca
            issuer_public_key.public_key().verify(cert_to_check.signature,cert_to_check.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_check.signature_hash_algorithm,)
    except InvalidSignature:
        print("falhou")
    print("passou")
    y=verificaCA(issuer_public_key)
    return y

def verificaCA(ca):
    try:
        if ca.not_valid_before < datetime.datetime.utcnow() < ca.not_valid_after:
            cn = ca.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuerid = cn[0].value[-3:]
            c= open("/home/user/Desktop/teste/guiao06/PTEID/pem/Cartao de Cidadao "+issuerid+".pem", "rb")
            print(c)
            issuer_public_key=x509.load_pem_x509_certificate(c.read(), default_backend())
            #print(issuer_public_key)
            cert_to_check = ca
            issuer_public_key.public_key().verify(cert_to_check.signature,cert_to_check.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_check.signature_hash_algorithm,)
    except InvalidSignature:
        print("falhou")
    print("passou")
    x=verificaADO(issuer_public_key)
    return x

def verificaADO(ca):
    try:
        if ca.not_valid_before < datetime.datetime.utcnow() < ca.not_valid_after:
            c= open("/home/user/Desktop/teste/guiao06/PTEID/pem/ecraizestado.pem", "rb")
            print(c)
            issuer_public_key=x509.load_pem_x509_certificate(c.read(), default_backend())
            #print(issuer_public_key)
            cert_to_check = ca
            issuer_public_key.public_key().verify(cert_to_check.signature,cert_to_check.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_check.signature_hash_algorithm,)
    except InvalidSignature:
        print("falhou")
    print("passou")
    return True


        
         

    
def accessCert():    

    lib = '/usr/local/lib/libpteidpkcs11.so'
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    public_key = None
    private_key = None
    for slot in slots:

        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]
        session = pkcs11.openSession(slot)
        for obj in session.findObjects():
            attr = session.getAttributeValue(obj, all_attr)
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
            if attr['CKA_CLASS'] is not None and attr['CKA_CERTIFICATE_TYPE'] is not None:
                ca = bytes(attr['CKA_VALUE'])
                ca = x509.load_der_x509_certificate(ca, default_backend())
                test = ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                key_usage = ca.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if key_usage.value.digital_signature is True:
                    print(ca)
                    ca=ca.public_bytes(encoding=serialization.Encoding.DER)
                    #z=verificaEC(ca)
                    #print(z)
                    return ca


#primeiro ec, depois ca

