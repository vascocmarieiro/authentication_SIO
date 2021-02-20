#import pyotp

#totp = pyotp.TOTP('base32secret3232')
#print(totp.now()) 


import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1


	
def otp(w):
	f = open('pass.txt', 'rb')
	key = f.read()
	totp = TOTP(key, 8, SHA1(), 30, backend=default_backend())
	time_value = time.time()
	totp_value = totp.generate(time_value)
	print(totp_value)
	return totp_value==w
