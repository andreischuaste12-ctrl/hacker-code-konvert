import hashlib

hashlib.scrypt(b"password", salt=b"salt", n=16384, r=8, p=1)
