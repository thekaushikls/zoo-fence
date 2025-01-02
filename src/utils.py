from os import urandom
from hashlib import pbkdf2_hmac
from base64 import b64encode, b64decode

# - - - - CONFIG
MIN_PASSWORD_LENGTH = 8

# - - - - METHODS
def hash_password(password: str, base64_encoded_salt: str = "") -> tuple[str, str]:
    if base64_encoded_salt and len(base64_encoded_salt) > 0:
        salt = b64decode(base64_encoded_salt)
    else:
        salt = urandom(16)
        base64_encoded_salt = b64encode(salt).decode()
    
    hashed_password = pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    base64_encoded_hash = b64encode(hashed_password).decode()
    return base64_encoded_hash, base64_encoded_salt

def map_mongo_id(doc: dict) -> dict:
    key = "_id"
    if(key in doc.keys()):
        doc["_id"] = str(doc["_id"])
        return doc
    else:
        raise TypeError("Argument is not a valid Mongo Document")
