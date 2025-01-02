from re import match as regex_match
from bson import ObjectId
from cryptography.fernet import Fernet
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

def generate_encryption_key() -> bytes:
    return Fernet.generate_key()

def encrypt(data: str, key: bytes) -> bytes:
    encrypted_data = Fernet(key).encrypt(data.encode())
    return encrypted_data

def decrypt(data: bytes, key: bytes) -> str:
    decrypted_data = Fernet(key).decrypt(data).decode()
    return decrypted_data

def is_mongo_doc(doc: dict) -> bool:
    return isinstance(doc, dict) and "_id" in doc and isinstance(doc["_id"], ObjectId)

def map_mongo_id(doc: dict) -> dict:
    key = "_id"
    if(key in doc.keys()):
        doc["_id"] = str(doc["_id"])
        return doc
    else:
        raise TypeError("Argument is not a valid Mongo Document")

def strip_email_tag(email: str) -> dict[str]:
    pattern = r"([A-Z0-9a-z._-]+)(\+{1}([A-Z0-9a-z_-]*))?@{1}([A-Z0-9a-z._-]+)"
    match = regex_match(pattern, email)
    
    if match is None:
        raise ValueError("Not a valid email id.")
    
    groups = match.groups()
    return  { 
        "email" : "{}{}".format(groups[0], groups[3]),
        "tag"   : groups[1]
    }
        