# SecurePasswordManager
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import getpass

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"

def derive_key(password, salt):
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID
    )

def setup_master_password():
    password = getpass.getpass("Create master password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(SALT_FILE, "wb") as f:
        f.write(salt)

    encrypt_vault({}, key)
    print("Vault created securely.")

def encrypt_vault(data, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)

    with open(VAULT_FILE, "wb") as f:
        f.write(nonce + encrypted)

def unlock_vault():
    password = getpass.getpass("Enter master password: ")

    with open(SALT_FILE, "rb") as f:
        salt = f.read()

    key = derive_key(password, salt)

    try:
        with open(VAULT_FILE, "rb") as f:
            data = f.read()
        nonce, encrypted = data[:12], data[12:]
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
        return json.loads(decrypted)
    except:
        print("Access denied.")
        return None

if not os.path.exists(VAULT_FILE):
    setup_master_password()

vault = unlock_vault()

if vault is not None:
    print("Vault unlocked successfully.")

