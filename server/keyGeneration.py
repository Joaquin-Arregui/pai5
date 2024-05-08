import sqlite3
import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_client_id():
    return '_'.join(''.join(random.choices(string.ascii_lowercase + string.digits, k=4)) for _ in range(4))


def init_db():
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    # Create the client table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS client
                 (nClient TEXT PRIMARY KEY, rsaKey BLOB)''')
    conn.commit()
    conn.close()


def insert_public_key(nClient, rsaKey):
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute("INSERT INTO client (nClient, rsaKey) VALUES (?, ?)", (nClient, rsaKey))
    conn.commit()
    conn.close()


def generate_key_pairs(num_keys):
    key_pairs = []
    for _ in range(num_keys):
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Serialize private key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Generate public key
        public_key = private_key.public_key()
        # Serialize public key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_id = generate_client_id()
        key_pairs.append((client_id, pem_public.decode('utf-8'), pem_private.decode('utf-8')))
    return key_pairs


def save_keys_to_file(key_pairs):
    for nClient, _, pem_private in key_pairs:
        # Save each private key in a separate .pem file named by client number
        with open(f"private_key_{nClient}.pem", "w") as file:
            file.write(pem_private)


# Initialize database
init_db()

# Generate 10 RSA key pairs
key_pairs = generate_key_pairs(2)

# Insert public keys into the database and save private keys to individual .pem files
for nClient, pem_public, pem_private in key_pairs:
    insert_public_key(nClient, pem_public)
    save_keys_to_file([(nClient, pem_public, pem_private)])

print("Public keys stored in database and private keys stored in individual .pem files.")
