import os
import base64
import hashlib
from Crypto.Cipher import AES


# ---------- Utils base64 / sel ----------

def generate_salt(length: int = 16) -> bytes:
    """Génère un sel cryptographique aléatoire (par défaut 16 octets)."""
    return os.urandom(length)


def b64encode_bytes(data: bytes) -> str:
    """Encode des octets en base64 (retourne une str)."""
    return base64.b64encode(data).decode("utf-8")


def b64decode_str(data: str) -> bytes:
    """Décode une string base64 en bytes."""
    return base64.b64decode(data.encode("utf-8"))


# ---------- SHA-256 pour le master password ----------

def sha256_with_salt(password: str, salt: bytes) -> str:
    """
    Calcule SHA-256(password + salt) avec hashlib,
    puis renvoie le résultat encodé en base64.
    """
    digest = hashlib.sha256(password.encode("utf-8") + salt).digest()
    return b64encode_bytes(digest)


# ---------- PBKDF2-HMAC-SHA256 pour la clé AES ----------

def derive_aes_key(master_password: str, salt: bytes) -> bytes:
    """
    Dérive une clé AES-256 via PBKDF2-HMAC-SHA256 (lib standard).
    - 100000 itérations
    - sel de 16 octets
    - clé finale = 32 octets (AES-256)
    """
    key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        100000,
        dklen=32,
    )
    return key


# ---------- Chiffrement / déchiffrement AES-256-GCM ----------

def encrypt_password(plain_password: str, aes_key: bytes) -> str:
    """
    Chiffre un mot de passe avec AES-256-GCM (PyCryptodome).
    Renvoie la concaténation : nonce + tag + ciphertext, encodée base64.
    """
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_password.encode("utf-8"))

    # Format : [nonce(16) | tag(16) | ciphertext]
    blob = cipher.nonce + tag + ciphertext
    return b64encode_bytes(blob)


def decrypt_password(enc_b64: str, aes_key: bytes) -> str:
    """
    Déchiffre le mot de passe stocké.
    Prend base64 -> bytes -> reconstruit nonce/tag/ciphertext -> déchiffre.
    """
    raw = b64decode_str(enc_b64)

    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ciphertext, tag)

    return plain.decode("utf-8")
