import getpass
from typing import Optional, Tuple

from . import crypto
from . import database


def prompt_master_password(username: str) -> str:
    """Demande le mot de passe principal de l'utilisateur en mode caché."""
    prompt = f"/!\\ Enter {username} master password: "
    return getpass.getpass(prompt)


def register_user(username: str) -> None:
    """
    Enregistre un nouvel utilisateur :
    - génère un sel pour SHA-256
    - génère un sel pour PBKDF2
    - calcule et stocke le hash du master password
    """
    master_password = prompt_master_password(username)

    # Génération des sels (16 octets chacun)
    salt = crypto.generate_salt(16)
    aes_salt = crypto.generate_salt(16)

    # Hash du mot de passe principal (SHA-256 + sel, puis base64)
    password_hash = crypto.sha256_with_salt(master_password, salt)

    salt_b64 = crypto.b64encode_bytes(salt)
    aes_salt_b64 = crypto.b64encode_bytes(aes_salt)

    created = database.create_user(username, password_hash, salt_b64, aes_salt_b64)
    if not created:
        print(f"Error: user {username} already exists.")


def verify_user_credentials(username: str) -> Optional[Tuple[int, bytes]]:
    """
    Vérifie les identifiants de l'utilisateur.
    - récupère l'utilisateur
    - redemande le master password
    - compare le hash
    - dérive la clé AES si OK
    Retourne (user_id, aes_key) ou None en cas d'erreur.
    """
    user = database.get_user(username)
    if user is None:
        print(f"Error: user {username} does not exist.")
        return None

    user_id, stored_hash, salt_b64, aes_salt_b64 = user
    salt = crypto.b64decode_str(salt_b64)
    aes_salt = crypto.b64decode_str(aes_salt_b64)

    master_password = prompt_master_password(username)
    computed_hash = crypto.sha256_with_salt(master_password, salt)

    if computed_hash != stored_hash:
        print("Error: invalid master password.")
        return None

    aes_key = crypto.derive_aes_key(master_password, aes_salt)
    return user_id, aes_key


def add_password(username: str, label: str, plain_password: str) -> None:
    """
    Ajoute (ou met à jour) un mot de passe pour un utilisateur donné.
    """
    result = verify_user_credentials(username)
    if result is None:
        return
    user_id, aes_key = result

    enc_password = crypto.encrypt_password(plain_password, aes_key)
    database.save_password(user_id, label, enc_password)
    print(f"--> password {label} successfully saved!")


def show_password(username: str, label: str) -> None:
    """
    Affiche un mot de passe en clair pour un utilisateur et un label donnés.
    """
    result = verify_user_credentials(username)
    if result is None:
        return
    user_id, aes_key = result

    enc = database.get_password_enc(user_id, label)
    if enc is None:
        print(f"Error: label {label} not found for user {username}.")
        return

    try:
        plain = crypto.decrypt_password(enc, aes_key)
    except Exception:
        print("Error: unable to decrypt password.")
        return

    print(f"--> password {label} is: {plain}")
