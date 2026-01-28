import os
import sqlite3
from typing import Optional, Tuple

from dotenv import load_dotenv

# Charge les variables d'environnement depuis .env s'il existe
load_dotenv()

# Chemin de la base SQLite dans le dossier db/
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "data.sqlite")


def ensure_db_directory() -> None:
    """S'assure que le dossier db/ existe."""
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """Retourne une connexion SQLite avec les foreign keys activées."""
    ensure_db_directory()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    """Crée les tables si elles n'existent pas déjà."""
    conn = get_connection()
    cur = conn.cursor()

    # Table des utilisateurs
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            aes_salt TEXT NOT NULL
        );
        """
    )

    # Table des mots de passe
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            password_enc TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, label)
        );
        """
    )

    conn.commit()
    conn.close()


def create_user(username: str, password_hash: str, salt_b64: str, aes_salt_b64: str) -> bool:
    """
    Crée un nouvel utilisateur.
    Retourne True si OK, False si le username existe déjà.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, aes_salt) VALUES (?, ?, ?, ?);",
            (username, password_hash, salt_b64, aes_salt_b64),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # username déjà existant
        return False
    finally:
        conn.close()


def get_user(username: str) -> Optional[Tuple[int, str, str, str]]:
    """
    Retourne (id, password_hash, salt_b64, aes_salt_b64) pour un username donné,
    ou None si l'utilisateur n'existe pas.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, password_hash, salt, aes_salt FROM users WHERE username = ?;",
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    if row is None:
        return None
    return row[0], row[1], row[2], row[3]


def save_password(user_id: int, label: str, password_enc: str) -> None:
    """
    Sauvegarde (ou met à jour) un mot de passe chiffré pour un utilisateur et un label.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO passwords (user_id, label, password_enc)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, label) DO UPDATE SET password_enc = excluded.password_enc;
        """,
        (user_id, label, password_enc),
    )
    conn.commit()
    conn.close()


def get_password_enc(user_id: int, label: str) -> Optional[str]:
    """
    Retourne la version chiffrée du mot de passe pour un (user_id, label),
    ou None si aucun mot de passe n'est trouvé.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT password_enc FROM passwords WHERE user_id = ? AND label = ?;",
        (user_id, label),
    )
    row = cur.fetchone()
    conn.close()
    if row is None:
        return None
    return row[0]
