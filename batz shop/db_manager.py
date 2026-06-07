import os
import json
import tempfile
import threading
import shutil
from datetime import datetime
from werkzeug.security import generate_password_hash

# Use a local application data folder for the database to avoid OneDrive locks
if os.name == 'nt':
    DB_DIR = os.path.join(os.getenv('APPDATA') or os.path.expanduser('~'), 'Zatirfo')
else:
    DB_DIR = os.path.expanduser('~/.zatirfo')

os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, 'zatirfo_database.db')
BACKUP_DIR = os.path.join(DB_DIR, 'backups')
os.makedirs(BACKUP_DIR, exist_ok=True)

MAX_BACKUPS = 3  # Numero massimo di backup da mantenere

# Thread lock globale per proteggere le operazioni di lettura/scrittura del database
_db_lock = threading.Lock()

# Schema atteso del database — usato per la validazione e la migrazione.
# NOTA: L'account admin viene creato con password criptata, a prova di furto.
# Le impostazioni di pagamento sono opzionali nel DB e vengono sovrascritte da payments.py se mancanti.
DEFAULT_DATA = {
    "users": [
        {
            "id": "admin_master",
            "name": "Admin",
            "email": "admin@zatirfo.com",
            "password": generate_password_hash("Michele2311"),  # Password criptata
            "isAdmin": True
        }
    ],
    "products": [],
    "orders": [],
    "reviews": [],
    "logo": "zatirfo.png",
    "paymentSettings": {}
}

# Campi richiesti a livello root del database
REQUIRED_FIELDS = {
    "users": list,
    "products": list,
    "orders": list,
    "reviews": list,
    "logo": str,
    "paymentSettings": dict
}


def _validate_and_migrate(data):
    """
    Valida la struttura del database e aggiunge campi mancanti.
    Garantisce compatibilità con versioni precedenti del DB.
    """
    if not isinstance(data, dict):
        print("[!] Database corrotto: il contenuto non è un dizionario. Reset ai default.")
        return DEFAULT_DATA.copy()

    migrated = False
    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in data:
            print(f"[*] Campo mancante '{field}' aggiunto al database.")
            data[field] = DEFAULT_DATA.get(field, expected_type())
            migrated = True
        elif not isinstance(data[field], expected_type):
            print(f"[!] Campo '{field}' ha tipo errato. Reset al default.")
            data[field] = DEFAULT_DATA.get(field, expected_type())
            migrated = True

    # Validazione struttura utenti
    for user in data.get("users", []):
        if "id" not in user:
            user["id"] = "u_" + os.urandom(4).hex()
        if "isAdmin" not in user:
            user["isAdmin"] = False
        if "googleUser" not in user:
            user["googleUser"] = False

    # Validazione struttura ordini
    for order in data.get("orders", []):
        if "status" not in order:
            order["status"] = "In Attesa di Conferma"
        if "paymentRef" not in order:
            order["paymentRef"] = None
        if "cryptoAmount" not in order:
            order["cryptoAmount"] = None
        if "orderTimestamp" not in order:
            order["orderTimestamp"] = None

    # Validazione struttura prodotti
    for product in data.get("products", []):
        if "variants" not in product:
            product["variants"] = []

    if migrated:
        print("[*] Migrazione del database completata.")

    return data


def _create_backup():
    """Crea un backup del database corrente e mantiene solo le ultime N copie."""
    if not os.path.exists(DB_FILE):
        return

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"zatirfo_backup_{timestamp}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        shutil.copy2(DB_FILE, backup_path)

        # Pulizia backup vecchi — mantieni solo le ultime MAX_BACKUPS copie
        backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.startswith("zatirfo_backup_")],
            reverse=True
        )
        for old_backup in backups[MAX_BACKUPS:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, old_backup))
            except Exception:
                pass
    except Exception as e:
        print(f"[!] Errore nella creazione del backup: {e}")


def init_db():
    """Inizializza il database se non esiste"""
    with _db_lock:
        if not os.path.exists(DB_FILE):
            print(f"[*] Creazione del database sicuro {DB_FILE} in corso...")
            # write atomically
            tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(DB_FILE))
            try:
                with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
                    json.dump(DEFAULT_DATA, f, indent=4)
                os.replace(tmp_path, DB_FILE)
                print("[*] Database sicuro creato con successo!")
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
        else:
            print(f"[*] Il database esiste gia' in: {DB_FILE}")
            # Valida e migra il database esistente all'avvio
            data = _load_db_unsafe()
            validated = _validate_and_migrate(data)
            _save_db_unsafe(validated)


def _load_db_unsafe():
    """Caricamento interno senza lock (chiamato solo da funzioni che già hanno il lock)."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("[!] Database corrotto: errore nel parsing JSON.")
                return DEFAULT_DATA.copy()
    return DEFAULT_DATA.copy()


def _save_db_unsafe(data):
    """Salvataggio interno senza lock (chiamato solo da funzioni che già hanno il lock)."""
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(DB_FILE))
    try:
        with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_path, DB_FILE)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def load_db():
    """Carica in modo sicuro il database in memoria (thread-safe)."""
    with _db_lock:
        data = _load_db_unsafe()
        return _validate_and_migrate(data)


def save_db(data):
    """Salva i dati sovrascrivendo il database in modo sicuro (thread-safe con backup)."""
    with _db_lock:
        _create_backup()
        _save_db_unsafe(data)