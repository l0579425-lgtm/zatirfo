import os
import json
import urllib.request
import time
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash
from db_manager import init_db, load_db, save_db
import payments
from email_otp import send_otp_email, verify_otp, resend_otp, get_otp_expiry_time
from dotenv import load_dotenv

# Carica le variabili d'ambiente dal file .env
load_dotenv()

app = Flask(__name__)
# Chiave segreta per i cookie di sessione (impossibile falsificare il login)
app.secret_key = os.getenv("SECRET_KEY", "z4t1rf0_s3cr3t_k3y_2026_molto_sicura")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

# --- RATE LIMITING BASICO ---
_rate_limit_store = {}  # ip -> [timestamps]
RATE_LIMIT_WINDOW = 60  # secondi
RATE_LIMIT_MAX = 30  # max richieste per finestra


def _check_rate_limit(ip):
    """Controlla se l'IP ha superato il rate limit."""
    now = time.time()
    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []
    # Rimuovi timestamp vecchi
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limit_store[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limit_store[ip].append(now)
    return True


# --- SICUREZZA GLOBALE ANTI-PHISHING E ANTI-HACK ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.before_request
def rate_limit_check():
    """Rate limiting globale per le API."""
    if request.path.startswith('/api/'):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if not _check_rate_limit(client_ip):
            return jsonify({"status": "error", "message": "Troppe richieste. Riprova tra poco."}), 429


@app.route('/')
def home():
    return render_template('index.html', google_client_id=GOOGLE_CLIENT_ID)


def verify_google_token(id_token):
    """Verifica un ID token Google usando l'endpoint pubblico di Google."""
    if not id_token or not GOOGLE_CLIENT_ID:
        return None

    url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))

        if data.get('aud') != GOOGLE_CLIENT_ID or data.get('email_verified') != 'true':
            return None

        return {
            "email": data.get('email'),
            "name": data.get('name') or data.get('email', '').split('@')[0]
        }
    except Exception:
        return None


# --- HELPER ADMIN CHECK ---
def _get_admin_user():
    """Restituisce l'utente admin dalla sessione, o None se non admin."""
    if 'user_id' not in session:
        return None
    db = load_db()
    user = next((u for u in db['users'] if u['id'] == session['user_id']), None)
    if not user or not user.get('isAdmin'):
        return None
    return user


def _sanitize_string(value, max_length=500):
    """Sanitizza una stringa: rimuove spazi e limita la lunghezza."""
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]


# --- OTP EMAIL VERIFICATION STORE (temporaneo in memoria) ---
_otp_registration_store = {}  # email -> {"name": ..., "password_hash": ..., "verified": False}


# --- AUTENTICAZIONE UTENTE ---
@app.route('/api/auth/register-otp', methods=['POST'])
def register_otp():
    """Primo step: invia OTP email per la registrazione."""
    data = request.json or {}
    email = _sanitize_string(data.get('email', ''), 254).lower()
    password = data.get('password') or ''
    name = _sanitize_string(data.get('name', ''), 100) or email.split('@')[0]

    if not email or not password:
        return jsonify({"status": "error", "message": "Email e password sono richieste."}), 400

    if len(password) < 6:
        return jsonify({"status": "error", "message": "La password deve avere almeno 6 caratteri."}), 400

    if '@' not in email or '.' not in email:
        return jsonify({"status": "error", "message": "Formato email non valido."}), 400

    db = load_db()
    if any(u['email'] == email for u in db['users']):
        return jsonify({"status": "error", "message": "Account già esistente con questa email."}), 400

    # Invia OTP email
    if not send_otp_email(email, name):
        return jsonify({"status": "error", "message": "Errore nell'invio dell'email OTP. Riprova più tardi."}), 500

    # Salva dati temporanei in attesa di verifica OTP
    _otp_registration_store[email] = {
        "name": name,
        "password_hash": generate_password_hash(password),
        "verified": False
    }

    return jsonify({
        "status": "success",
        "message": "Codice OTP inviato all'email. Controlla la posta (incluso spam).",
        "email": email,
        "otpExpirySeconds": get_otp_expiry_time(email)
    })


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_registration_otp():
    """Secondo step: verifica OTP e completa registrazione."""
    data = request.json or {}
    email = _sanitize_string(data.get('email', ''), 254).lower()
    otp_code = _sanitize_string(data.get('otp', ''), 10)

    if not email or not otp_code:
        return jsonify({"status": "error", "message": "Email e codice OTP sono richiesti."}), 400

    # Controlla se l'email è in attesa di registrazione
    if email not in _otp_registration_store:
        return jsonify({"status": "error", "message": "Registrazione non trovata. Inizia una nuova registrazione."}), 400

    # Verifica il codice OTP
    if not verify_otp(email, otp_code):
        return jsonify({"status": "error", "message": "Codice OTP errato o scaduto. Richiedi un nuovo codice."}), 400

    # Crea l'account utente
    db = load_db()
    registration_data = _otp_registration_store[email]
    new_user = {
        "id": "u_" + os.urandom(4).hex(),
        "name": registration_data['name'],
        "email": email,
        "password": registration_data['password_hash'],
        "isAdmin": False,
        "googleUser": False,
        "emailVerified": True,
        "createdAt": datetime.now().strftime('%d/%m/%Y %H:%M')
    }
    db['users'].append(new_user)
    save_db(db)

    # Pulisci i dati temporanei
    del _otp_registration_store[email]

    # Login automatico
    session['user_id'] = new_user['id']

    return jsonify({
        "status": "success",
        "message": "Account creato e verificato con successo! Bentornato!",
        "user": {
            "id": new_user['id'],
            "name": new_user['name'],
            "email": new_user['email'],
            "isAdmin": False,
            "emailVerified": True
        }
    })


@app.route('/api/auth/resend-otp', methods=['POST'])
def resend_registration_otp():
    """Reinvia il codice OTP per la registrazione."""
    data = request.json or {}
    email = _sanitize_string(data.get('email', ''), 254).lower()

    if not email:
        return jsonify({"status": "error", "message": "Email richiesta."}), 400

    if email not in _otp_registration_store:
        return jsonify({"status": "error", "message": "Registrazione non trovata per questa email."}), 400

    reg_data = _otp_registration_store[email]
    if not resend_otp(email, reg_data['name']):
        return jsonify({"status": "error", "message": "Errore nell'invio dell'email. Riprova più tardi."}), 500

    return jsonify({
        "status": "success",
        "message": "Nuovo codice OTP inviato all'email.",
        "otpExpirySeconds": get_otp_expiry_time(email)
    })


@app.route('/api/auth/register', methods=['POST'])
def register():
    """LEGACY: Registrazione diretta senza OTP (mantenuta per compatibilità)."""
    data = request.json or {}
    email = _sanitize_string(data.get('email', ''), 254).lower()
    password = data.get('password') or ''
    name = _sanitize_string(data.get('name', ''), 100) or email.split('@')[0]

    if not email or not password:
        return jsonify({"status": "error", "message": "Email e password sono richieste."}), 400

    if len(password) < 6:
        return jsonify({"status": "error", "message": "La password deve avere almeno 6 caratteri."}), 400

    if '@' not in email or '.' not in email:
        return jsonify({"status": "error", "message": "Formato email non valido."}), 400

    db = load_db()
    if any(u['email'] == email for u in db['users']):
        return jsonify({"status": "error", "message": "Account già esistente con questa email."}), 400

    new_user = {
        "id": "u_" + os.urandom(4).hex(),
        "name": name,
        "email": email,
        "password": generate_password_hash(password),
        "isAdmin": False,
        "googleUser": False
    }
    db['users'].append(new_user)
    save_db(db)
    session['user_id'] = new_user['id']

    return jsonify({"status": "success", "user": {"id": new_user['id'], "name": new_user['name'], "email": new_user['email'], "isAdmin": False}})


@app.route('/api/auth/google', methods=['POST'])
def auth_google():
    data = request.json or {}
    id_token = data.get('id_token')
    user_info = verify_google_token(id_token)
    if not user_info:
        return jsonify({"status": "error", "message": "Token Google non valido o client ID non configurato."}), 401

    db = load_db()
    user = next((u for u in db['users'] if u['email'] == user_info['email']), None)
    if not user:
        user = {
            "id": "u_" + os.urandom(4).hex(),
            "name": user_info['name'],
            "email": user_info['email'],
            "password": "",
            "isAdmin": False,
            "googleUser": True
        }
        db['users'].append(user)
        save_db(db)

    session['user_id'] = user['id']
    return jsonify({"status": "success", "user": {"id": user['id'], "name": user['name'], "email": user['email'], "isAdmin": user.get('isAdmin', False)}})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = _sanitize_string(data.get('email', ''), 254).lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"status": "error", "message": "Email e password sono richieste."}), 400

    db = load_db()
    for u in db['users']:
        if u['email'] == email and u.get('password') and check_password_hash(u['password'], password):
            session['user_id'] = u['id']
            return jsonify({"status": "success", "user": {"id": u['id'], "name": u['name'], "email": u['email'], "isAdmin": u.get('isAdmin', False)}})

    return jsonify({"status": "error", "message": "Credenziali errate o account non esistente."}), 401


@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    if 'user_id' in session:
        db = load_db()
        user = next((u for u in db['users'] if u['id'] == session['user_id']), None)
        if user:
            return jsonify({"status": "success", "user": {"id": user['id'], "name": user['name'], "email": user['email'], "isAdmin": user.get('isAdmin', False)}})
    return jsonify({"status": "error", "message": "Non connesso."})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"status": "success", "message": "Disconnesso."})


# --- SISTEMA DI PAGAMENTO ---
@app.route('/api/payments/convert', methods=['GET'])
def get_crypto_conversion():
    try:
        amount = float(request.args.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Importo non valido."}), 400

    currency = _sanitize_string(request.args.get('currency', 'btc'), 10).lower()
    order_id = request.args.get('order_id', '')

    if currency not in ('btc', 'eth', 'ltc'):
        return jsonify({"status": "error", "message": "Valuta non supportata."}), 400

    if order_id:
        # Genera importo unico per poter tracciare il pagamento
        crypto_amount = payments.generate_unique_crypto_amount(amount, currency, order_id)
    else:
        crypto_amount = payments.convert_eur_to_crypto(amount, currency)

    return jsonify({"status": "success", "crypto_amount": crypto_amount, "currency": currency})


# --- DATI E ORDINI ---
@app.route('/api/data', methods=['GET'])
def get_data():
    db = load_db()
    user_id = session.get('user_id')

    # Le payment settings possono venire dal DB o dai default
    ps = payments.get_payment_settings(db.get('paymentSettings'))

    response = {
        "products": db.get('products', []),
        "reviews": db.get('reviews', []),
        "logo": db.get('logo', 'zatirfo.png'),
        "paymentSettings": ps
    }

    if user_id:
        user = next((u for u in db['users'] if u['id'] == user_id), None)
        if user:
            if user.get('isAdmin'):
                response['orders'] = db.get('orders', [])
                response['allUsers'] = [{"id": u['id'], "name": u['name'], "email": u['email']} for u in db.get('users', [])]
            else:
                response['orders'] = [o for o in db.get('orders', []) if o['userId'] == user_id]
    else:
        response['orders'] = []

    return jsonify(response)


@app.route('/api/orders', methods=['POST'])
def create_order():
    """Crea un ordine utente.

    Request JSON atteso:
    - productId: id del prodotto selezionato
    - finalTitle: titolo del prodotto da salvare nell'ordine
    - finalPrice: prezzo finale da registrare
    - method: metodo di pagamento scelto (es. PayPal, Bitcoin)
    - variantIndex: indice variante opzionale, se presente
    """
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Non autorizzato. Effettua il login."}), 401

    data = request.json or {}
    db = load_db()
    user = next((u for u in db['users'] if u['id'] == session['user_id']), None)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    same_ip_records = [o for o in db.get('orders', []) if o.get('client_ip') == client_ip]
    same_ip_user = any(o for o in same_ip_records if o.get('userId') == session['user_id'])

    order_id = f"ORD-{os.urandom(3).hex().upper()}"
    final_price = data.get('finalPrice', 0)
    method = _sanitize_string(data.get('method', ''), 50)

    # Calcola importo crypto unico per questo ordine (se pagamento crypto)
    crypto_amount = None
    if method.lower() != 'paypal':
        symbol = 'btc' if method == 'Bitcoin' else 'eth' if method == 'Ethereum' else 'ltc'
        crypto_amount = payments.generate_unique_crypto_amount(final_price, symbol, order_id)

    variant_index = data.get('variantIndex')
    if variant_index is not None:
        try:
            variant_index = int(variant_index)
        except (ValueError, TypeError):
            variant_index = None

    new_order = {
        "id": order_id,
        "userId": session['user_id'],
        "userName": user['name'] if user else "Utente",
        "userEmail": user['email'] if user else "",
        "productId": data.get('productId'),
        "variantIndex": variant_index,
        "productTitle": _sanitize_string(data.get('finalTitle', ''), 200),
        "price": final_price,
        "date": datetime.now().strftime('%d/%m/%Y'),
        "orderTimestamp": int(datetime.now().timestamp()),
        "method": method,
        "status": "In Attesa di Pagamento",
        "client_ip": client_ip,
        "payment_ip": None,
        "same_ip_count": len(same_ip_records),
        "same_ip_user": same_ip_user,
        "cryptoAmount": crypto_amount,
        "paymentRef": None,  # Sarà compilato quando il pagamento viene verificato
        "adminNotes": ""
    }

    product_id = data.get('productId')
    for p in db['products']:
        if p['id'] == product_id:
            if variant_index is not None and 'variants' in p and len(p['variants']) > variant_index:
                p['variants'][variant_index]['stock'] -= 1
            p['stock'] -= 1
            break

    db['orders'].insert(0, new_order)
    save_db(db)
    return jsonify({"status": "success", "order": new_order})


@app.route('/api/reviews', methods=['POST'])
def create_review():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Non autorizzato."}), 401

    data = request.json or {}
    db = load_db()
    user = next((u for u in db['users'] if u['id'] == session['user_id']), None)

    rating = data.get('rating', 5)
    if not isinstance(rating, int) or rating < 1 or rating > 5:
        rating = 5

    text = _sanitize_string(data.get('text', ''), 1000)
    if not text:
        return jsonify({"status": "error", "message": "Il testo della recensione è richiesto."}), 400

    new_review = {
        "id": f"rev_{int(datetime.now().timestamp())}",
        "userId": session['user_id'],
        "userName": user['name'] if user else "Utente",
        "rating": rating,
        "text": text,
        "date": datetime.now().strftime('%d/%m/%Y')
    }
    db['reviews'].insert(0, new_review)
    save_db(db)
    return jsonify({"status": "success", "review": new_review})


# --- GESTIONE ADMIN ---
@app.route('/api/admin/save', methods=['POST'])
def admin_save():
    if not _get_admin_user():
        return jsonify({"status": "error", "message": "Accesso negato."}), 403

    db = load_db()
    data = request.json or {}
    if 'products' in data:
        db['products'] = data['products']
    if 'logo' in data:
        db['logo'] = data['logo']
    if 'paymentSettings' in data:
        db['paymentSettings'] = data['paymentSettings']

    save_db(db)
    return jsonify({"status": "success", "message": "Dati salvati con successo!"})


@app.route('/api/admin/orders/update-status', methods=['POST'])
def admin_update_order_status():
    """Aggiorna lo stato di un ordine (solo admin)."""
    if not _get_admin_user():
        return jsonify({"status": "error", "message": "Accesso negato."}), 403

    data = request.json or {}
    order_id = data.get('orderId')
    new_status = _sanitize_string(data.get('status', ''), 50)
    admin_notes = _sanitize_string(data.get('adminNotes', ''), 500)

    valid_statuses = ["In Attesa di Pagamento", "In Attesa di Verifica", "Pagamento Verificato", "Completato", "Rifiutato", "Annullato"]
    if new_status not in valid_statuses:
        return jsonify({"status": "error", "message": f"Stato non valido. Usa: {', '.join(valid_statuses)}"}), 400

    db = load_db()
    order = next((o for o in db['orders'] if o['id'] == order_id), None)
    if not order:
        return jsonify({"status": "error", "message": "Ordine non trovato."}), 404

    order['status'] = new_status
    if admin_notes:
        order['adminNotes'] = admin_notes
    order['statusUpdatedAt'] = datetime.now().strftime('%d/%m/%Y %H:%M')
    order['statusUpdatedBy'] = session.get('user_id')

    # Se rifiutato o annullato, ripristina lo stock
    if new_status in ("Rifiutato", "Annullato"):
        for p in db['products']:
            if p['id'] == order.get('productId'):
                p['stock'] += 1
                # Ripristina anche la variante se presente
                variant_idx = order.get('variantIndex')
                if variant_idx is not None and 'variants' in p and len(p['variants']) > variant_idx:
                    p['variants'][variant_idx]['stock'] += 1
                break

    save_db(db)
    return jsonify({"status": "success", "message": f"Stato aggiornato a: {new_status}", "order": order})


@app.route('/api/admin/orders/delete', methods=['POST'])
def admin_delete_order():
    """Elimina un ordine (solo admin)."""
    if not _get_admin_user():
        return jsonify({"status": "error", "message": "Accesso negato."}), 403

    data = request.json or {}
    order_id = data.get('orderId')

    db = load_db()
    original_len = len(db['orders'])
    db['orders'] = [o for o in db['orders'] if o['id'] != order_id]

    if len(db['orders']) == original_len:
        return jsonify({"status": "error", "message": "Ordine non trovato."}), 404

    save_db(db)
    return jsonify({"status": "success", "message": "Ordine eliminato."})


@app.route('/api/admin/orders/check-payment', methods=['POST'])
def admin_check_payment():
    """
    Verifica automatica del pagamento sulla blockchain (solo admin).
    Interroga le API pubbliche per verificare se il pagamento è arrivato.
    """
    if not _get_admin_user():
        return jsonify({"status": "error", "message": "Accesso negato."}), 403

    data = request.json or {}
    order_id = data.get('orderId')

    db = load_db()
    order = next((o for o in db['orders'] if o['id'] == order_id), None)
    if not order:
        return jsonify({"status": "error", "message": "Ordine non trovato."}), 404

    method = order.get('method', '')
    ps = payments.get_payment_settings(db.get('paymentSettings'))

    # Determina l'indirizzo e l'importo atteso
    if method == 'PayPal':
        return jsonify({
            "status": "success",
            "result": {
                "found": False,
                "manual": True,
                "message": f"Verifica manuale: controlla se €{order['price']:.2f} è arrivato su {ps.get('paypal', 'N/A')} dall'utente {order.get('userEmail', order.get('userName', 'N/A'))}."
            }
        })

    address_map = {'Bitcoin': ps.get('btc'), 'Ethereum': ps.get('eth'), 'Litecoin': ps.get('ltc')}
    address = address_map.get(method)
    expected_amount = order.get('cryptoAmount')

    if not address or not expected_amount:
        return jsonify({
            "status": "success",
            "result": {"found": False, "error": "Indirizzo o importo crypto mancante per questo ordine."}
        })

    since_timestamp = order.get('orderTimestamp')
    tx_hash = order.get('paymentRef')
    result = payments.verify_payment(method, address, expected_amount, since_timestamp, tx_hash)

    # Se trovato, aggiorna l'ordine con il riferimento della transazione
    if result.get('found'):
        order['paymentRef'] = result.get('tx_id') or result.get('tx_hash', '')
        order['paymentVerifiedAt'] = datetime.now().strftime('%d/%m/%Y %H:%M')
        if order['status'] == "In Attesa di Conferma":
            order['status'] = "Pagamento Verificato"
        save_db(db)

    return jsonify({"status": "success", "result": result, "order": order})


@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    """Statistiche rapide per il pannello admin."""
    if not _get_admin_user():
        return jsonify({"status": "error", "message": "Accesso negato."}), 403

    db = load_db()
    orders = db.get('orders', [])
    total_revenue = sum(o.get('price', 0) for o in orders if o.get('status') in ('Completato', 'Pagamento Verificato'))
    pending_orders = len([o for o in orders if o.get('status') == 'In Attesa di Conferma'])
    completed_orders = len([o for o in orders if o.get('status') == 'Completato'])
    total_users = len(db.get('users', []))

    return jsonify({
        "status": "success",
        "stats": {
            "totalRevenue": round(total_revenue, 2),
            "pendingOrders": pending_orders,
            "completedOrders": completed_orders,
            "totalOrders": len(orders),
            "totalUsers": total_users,
            "totalProducts": len(db.get('products', []))
        }
    })


@app.route('/api/orders/submit-payment', methods=['POST'])
def submit_payment():
    """
    L'utente segnala di aver effettuato il pagamento.
    Opzionalmente fornisce un TX Hash.
    """
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Non autorizzato."}), 401
        
    data = request.json or {}
    order_id = data.get('orderId')
    tx_hash = _sanitize_string(data.get('txHash', ''), 128)
    
    db = load_db()
    order = next((o for o in db['orders'] if o['id'] == order_id), None)
    if not order:
        return jsonify({"status": "error", "message": "Ordine non trovato."}), 404
        
    if order['userId'] != session['user_id']:
        return jsonify({"status": "error", "message": "Non autorizzato."}), 403
        
    if order['status'] not in ("In Attesa di Pagamento", "In Attesa di Verifica"):
        return jsonify({"status": "error", "message": f"Non puoi inviare la notifica di pagamento per un ordine in stato: {order['status']}"}), 400
        
    # Registra l'IP del pagamento per confronto
    payment_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    order['payment_ip'] = payment_ip
    
    # Se è presente un tx_hash, controlla che non sia già stato usato da un altro ordine!
    if tx_hash:
        tx_hash_lower = tx_hash.lower()
        for other_order in db['orders']:
            if other_order['id'] != order_id and other_order.get('paymentRef') and other_order.get('paymentRef').lower() == tx_hash_lower:
                # Segnala allerta frode
                order['adminNotes'] = (order.get('adminNotes', '') + 
                    f"\n[ALLERTA] L'utente ha tentato di inviare un TX Hash già utilizzato nell'ordine {other_order['id']}!").strip()
                order['status'] = "In Attesa di Verifica"
                save_db(db)
                return jsonify({
                    "status": "error", 
                    "message": "Questo ID Transazione è già stato utilizzato per un altro ordine! L'admin è stato notificato di questa attività sospetta."
                }), 400

    order['status'] = "In Attesa di Verifica"
    if tx_hash:
        order['paymentRef'] = tx_hash
        
    # Tentativo di verifica automatica immediata se crypto
    method = order.get('method', '')
    ps = payments.get_payment_settings(db.get('paymentSettings'))
    address_map = {'Bitcoin': ps.get('btc'), 'Ethereum': ps.get('eth'), 'Litecoin': ps.get('ltc')}
    address = address_map.get(method)
    expected_amount = order.get('cryptoAmount')
    
    verification_success = False
    verification_message = ""
    
    if method != 'PayPal' and address and expected_amount and tx_hash:
        since_ts = order.get('orderTimestamp')
        result = payments.verify_payment(method, address, expected_amount, since_ts, tx_hash)
        if result.get('found'):
            order['status'] = "Pagamento Verificato"
            order['paymentVerifiedAt'] = datetime.now().strftime('%d/%m/%Y %H:%M')
            order['adminNotes'] = (order.get('adminNotes', '') + "\n[AUTO] Pagamento verificato automaticamente on-chain.").strip()
            verification_success = True
            verification_message = "Pagamento rilevato e verificato automaticamente con successo!"
            
    save_db(db)
    return jsonify({
        "status": "success", 
        "message": verification_message or "Notifica inviata con successo. L'admin verificherà a breve.",
        "verified": verification_success,
        "order": order
    })


@app.route('/api/orders/cancel', methods=['POST'])
def cancel_order():
    """
    L'utente annulla il proprio ordine prima di pagare.
    Ripristina le scorte del prodotto.
    """
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Non autorizzato."}), 401
        
    data = request.json or {}
    order_id = data.get('orderId')
    
    db = load_db()
    order = next((o for o in db['orders'] if o['id'] == order_id), None)
    if not order:
        return jsonify({"status": "error", "message": "Ordine non trovato."}), 404
        
    if order['userId'] != session['user_id']:
        return jsonify({"status": "error", "message": "Non autorizzato."}), 403
        
    if order['status'] != "In Attesa di Pagamento":
        return jsonify({"status": "error", "message": "Puoi annullare un ordine solo se è in attesa di pagamento."}), 400
        
    order['status'] = "Annullato"
    order['adminNotes'] = (order.get('adminNotes', '') + "\nAnnullato dall'utente.").strip()
    
    # Ripristina lo stock
    product_id = order.get('productId')
    variant_idx = order.get('variantIndex')
    for p in db['products']:
        if p['id'] == product_id:
            p['stock'] += 1
            if variant_idx is not None and 'variants' in p and len(p['variants']) > variant_idx:
                p['variants'][variant_idx]['stock'] += 1
            break
            
    save_db(db)
    return jsonify({"status": "success", "message": "Ordine annullato. Le scorte sono state ripristinate.", "order": order})


def cleanup_expired_orders():
    """
    Cicla all'infinito ogni 60 secondi.
    Trova gli ordini in "In Attesa di Pagamento" creati più di 30 minuti fa
    e li annulla ripristinando lo stock.
    """
    time.sleep(5)
    while True:
        try:
            db = load_db()
            now = int(time.time())
            changed = False
            
            for order in db.get('orders', []):
                if order.get('status') == "In Attesa di Pagamento":
                    ts = order.get('orderTimestamp')
                    if ts and (now - ts) > 1800:  # 30 minuti
                        order['status'] = "Annullato"
                        order['adminNotes'] = (order.get('adminNotes', '') + 
                            "\nAnnullato automaticamente per mancato pagamento entro 30 minuti.").strip()
                        
                        # Ripristina stock
                        product_id = order.get('productId')
                        variant_idx = order.get('variantIndex')
                        for p in db.get('products', []):
                            if p['id'] == product_id:
                                p['stock'] += 1
                                if variant_idx is not None and 'variants' in p and len(p['variants']) > variant_idx:
                                    p['variants'][variant_idx]['stock'] += 1
                                break
                        changed = True
                        print(f"[*] Ordine {order['id']} annullato automaticamente per timeout (30min). Stock ripristinato.")
                        
            if changed:
                save_db(db)
        except Exception as e:
            print(f"[!] Errore nel thread di pulizia ordini: {e}")
        time.sleep(60)


if __name__ == '__main__':
    init_db()
    # Avvia il thread di pulizia ordini scaduti
    threading.Thread(target=cleanup_expired_orders, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)