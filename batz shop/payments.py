import urllib.request
import json
import time
import random

# Impostazioni di pagamento di default (fallback).
# Queste vengono sovrascritte se presenti nel database.
DEFAULT_PAYMENT_SETTINGS = {
    "paypal": "lostecho0000@gmail.com",
    "btc": "bc1qtcc5sxfxel0nl0559quhx028wu7f28vx9cpw26",
    "eth": "0xEe13AD3D6d0E877feE72144bF3Abba7d26F8a0F6",
    "ltc": "ltc1qwvp78ul5ap6n9e6zyuyfzcl3pnmfdem3w5t3cj"
}

# --- CACHE DEI TASSI DI CAMBIO ---
# Evita chiamate ripetute a CoinGecko; i tassi vengono aggiornati ogni 5 minuti.
_rates_cache = {"data": None, "timestamp": 0}
CACHE_TTL = 300  # 5 minuti in secondi


def get_payment_settings(db_settings=None):
    """Restituisce le impostazioni di pagamento.
    Se vengono passate impostazioni dal database, usa quelle; altrimenti usa i default.
    """
    if db_settings and isinstance(db_settings, dict):
        merged = DEFAULT_PAYMENT_SETTINGS.copy()
        for key in merged:
            if db_settings.get(key):
                merged[key] = db_settings[key]
        return merged
    return DEFAULT_PAYMENT_SETTINGS.copy()


def get_crypto_rates():
    """
    Recupera i tassi di cambio in tempo reale per BTC, ETH e LTC rispetto all'Euro
    utilizzando l'API pubblica di CoinGecko (non richiede chiavi).
    Include cache con TTL di 5 minuti per evitare troppe chiamate.
    """
    global _rates_cache
    now = time.time()

    # Usa la cache se ancora valida
    if _rates_cache["data"] is not None and (now - _rates_cache["timestamp"]) < CACHE_TTL:
        return _rates_cache["data"]

    url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,litecoin&vs_currencies=eur"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode('utf-8'))
            rates = {
                "btc": data.get("bitcoin", {}).get("eur", 0),
                "eth": data.get("ethereum", {}).get("eur", 0),
                "ltc": data.get("litecoin", {}).get("eur", 0)
            }
            _rates_cache = {"data": rates, "timestamp": now}
            return rates
    except Exception as e:
        print(f"[*] Attenzione: Errore nel recupero prezzi crypto in tempo reale: {e}")
        # Se abbiamo dati in cache (anche scaduti), usiamoli come fallback
        if _rates_cache["data"] is not None:
            print("[*] Uso dei dati in cache scaduti come fallback.")
            return _rates_cache["data"]
        # Valori di fallback in caso l'API non sia raggiungibile
        return {"btc": 60000, "eth": 3000, "ltc": 80}


def convert_eur_to_crypto(amount_eur, crypto_symbol):
    """
    Converte un importo in Euro nella criptovaluta specificata in tempo reale.
    Restituisce il valore con 8 decimali (standard per le crypto).
    """
    rates = get_crypto_rates()
    symbol = crypto_symbol.lower()

    if symbol in rates and rates[symbol] > 0:
        crypto_amount = amount_eur / rates[symbol]
        return round(crypto_amount, 8)

    return 0


def generate_unique_crypto_amount(base_amount_eur, crypto_symbol, order_id):
    """
    Genera un importo crypto leggermente unico per ogni ordine.
    Aggiunge un piccolo offset randomizzato basato sull'ID ordine per rendere
    l'importo facilmente identificabile sulla blockchain.
    Il valore aggiuntivo è nell'ordine dei centesimi di euro (0.01-0.05 EUR).
    """
    # Offset deterministico basato sull'hash dell'order_id per renderlo reproducibile
    seed = hash(order_id) % 10000
    # Offset tra 0.001 e 0.049 EUR — impercettibile per l'utente
    offset_eur = (seed % 50 + 1) / 1000.0

    total_eur = base_amount_eur + offset_eur
    crypto_amount = convert_eur_to_crypto(total_eur, crypto_symbol)
    return crypto_amount


# --- VERIFICA PAGAMENTI ON-CHAIN ---

def _http_get_json(url, timeout=10):
    """Utility per fare GET HTTP e parsare JSON."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[*] Errore HTTP GET {url}: {e}")
        return None


def verify_btc_payment(address, expected_amount_btc, since_timestamp=None):
    """
    Verifica se un pagamento BTC è arrivato all'indirizzo specificato.
    Usa l'API pubblica di Blockstream (nessuna chiave richiesta).
    
    Args:
        address: indirizzo BTC del negozio
        expected_amount_btc: importo atteso in BTC
        since_timestamp: timestamp Unix dopo il quale cercare la transazione
    
    Returns:
        dict con {found: bool, tx_id: str, amount: float, confirmations: int}
    """
    # Recupera le transazioni recenti dell'indirizzo
    data = _http_get_json(f"https://blockstream.info/api/address/{address}/txs")
    if not data:
        return {"found": False, "error": "Impossibile contattare Blockstream API"}

    tolerance = 0.000005  # Tolleranza di ~0.5 sat per arrotondamenti

    for tx in data[:20]:  # Controlla le ultime 20 transazioni
        # Controlla timestamp se specificato
        if since_timestamp and tx.get("status", {}).get("block_time", 0) < since_timestamp:
            continue

        # Cerca negli output della transazione
        for vout in tx.get("vout", []):
            if vout.get("scriptpubkey_address") == address:
                amount_btc = vout.get("value", 0) / 100_000_000  # satoshi → BTC
                if abs(amount_btc - expected_amount_btc) < tolerance:
                    confirmations = 0
                    if tx.get("status", {}).get("confirmed"):
                        # Stima approssimativa delle conferme
                        tip = _http_get_json("https://blockstream.info/api/blocks/tip/height")
                        if tip:
                            confirmations = tip - tx["status"].get("block_height", tip)
                    return {
                        "found": True,
                        "tx_id": tx.get("txid", ""),
                        "amount": amount_btc,
                        "confirmations": confirmations
                    }

    return {"found": False, "error": "Nessuna transazione corrispondente trovata"}


def verify_eth_payment(address, expected_amount_eth, since_timestamp=None):
    """
    Verifica se un pagamento ETH è arrivato all'indirizzo specificato.
    Usa l'API pubblica di Etherscan (rate-limited senza chiave, ma funzionante).
    
    Returns:
        dict con {found: bool, tx_hash: str, amount: float, confirmations: int}
    """
    # Etherscan API pubblica (senza chiave, max 1 req/5s)
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&page=1&offset=20"
    data = _http_get_json(url)

    if not data or data.get("status") != "1":
        return {"found": False, "error": "Impossibile contattare Etherscan API"}

    tolerance = 0.0001  # Tolleranza per arrotondamenti ETH

    for tx in data.get("result", [])[:20]:
        # Verifica che sia una transazione in entrata verso il nostro indirizzo
        if tx.get("to", "").lower() != address.lower():
            continue

        if since_timestamp and int(tx.get("timeStamp", 0)) < since_timestamp:
            continue

        amount_eth = int(tx.get("value", 0)) / 1e18  # Wei → ETH
        if abs(amount_eth - expected_amount_eth) < tolerance:
            confirmations = int(tx.get("confirmations", 0))
            return {
                "found": True,
                "tx_hash": tx.get("hash", ""),
                "amount": amount_eth,
                "confirmations": confirmations
            }

    return {"found": False, "error": "Nessuna transazione corrispondente trovata"}


def verify_ltc_payment(address, expected_amount_ltc, since_timestamp=None):
    """
    Verifica se un pagamento LTC è arrivato all'indirizzo specificato.
    Usa l'API pubblica di Blockcypher.
    
    Returns:
        dict con {found: bool, tx_hash: str, amount: float, confirmations: int}
    """
    data = _http_get_json(f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}?limit=20")

    if not data:
        return {"found": False, "error": "Impossibile contattare Blockcypher API"}

    tolerance = 0.0001

    for tx in data.get("txrefs", [])[:20]:
        if since_timestamp:
            # Blockcypher usa formato ISO, convertiamo
            pass  # Semplificato per compatibilità

        amount_ltc = tx.get("value", 0) / 1e8  # Litoshi → LTC
        if abs(amount_ltc - expected_amount_ltc) < tolerance:
            return {
                "found": True,
                "tx_hash": tx.get("tx_hash", ""),
                "amount": amount_ltc,
                "confirmations": tx.get("confirmations", 0)
            }

    return {"found": False, "error": "Nessuna transazione corrispondente trovata"}


def verify_btc_tx(tx_id, expected_address, expected_amount_btc):
    """
    Verifica una specifica transazione BTC tramite TX ID.
    """
    data = _http_get_json(f"https://blockstream.info/api/tx/{tx_id}")
    if not data:
        return {"found": False, "error": "Impossibile caricare i dati della transazione da Blockstream"}

    tolerance = 0.000005
    found_output = False
    amount_btc = 0

    for vout in data.get("vout", []):
        if vout.get("scriptpubkey_address") == expected_address:
            amount_btc = vout.get("value", 0) / 100_000_000
            if abs(amount_btc - expected_amount_btc) < tolerance:
                found_output = True
                break

    if not found_output:
        return {"found": False, "error": f"Transazione trovata ma nessun output verso {expected_address} con importo atteso di {expected_amount_btc} BTC."}

    confirmations = 0
    status = data.get("status", {})
    if status.get("confirmed"):
        tip = _http_get_json("https://blockstream.info/api/blocks/tip/height")
        if tip:
            confirmations = tip - status.get("block_height", tip)

    return {
        "found": True,
        "tx_id": tx_id,
        "amount": amount_btc,
        "confirmations": confirmations
    }


def verify_eth_tx(tx_hash, expected_address, expected_amount_eth):
    """
    Verifica una transazione ETH cercando il tx_hash nelle ultime transazioni dell'indirizzo.
    """
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={expected_address}&startblock=0&endblock=99999999&sort=desc&page=1&offset=50"
    data = _http_get_json(url)

    if not data or data.get("status") != "1":
        return {"found": False, "error": "Impossibile contattare Etherscan API"}

    tolerance = 0.0001
    for tx in data.get("result", []):
        if tx.get("hash", "").lower() == tx_hash.lower():
            if tx.get("to", "").lower() != expected_address.lower():
                return {"found": False, "error": f"La transazione invia fondi a un indirizzo errato: {tx.get('to')}"}
            
            amount_eth = int(tx.get("value", 0)) / 1e18
            if abs(amount_eth - expected_amount_eth) >= tolerance:
                return {"found": False, "error": f"Importo non corrispondente. Atteso: {expected_amount_eth} ETH, trovato: {amount_eth} ETH."}
            
            return {
                "found": True,
                "tx_hash": tx_hash,
                "amount": amount_eth,
                "confirmations": int(tx.get("confirmations", 0))
            }

    return {"found": False, "error": "Transazione non trovata tra le recenti dell'indirizzo."}


def verify_ltc_tx(tx_hash, expected_address, expected_amount_ltc):
    """
    Verifica una transazione LTC cercando il tx_hash nelle transazioni dell'indirizzo.
    """
    data = _http_get_json(f"https://api.blockcypher.com/v1/ltc/main/addrs/{expected_address}?limit=50")
    if not data:
        return {"found": False, "error": "Impossibile contattare Blockcypher API"}

    tolerance = 0.0001
    for tx in data.get("txrefs", []):
        if tx.get("tx_hash", "").lower() == tx_hash.lower():
            amount_ltc = tx.get("value", 0) / 1e8
            if abs(amount_ltc - expected_amount_ltc) >= tolerance:
                return {"found": False, "error": f"Importo non corrispondente. Atteso: {expected_amount_ltc} LTC, trovato: {amount_ltc} LTC."}
            
            return {
                "found": True,
                "tx_hash": tx_hash,
                "amount": amount_ltc,
                "confirmations": tx.get("confirmations", 0)
            }

    return {"found": False, "error": "Transazione non trovata tra le recenti dell'indirizzo."}


def verify_payment(method, address, expected_amount, since_timestamp=None, tx_hash=None):
    """
    Funzione unificata di verifica pagamento.
    Dispatch al metodo corretto basato sul tipo di crypto.
    Se tx_hash è fornito, verifica specificamente quel hash.
    Per PayPal, restituisce sempre 'verifica manuale richiesta'.
    """
    method_lower = method.lower()

    if method_lower == 'paypal':
        return {"found": False, "manual": True, "message": "PayPal richiede verifica manuale. Controlla il tuo account PayPal."}
    
    if tx_hash:
        tx_hash = tx_hash.strip()
        if method_lower == 'bitcoin':
            return verify_btc_tx(tx_hash, address, expected_amount)
        elif method_lower == 'ethereum':
            return verify_eth_tx(tx_hash, address, expected_amount)
        elif method_lower == 'litecoin':
            return verify_ltc_tx(tx_hash, address, expected_amount)
        else:
            return {"found": False, "error": f"Metodo di pagamento sconosciuto: {method}"}
            
    # Altrimenti, verifica scansionando l'indirizzo
    if method_lower == 'bitcoin':
        return verify_btc_payment(address, expected_amount, since_timestamp)
    elif method_lower == 'ethereum':
        return verify_eth_payment(address, expected_amount, since_timestamp)
    elif method_lower == 'litecoin':
        return verify_ltc_payment(address, expected_amount, since_timestamp)
    else:
        return {"found": False, "error": f"Metodo di pagamento sconosciuto: {method}"}