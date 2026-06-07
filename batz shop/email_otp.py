import os
import random
import string
import smtplib
import json
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Carica le variabili d'ambiente dal file .env
load_dotenv()

GMAIL_EMAIL = os.getenv("GMAIL_EMAIL", "")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD", "")
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "5"))
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))

# In-memory store per OTP (in produzione usare Redis o database)
_otp_store = {}  # email -> {"code": "123456", "expires": timestamp}


def generate_otp(length=OTP_LENGTH):
    """Genera un codice OTP numerico casuale."""
    return ''.join(random.choices(string.digits, k=length))


def send_otp_email(email, name="Utente"):
    """
    Invia un codice OTP via email.
    Restituisce True se inviato con successo, False altrimenti.
    """
    if not GMAIL_EMAIL or not GMAIL_PASSWORD:
        print("[!] Errore: Credenziali Gmail non configurate nel file .env")
        return False

    try:
        # Genera il codice OTP
        otp_code = generate_otp()
        expiry_time = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)

        # Salva il codice nello store
        _otp_store[email.lower()] = {
            "code": otp_code,
            "expires": expiry_time.timestamp()
        }

        # Crea il messaggio email
        message = MIMEMultipart("alternative")
        message["Subject"] = "Il tuo codice OTP di verifica - Zatirfo Shop"
        message["From"] = GMAIL_EMAIL
        message["To"] = email

        # Versione testo
        text = f"""
Ciao {name},

Il tuo codice OTP per verificare l'account Zatirfo è:

{otp_code}

Questo codice scadrà tra {OTP_EXPIRY_MINUTES} minuti.

Se non hai richiesto questo codice, ignora questo messaggio.

Cordiali saluti,
Team Zatirfo
"""

        # Versione HTML
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">Verifica il tuo account Zatirfo</h2>
                    <p>Ciao {name},</p>
                    <p>Il tuo codice OTP per verificare l'account è:</p>
                    
                    <div style="background-color: #f0f0f0; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #e74c3c; letter-spacing: 5px; font-size: 36px;">{otp_code}</h1>
                    </div>
                    
                    <p style="color: #7f8c8d;">Questo codice scadrà tra <strong>{OTP_EXPIRY_MINUTES} minuti</strong>.</p>
                    <p style="color: #7f8c8d;">Se non hai richiesto questo codice, ignora questo messaggio.</p>
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
                    <p style="font-size: 12px; color: #95a5a6;">Questo è un messaggio automatico. Non rispondere a questa email.</p>
                </div>
            </body>
        </html>
        """

        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)

        # Invia l'email tramite Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
            server.sendmail(GMAIL_EMAIL, email, message.as_string())

        print(f"[✓] Email OTP inviata a {email}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[!] Errore: Credenziali Gmail non valide. Verifica email e password in .env")
        return False
    except Exception as e:
        print(f"[!] Errore nell'invio dell'email: {e}")
        return False


def verify_otp(email, otp_code):
    """
    Verifica il codice OTP fornito dall'utente.
    Restituisce True se valido e non scaduto, False altrimenti.
    """
    email = email.lower()

    if email not in _otp_store:
        return False

    stored_otp = _otp_store[email]

    # Controlla se il codice è scaduto
    if datetime.now().timestamp() > stored_otp["expires"]:
        del _otp_store[email]
        return False

    # Controlla se il codice corrisponde
    if stored_otp["code"] == otp_code:
        del _otp_store[email]
        return True

    return False


def is_otp_expired(email):
    """Controlla se il codice OTP è scaduto."""
    email = email.lower()

    if email not in _otp_store:
        return True

    if datetime.now().timestamp() > _otp_store[email]["expires"]:
        del _otp_store[email]
        return True

    return False


def resend_otp(email, name="Utente"):
    """Invia un nuovo codice OTP all'email, invalidando il precedente."""
    # Rimuove il codice vecchio se esiste
    if email.lower() in _otp_store:
        del _otp_store[email.lower()]

    # Invia un nuovo codice
    return send_otp_email(email, name)


def get_otp_expiry_time(email):
    """Restituisce il tempo di scadenza del codice OTP in secondi."""
    email = email.lower()

    if email not in _otp_store:
        return 0

    expires_timestamp = _otp_store[email]["expires"]
    time_remaining = expires_timestamp - datetime.now().timestamp()

    return max(0, int(time_remaining))
