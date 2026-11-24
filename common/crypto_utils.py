"""STMA - Ortak kriptografi fonksiyonları (sunucu ve istemci kullanır)."""
import base64
import hashlib
import hmac
import os

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad

RSA_BITS = 2048
DES_KEY_SIZE = 8      # DES anahtarı 8 baytır
DES_BLOCK = 8

# ---------------------------------------------------------------- yardımcılar
def b64e(data: bytes) -> str:
    """Baytı yazıya çevirir (JSON içinde gönderebilmek için)."""
    return base64.b64encode(data).decode("ascii")

def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))

# ---------------------------------------------------------------- DES
def generate_des_key() -> bytes:
    return get_random_bytes(DES_KEY_SIZE)

def des_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """DES-CBC ile şifreler. (iv, şifreli_metin) döner."""
    iv = get_random_bytes(DES_BLOCK)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(plaintext, DES_BLOCK))

def des_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES_BLOCK)

# ---------------------------------------------------------------- RSA
def generate_rsa_keypair(bits: int = RSA_BITS) -> RSA.RsaKey:
    return RSA.generate(bits)

def export_public_key(key: RSA.RsaKey) -> str:
    """Açık anahtarı PEM metni olarak verir (ağdan göndermek için)."""
    return key.publickey().export_key().decode("ascii")

def import_key(pem: str) -> RSA.RsaKey:
    return RSA.import_key(pem)

def rsa_encrypt(public_key: RSA.RsaKey, data: bytes) -> bytes:
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(data)

def rsa_decrypt(private_key: RSA.RsaKey, data: bytes) -> bytes:
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(data)

def key_fingerprint(public_pem: str) -> str:
    """Açık anahtarın kısa parmak izi (ekranda göstermek için)."""
    digest = hashlib.sha256(public_pem.encode("ascii")).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, 16, 2)).upper()
# ---------------------------------------------------------------- imza
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sign(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """Verinin SHA-256 özetini RSA-PSS ile imzalar."""
    return pss.new(private_key).sign(SHA256.new(data))

def verify(public_key: RSA.RsaKey, data: bytes, signature: bytes) -> bool:
    try:
        pss.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False

# ---------------------------------------------------------------- parola
PBKDF2_ROUNDS = 100_000

def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """(salt, hash) döner. Parola veritabanında asla açık tutulmaz."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return b64e(salt), b64e(digest)

def check_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    _, digest = hash_password(password, b64d(salt_b64))
    return hmac.compare_digest(digest, hash_b64)