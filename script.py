#AdvComArc TP4 - 3G & LTE Mouti Amir, Barreira Romero Adrian

"""
================================================================================
  TSM-AdvComArch - TP Securite 3G et LTE
  Simulation d'une authentification mutuelle client/serveur (style AKA/UMTS)
================================================================================

ETAPES IMPLEMENTEES :
  1. Etablissement de la connexion (simulation via sockets locaux + threads)
  2. Cle secrete partagee Ki (256 bits)
  3. Authentification du client  : challenge RAND -> verification SRES
  4. Authentification du serveur : token AUTN -> verification XMAC
  5. Generation d'une cle temporaire Kc (valide 20 minutes)
  6. Chiffrement/dechiffrement d'un paquet de 250 bits (32 octets)

Algorithmes utilises (stdlib uniquement) :
  - HMAC-SHA256  -> fonctions f1 (MAC), f2 (SRES/RES), f3 (CK), f4 (IK), f5 (AK)
  - XOR stream   -> chiffrement symetrique (simplifie, illustratif)
  - hashlib.sha256 pour la derivation de cles
================================================================================
"""

import hashlib
import hmac
import os
import secrets
import socket
import struct
import threading
import time
from datetime import datetime, timedelta


# =============================================================================
# SECTION 1 : FONCTIONS MILENAGE SIMPLIFIEES (f1 ... f5)
#   Basees sur HMAC-SHA256 au lieu d'AES-128 pour rester en stdlib pure.
#   L'architecture et les roles de chaque fonction restent fideles au standard.
# =============================================================================

def _prf(key: bytes, data: bytes, label: bytes) -> bytes:
    """Pseudo-Random Function interne : HMAC-SHA256(key, label || data)."""
    return hmac.new(key, label + data, hashlib.sha256).digest()


def f1(Ki: bytes, RAND: bytes, SQN: bytes, AMF: bytes) -> bytes:
    """f1 : calcul du MAC (Message Authentication Code) -- 8 octets."""
    return _prf(Ki, RAND + SQN + AMF, b"f1")[:8]


def f2(Ki: bytes, RAND: bytes) -> bytes:
    """f2 : calcul de XRES/SRES (reponse attendue) -- 4 octets (32 bits)."""
    return _prf(Ki, RAND, b"f2")[:4]


def f3(Ki: bytes, RAND: bytes) -> bytes:
    """f3 : derivation de CK (Cipher Key) -- 16 octets."""
    return _prf(Ki, RAND, b"f3")[:16]


def f4(Ki: bytes, RAND: bytes) -> bytes:
    """f4 : derivation de IK (Integrity Key) -- 16 octets."""
    return _prf(Ki, RAND, b"f4")[:16]


def f5(Ki: bytes, RAND: bytes) -> bytes:
    """f5 : derivation de AK (Anonymity Key) -- 6 octets."""
    return _prf(Ki, RAND, b"f5")[:6]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR octet-a-octet (longueurs egales)."""
    return bytes(x ^ y for x, y in zip(a, b))


# =============================================================================
# SECTION 2 : CHIFFREMENT XOR-STREAM (illustratif, inspire KASUMI/SNOW3G)
# =============================================================================

def generate_keystream(Kc: bytes, nonce: bytes, length: int) -> bytes:
    """
    Genere un keystream de `length` octets a partir de Kc et d'un nonce,
    en enchainant des blocs SHA-256 (construction CTR simplifiee).
    """
    stream = b""
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(Kc + nonce + counter.to_bytes(4, "big")).digest()
        stream += block
        counter += 1
    return stream[:length]


def encrypt_packet(Kc: bytes, plaintext: bytes):
    """Chiffre un paquet ; retourne (nonce, ciphertext)."""
    nonce = secrets.token_bytes(16)
    keystream = generate_keystream(Kc, nonce, len(plaintext))
    return nonce, xor_bytes(plaintext, keystream)


def decrypt_packet(Kc: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Dechiffre un paquet avec le meme nonce."""
    keystream = generate_keystream(Kc, nonce, len(ciphertext))
    return xor_bytes(ciphertext, keystream)


# =============================================================================
# SECTION 3 : GENERATION DU VECTEUR D'AUTHENTIFICATION (cote AuC/reseau)
# =============================================================================

def generate_auth_vector(Ki: bytes, SQN: int, AMF: bytes) -> dict:
    """
    Genere le vecteur d'authentification (AV) :
      RAND  -> alea 128 bits
      AK    = f5(Ki, RAND)
      MAC   = f1(Ki, RAND, SQN, AMF)
      AUTN  = (SQN XOR AK) || AMF || MAC
      XRES  = f2(Ki, RAND)
      CK    = f3(Ki, RAND)
      IK    = f4(Ki, RAND)
    """
    RAND = secrets.token_bytes(16)                    # 128 bits aleatoires
    SQN_bytes = SQN.to_bytes(6, "big")               # 48 bits

    AK   = f5(Ki, RAND)                              # 48 bits
    MAC  = f1(Ki, RAND, SQN_bytes, AMF)              # 64 bits
    XRES = f2(Ki, RAND)                              # 32 bits
    CK   = f3(Ki, RAND)                              # 128 bits
    IK   = f4(Ki, RAND)                              # 128 bits

    SQN_xor_AK = xor_bytes(SQN_bytes, AK)           # SQN XOR AK
    AUTN = SQN_xor_AK + AMF + MAC                   # token reseau -> mobile

    return {
        "RAND":  RAND,
        "AUTN":  AUTN,
        "XRES":  XRES,
        "CK":    CK,
        "IK":    IK,
        "AK":    AK,
        "MAC":   MAC,
        "SQN":   SQN_bytes,
    }


# =============================================================================
# SECTION 4 : VERIFICATION COTE USIM/CLIENT
# =============================================================================

def usim_process_challenge(Ki: bytes, RAND: bytes, AUTN: bytes, expected_SQN: int) -> dict:
    """
    Le client (USIM) recoit RAND et AUTN, et :
      1. Recalcule AK = f5(Ki, RAND)
      2. Extrait SQN = (SQN XOR AK) XOR AK
      3. Recalcule XMAC = f1(Ki, RAND, SQN, AMF)
      4. Verifie XMAC == MAC (authentification du reseau)
      5. Verifie SQN (protection replay)
      6. Calcule RES = f2(Ki, RAND)
    """
    AK         = f5(Ki, RAND)
    SQN_xor_AK = AUTN[:6]
    AMF        = AUTN[6:8]
    MAC        = AUTN[8:16]

    SQN_bytes = xor_bytes(SQN_xor_AK, AK)
    SQN_int   = int.from_bytes(SQN_bytes, "big")

    XMAC = f1(Ki, RAND, SQN_bytes, AMF)

    mac_ok = hmac.compare_digest(XMAC, MAC)
    sqn_ok = (SQN_int >= expected_SQN)           # anti-rejeu basique

    RES = f2(Ki, RAND)
    CK  = f3(Ki, RAND)
    IK  = f4(Ki, RAND)

    return {
        "SQN":    SQN_bytes,
        "XMAC":   XMAC,
        "MAC":    MAC,
        "mac_ok": mac_ok,
        "sqn_ok": sqn_ok,
        "RES":    RES,
        "CK":     CK,
        "IK":     IK,
    }


# =============================================================================
# SECTION 5 : DERIVATION DE LA CLE TEMPORAIRE Kc (valide 20 min)
# =============================================================================

def derive_session_key(CK: bytes, IK: bytes, validity_minutes: int = 20) -> dict:
    """
    Kc = SHA-256(CK || IK || timestamp_tranche)
    Le timestamp est tronque a la tranche de validity_minutes minutes,
    ce qui invalide automatiquement Kc apres la fenetre.
    """
    now     = datetime.utcnow()
    tranche = now.replace(
        minute=(now.minute // validity_minutes) * validity_minutes,
        second=0, microsecond=0
    )
    ts_bytes = tranche.strftime("%Y%m%d%H%M").encode()
    Kc = hashlib.sha256(CK + IK + ts_bytes).digest()   # 256 bits

    expiry = tranche + timedelta(minutes=validity_minutes)
    return {"Kc": Kc, "expires_at": expiry}


# =============================================================================
# SECTION 6 : SIMULATION RESEAU CLIENT / SERVEUR (sockets locaux + threads)
# =============================================================================

SEPARATOR = b"||SEP||"
PORT      = 40000


def send_msg(sock, *parts):
    payload = SEPARATOR.join(parts)
    header  = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_msg(sock):
    raw_len = _recvall(sock, 4)
    length  = struct.unpack("!I", raw_len)[0]
    payload = _recvall(sock, length)
    return payload.split(SEPARATOR)


def _recvall(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connexion fermee prematurement")
        data += chunk
    return data


def log(who, msg):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] [{who:^8}] {msg}")


# -----------------------------------------------------------------------------
# SERVEUR
# -----------------------------------------------------------------------------

def run_server(Ki, SQN, AMF, data_packet):
    """
    Logique serveur (AuC + reseau) :
      1. Attend la connexion du client
      2. Genere le vecteur d'authentification
      3. Envoie RAND + AUTN au client (challenge)
      4. Recoit RES du client et verifie (== XRES)
      5. Derive Kc, envoie un paquet chiffre au client
      6. Recoit et dechiffre le paquet envoye par le client
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    log("SERVEUR", f"En ecoute sur le port {PORT}...")

    conn, addr = srv.accept()
    log("SERVEUR", f"Client connecte depuis {addr}")

    # Etape 2 : generation du vecteur d'authentification
    av = generate_auth_vector(Ki, SQN, AMF)
    log("SERVEUR", "Vecteur d'authentification genere :")
    log("SERVEUR", f"  RAND  = {av['RAND'].hex()}")
    log("SERVEUR", f"  AUTN  = {av['AUTN'].hex()}")
    log("SERVEUR", f"  XRES  = {av['XRES'].hex()}")
    log("SERVEUR", f"  CK    = {av['CK'].hex()}")
    log("SERVEUR", f"  IK    = {av['IK'].hex()}")
    log("SERVEUR", f"  AK    = {av['AK'].hex()}")
    log("SERVEUR", f"  MAC   = {av['MAC'].hex()}")

    # Etape 3 : envoi du challenge RAND + AUTN
    send_msg(conn, b"CHALLENGE", av["RAND"], av["AUTN"])
    log("SERVEUR", "Challenge (RAND + AUTN) envoye au client")

    # Etape 4 : reception et verification de RES
    parts = recv_msg(conn)
    assert parts[0] == b"RES", "Message inattendu"
    client_RES = parts[1]
    auth_ok = hmac.compare_digest(client_RES, av["XRES"])
    log("SERVEUR", f"RES recu       = {client_RES.hex()}")
    log("SERVEUR", f"XRES attendu   = {av['XRES'].hex()}")
    log("SERVEUR", f"Auth client    : {'[OK] SUCCES' if auth_ok else '[FAIL] ECHEC'}")

    if not auth_ok:
        send_msg(conn, b"AUTH_FAIL")
        conn.close(); srv.close(); return

    send_msg(conn, b"AUTH_OK")

    # Etape 5 : derivation de Kc
    session = derive_session_key(av["CK"], av["IK"])
    Kc = session["Kc"]
    log("SERVEUR", f"Kc derivee     = {Kc.hex()}")
    log("SERVEUR", f"Kc valide jusqu'a {session['expires_at'].strftime('%H:%M UTC')}")

    # Etape 6a : serveur -> client (paquet chiffre)
    nonce_s, cipher_s = encrypt_packet(Kc, data_packet)
    log("SERVEUR", f"Paquet clair   = {data_packet.hex()}")
    log("SERVEUR", f"Paquet chiffre = {cipher_s.hex()}")
    send_msg(conn, b"ENCRYPTED", nonce_s, cipher_s)
    log("SERVEUR", "Paquet chiffre envoye au client")

    # Etape 6b : reception du paquet client
    parts = recv_msg(conn)
    assert parts[0] == b"ENCRYPTED"
    nonce_c, cipher_c = parts[1], parts[2]
    plain_c = decrypt_packet(Kc, nonce_c, cipher_c)
    log("SERVEUR", f"Paquet recu (chiffre) = {cipher_c.hex()}")
    log("SERVEUR", f"Paquet dechiffre      = {plain_c.hex()}")
    log("SERVEUR", f"Contenu               = {plain_c}")

    conn.close()
    srv.close()
    log("SERVEUR", "Connexion fermee.")


# -----------------------------------------------------------------------------
# CLIENT (USIM)
# -----------------------------------------------------------------------------

def run_client(Ki, expected_SQN, data_packet):
    """
    Logique client (UE + USIM) :
      1. Se connecte au serveur
      2. Recoit RAND + AUTN
      3. Verifie l'authenticite du reseau (XMAC) et repond avec RES
      4. Derive Kc, dechiffre le paquet serveur
      5. Envoie un paquet chiffre au serveur
    """
    time.sleep(0.3)
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(("127.0.0.1", PORT))
    log("CLIENT",  f"Connecte au serveur sur le port {PORT}")

    # Reception du challenge
    parts = recv_msg(conn)
    assert parts[0] == b"CHALLENGE"
    RAND, AUTN = parts[1], parts[2]
    log("CLIENT",  f"RAND recu  = {RAND.hex()}")
    log("CLIENT",  f"AUTN recu  = {AUTN.hex()}")

    # Traitement USIM
    usim = usim_process_challenge(Ki, RAND, AUTN, expected_SQN)
    log("CLIENT",  f"XMAC calcule     = {usim['XMAC'].hex()}")
    log("CLIENT",  f"MAC dans AUTN    = {usim['MAC'].hex()}")
    log("CLIENT",  f"Verif. MAC       : {'[OK] SUCCES' if usim['mac_ok'] else '[FAIL] ECHEC'}")
    log("CLIENT",  f"Verif. SQN       : {'[OK] valide' if usim['sqn_ok'] else '[FAIL] REJEU'}")

    if not usim["mac_ok"] or not usim["sqn_ok"]:
        log("CLIENT", "Authentification du reseau ECHOUEE -- abandon")
        conn.close(); return

    log("CLIENT",  "Reseau authentifie [OK] -- envoi de RES")
    send_msg(conn, b"RES", usim["RES"])

    # Reception du statut serveur
    parts = recv_msg(conn)
    if parts[0] != b"AUTH_OK":
        log("CLIENT", "Le serveur a rejete notre RES [FAIL]")
        conn.close(); return
    log("CLIENT",  "Serveur confirme l'authentification [OK]")

    # Derivation de Kc
    session = derive_session_key(usim["CK"], usim["IK"])
    Kc = session["Kc"]
    log("CLIENT",  f"Kc derivee = {Kc.hex()}")

    # Reception et dechiffrement du paquet serveur
    parts = recv_msg(conn)
    assert parts[0] == b"ENCRYPTED"
    nonce_s, cipher_s = parts[1], parts[2]
    plain_s = decrypt_packet(Kc, nonce_s, cipher_s)
    log("CLIENT",  f"Paquet recu (chiffre) = {cipher_s.hex()}")
    log("CLIENT",  f"Paquet dechiffre      = {plain_s.hex()}")
    log("CLIENT",  f"Contenu               = {plain_s}")

    # Envoi d'un paquet chiffre au serveur
    nonce_c, cipher_c = encrypt_packet(Kc, data_packet)
    log("CLIENT",  f"Paquet a envoyer (clair)  = {data_packet.hex()}")
    log("CLIENT",  f"Paquet chiffre            = {cipher_c.hex()}")
    send_msg(conn, b"ENCRYPTED", nonce_c, cipher_c)
    log("CLIENT",  "Paquet chiffre envoye au serveur")

    conn.close()
    log("CLIENT",  "Connexion fermee.")


# =============================================================================
# POINT D'ENTREE
# =============================================================================

if __name__ == "__main__":

    print("=" * 72)
    print("  TSM-AdvComArch -- TP Securite 3G/LTE")
    print("  Authentification mutuelle AKA + chiffrement de paquets")
    print("=" * 72)

    # Parametres partages
    Ki  = secrets.token_bytes(32)          # cle privee Ki (256 bits)
    AMF = b"\x80\x00"                      # Authentication Management Field
    SQN = 42                               # numero de sequence initial

    # Paquet de 250 bits utiles -> on utilise 32 octets (256 bits, padding nul)
    SERVER_PACKET = secrets.token_bytes(32)
    CLIENT_PACKET = b"Hello from USIM! [250b]"[:32].ljust(32, b"\x00")

    print(f"\n{'-'*72}")
    print(f"  Parametres initiaux")
    print(f"{'-'*72}")
    print(f"  Ki  (256 bits) = {Ki.hex()}")
    print(f"  AMF            = {AMF.hex()}")
    print(f"  SQN initial    = {SQN}")
    print(f"  Paquet serveur = {SERVER_PACKET.hex()}")
    print(f"  Paquet client  = {CLIENT_PACKET.hex()}")
    print(f"{'-'*72}\n")

    # Lancement serveur dans un thread
    t_server = threading.Thread(
        target=run_server,
        args=(Ki, SQN, AMF, SERVER_PACKET),
        daemon=True
    )
    t_server.start()

    # Lancement client dans le thread principal
    run_client(Ki, SQN, CLIENT_PACKET)

    t_server.join(timeout=5)

    print(f"\n{'='*72}")
    print("  Simulation terminee avec succes [OK]")
    print(f"{'='*72}\n")