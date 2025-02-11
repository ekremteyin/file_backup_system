from hashlib import sha256

def hash_parola(parola):
    return sha256(parola.encode()).hexdigest()
