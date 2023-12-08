import re
import hashlib


def hasher_mot_de_passe(mot_de_passe):
    sha256 = hashlib.sha256()
    sha256.update(mot_de_passe.encode('utf-8'))
    return sha256.hexdigest()

def verifier_mot_de_passe(mot_de_passe):
    if len(mot_de_passe) < 8  or not any(c.isupper() for c in mot_de_passe) \
       or not any(c.islower() for c in mot_de_passe) \
       or not any(c.isdigit() for c in mot_de_passe) \
       or not any(c in '!@#$%^&*' for c in mot_de_passe):
        return False, None
    
    mot_de_passe_hashe = hasher_mot_de_passe(mot_de_passe)
    return True, mot_de_passe_hashe

def demander_mot_de_passe():
    while True:
        mot_de_passe = input("Choisissez un mot de passe : ")
        est_valide, mot_de_passe_hashe = verifier_mot_de_passe(mot_de_passe)
        
        if est_valide:
            print("Mot de passe valide. Mot de passe haché :", mot_de_passe_hashe)
            break
        else:
            print("Mot de passe invalide! choisissez un nouveau mot de passe.")

# Appeler la fonction pour démarrer le programme
demander_mot_de_passe()


