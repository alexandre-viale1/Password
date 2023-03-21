import re
import hashlib

# Fonction pour vérifier si le mot de passe est valide
def password_validation(password):
    # Au moins 8 caractères
    if len(password) < 8:
        return False
    # Au moins une lettre majuscule
    if not re.search(r'[A-Z]', password):
        return False
    # Au moins une lettre minuscule
    if not re.search(r'[a-z]', password):
        return False
    # Au moins un chiffre
    if not re.search(r'\d', password):
        return False
    # Au moins un caractère spécial
    if not re.search(r'[!@#$%^&*]', password):
        return False
    return True

# Demande à l'utilisateur de choisir un mot de passe et vérifie s'il est valide
while True:
    password = input("Entrez votre mot de passe : ")
    if password_validation(password):
        print("Mot de passe valide!")
        break
    else:
        print("Mot de passe invalide. Veuillez choisir un mot de passe contenant au moins 8 caractères, une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial (!, @, #, $, %, ^, &, *).")

# Hache le mot de passe en utilisant SHA-256
hashed_password = hashlib.sha256(password.encode()).hexdigest()
print("Le mot de passe haché est :", hashed_password)
