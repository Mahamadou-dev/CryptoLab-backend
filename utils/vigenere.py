def vigenere_encrypt(plain_text: str, key: str) -> str:
    """
    Chiffre un texte en utilisant le chiffre de Vigenère.
    Gère les majuscules/minuscules et ignore les non-alphabétiques.
    """
    encrypted_text = ""
    key_index = 0
    key = key.upper()

    for char in plain_text:
        if 'a' <= char <= 'z':
            base = ord('a')
            key_shift = ord(key[key_index % len(key)]) - ord('A')
            encrypted_char = chr((ord(char) - base + key_shift) % 26 + base)
            encrypted_text += encrypted_char
            key_index += 1
        elif 'A' <= char <= 'Z':
            base = ord('A')
            key_shift = ord(key[key_index % len(key)]) - ord('A')
            encrypted_char = chr((ord(char) - base + key_shift) % 26 + base)
            encrypted_text += encrypted_char
            key_index += 1
        else:
            # Conserve les caractères non alphabétiques (espaces, ponctuation)
            encrypted_text += char

    return encrypted_text


def vigenere_decrypt(cipher_text: str, key: str) -> str:
    """
    Déchiffre un texte chiffré avec Vigenère.
    """
    decrypted_text = ""
    key_index = 0
    key = key.upper()

    for char in cipher_text:
        if 'a' <= char <= 'z':
            base = ord('a')
            key_shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = chr((ord(char) - base - key_shift + 26) % 26 + base)
            decrypted_text += decrypted_char
            key_index += 1
        elif 'A' <= char <= 'Z':
            base = ord('A')
            key_shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = chr((ord(char) - base - key_shift + 26) % 26 + base)
            decrypted_text += decrypted_char
            key_index += 1
        else:
            decrypted_text += char

    return decrypted_text