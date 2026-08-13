"""
Authentification CryptoLab.

Sous-systeme volontairement isole du reste de l'API : la crypto pedagogique
(utils/) est ecrite pour etre lue, pas pour etre sure. L'authentification, elle,
utilise exclusivement des primitives de production (bcrypt, PyJWT).

Aucun mot de passe n'est jamais stocke, journalise ou renvoye en clair.
"""
