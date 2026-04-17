#!/bin/bash

# On boucle sur tous les fichiers commençant par "flag_" et finissant par ".txt"
for file in flag_*.txt; do
    # Vérifie si le fichier existe pour éviter les erreurs si le dossier est vide
    [ -e "$file" ] || continue

    # 1. On extrait le numéro (ex: de "flag_12.txt" on garde "12.txt")
    number_ext="${file#flag_}"
    
    # 2. On enlève l'extension (ex: de "12.txt" on garde "12")
    number="${number_ext%.txt}"

    # 3. On renomme le fichier
    mv "$file" "${number}-flag.txt"
    
    echo "Renommé : $file -> ${number}-flag.txt"
done