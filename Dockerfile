# Image de base : Linux minimal avec Python 3.11 déjà installé
FROM python:3.11-slim

# Installation des outils système nécessaires pour télécharger et
# décompresser les binaires Subfinder/Nuclei
RUN apt-get update && apt-get install -y wget unzip && \
    rm -rf /var/lib/apt/lists/*

# Installation de Subfinder (version Linux)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip -d /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_amd64.zip && \
    chmod +x /usr/local/bin/subfinder

# Installation de Nuclei (version Linux) + téléchargement des templates
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip && \
    unzip nuclei_3.3.2_linux_amd64.zip -d /usr/local/bin/ && \
    rm nuclei_3.3.2_linux_amd64.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -update-templates

# Dossier de travail à l'intérieur du conteneur
WORKDIR /app

# Copie et installation des dépendances Python (fait avant de copier tout
# le code : Docker met en cache cette étape, donc les reconstructions
# suivantes seront plus rapides si requirements.txt ne change pas)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie de tout le reste du projet
COPY . .

# Commande exécutée au démarrage du conteneur
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]