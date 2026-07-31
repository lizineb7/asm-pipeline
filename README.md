ASM Pipeline — Attack Surface Management

Outil léger de cartographie et d'analyse de la surface d'attaque d'un domaine web. 
À partir d'un simple nom de domaine, l'outil découvre automatiquement les sous-domaines exposés, identifie les technologies et ports actifs, détecte les vulnérabilités connues (CVEs, mauvaises configurations), recherche des secrets exposés dans le code JavaScript public, historise chaque scan en base de données, et génère un rapport HTML/PDF consultable via un dashboard web.

*Fonctionnalités

- Découverte de sous-domaines via [Subfinder](https://github.com/projectdiscovery/subfinder)
- Résolution DNS de chaque sous-domaine
- Enrichissement réseau via l'API [Shodan](https://www.shodan.io/) (ports, services connus)
- Détection de technologies et headers HTTP via `httpx`
- Scan de vulnérabilités (CVEs, misconfigurations) via [Nuclei](https://github.com/projectdiscovery/nuclei)
- Détection de secrets exposés dans les fichiers JS (clés API, tokens JWT) et d'endpoints sensibles (`/.env`, `/admin`, etc.)
- Historisation complète des scans dans une base SQLite
- API REST (FastAPI) pour piloter les scans et consulter les résultats
- Rapport HTML/PDF automatisé, trié par sévérité, avec légende explicative
- Dashboard web (thème clair/sombre) pour lancer des scans et suivre leur avancement en temps réel

*Architecture du pipeline

Domaine cible
│
▼
Subfinder ──► Résolution DNS ──► httpx (technos/headers)
│ │
│ ▼
│ Nuclei (CVEs)
│ │
│ ▼
│ Secrets JS / Endpoints sensibles
│ │
▼ ▼
Base SQLite (historisation)
│
▼
API REST (FastAPI) ──► Dashboard web
│
▼
Rapport HTML / PDF

*Structure du projet

PROJET-STAGE/
├── tools/                    # Binaires externes (non versionnés, voir installation)
│   ├── subfinder.exe
│   └── nuclei.exe
├── templates/
│   └── report.html           # Template Jinja2 du rapport
├── static/
│   └── dashboard.html        # Dashboard web (HTML/CSS/JS)
├── subfinder_scanner.py       # Découverte de sous-domaines
├── shodan_scanner.py          # Enrichissement via l'API Shodan
├── httpx_scanner.py           # Détection technologies/headers HTTP
├── nuclei_scanner.py          # Scan de vulnérabilités
├── secrets_scanner.py         # Détection de secrets JS et endpoints sensibles
├── database.py                # Persistance SQLite (schéma + fonctions CRUD)
├── main_scanner.py            # Orchestrateur du pipeline complet
├── report_generator.py        # Génération des rapports HTML/PDF
├── api.py                     # API REST FastAPI + service du dashboard
├── requirements.txt
├── .env                       # Clé API Shodan (non versionné, à créer)
└── .gitignore

*Prérequis

- Python 3.12+ (installation officielle depuis [python.org](https://www.python.org/downloads/), pas une distribution MSYS2/MinGW)
- Un compte Shodan (gratuit ou payant) pour la clé API — [shodan.io](https://www.shodan.io/)
- Subfinder et Nuclei (exécutables, voir installation ci-dessous)

*Installation

1. Cloner le dépôt

powershell
git clone https://github.com/lizineb7/asm-pipeline.git
cd asm-pipeline


2. Créer et activer l'environnement virtuel

powershell
python -m venv venv
.\venv\Scripts\Activate.ps1


3. Installer les dépendances Python

powershell
pip install -r requirements.txt


4. Configurer la clé API Shodan

Créez un fichier `.env` à la racine du projet :
SHODAN_API_KEY=votre_cle_shodan_ici


5. Installer les outils externes

Créez le dossier `tools/` à la racine, puis téléchargez :

- Subfinder : release Windows depuis [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder/releases) → placez `subfinder.exe` dans `tools/`
- Nuclei : release Windows depuis [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) → placez `nuclei.exe` dans `tools/`

Téléchargez ensuite les templates Nuclei (une seule fois) :
powershell
.\tools\nuclei.exe -update-templates


*Utilisation

-En ligne de commande
powershell
python main_scanner.py

Entrez un domaine cible (ex: `nmap.org`) — le pipeline complet s'exécute et enregistre les résultats en base.

-Via l'API et le dashboard web
powershell
uvicorn api:app --reload

Puis ouvrez : `http://127.0.0.1:8000/`

- Dashboard : `http://127.0.0.1:8000/` — lancer des scans, suivre leur avancement, consulter/télécharger les rapports
- Documentation API interactive : `http://127.0.0.1:8000/docs`

Routes API disponibles

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/api/scan` | Démarre un nouveau scan (`{"domain": "exemple.com"}`) |
| `GET` | `/api/scans` | Liste tous les scans effectués |
| `GET` | `/api/scan/{id}/results` | Détails complets d'un scan (JSON) |
| `GET` | `/api/scan/{id}/report.html` | Rapport au format HTML |
| `GET` | `/api/scan/{id}/report.pdf` | Rapport au format PDF (téléchargement) |
| `DELETE` | `/api/scan/{id}` | Supprime un scan et ses données associées |

*Modèle de données

- `scans` : un scan par domaine analysé (statut, dates, progression)
- `assets` : un sous-domaine découvert par scan (IP, ports, technologies)
- `vulnerabilities` : une vulnérabilité/finding par asset (titre, sévérité, description)

*Limitations connues

- L'enrichissement Shodan dépend du quota de requêtes du compte utilisé (`query_credits`) — un compte gratuit à 0 crédit renvoie des résultats vides sans bloquer le reste du pipeline.
- Nuclei étant un scanner actif, n'utiliser cet outil que sur des domaines pour lesquels vous avez une autorisation explicite de scan (ex: `scanme.nmap.org`, `testphp.vulnweb.com`).
- Les binaires `subfinder.exe`/`nuclei.exe` ne sont pas versionnés (voir `.gitignore`) — à télécharger séparément selon l'étape d'installation.

*Cibles de test recommandées

- `scanme.nmap.org` — domaine de démonstration officiel de Nmap
- `testphp.vulnweb.com` / `vulnweb.com` — sites de démonstration Acunetix, volontairement vulnérables
