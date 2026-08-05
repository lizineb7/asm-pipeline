"""
subfinder_scanner.py

Module autonome pour exécuter Subfinder (outil externe) via subprocess
et récupérer la liste des sous-domaines découverts.

"""

import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration du chemin vers l'exécutable
# ---------------------------------------------------------------------------


import shutil
import platform

BASE_DIR: Path = Path(__file__).resolve().parent

def _find_subfinder() -> Path:
    """
    Cherche l'exécutable Subfinder : d'abord dans le PATH système (cas
    du déploiement Linux/Docker, où l'outil est installé globalement),
    sinon dans tools/ (cas du développement local Windows).
    """
    system_path = shutil.which("subfinder")
    if system_path:
        return Path(system_path)

    exe_name = "subfinder.exe" if platform.system() == "Windows" else "subfinder"
    return BASE_DIR / "tools" / exe_name

SUBFINDER_PATH: Path = _find_subfinder()


def run_subfinder(domain: str, timeout: int = 60) -> list[str]:
    """
    Exécute Subfinder sur un domaine donné et retourne la liste des
    sous-domaines trouvés.

    Args:
        domain: Le domaine cible (ex: "scanme.nmap.org").
        timeout: Délai maximal d'exécution en secondes (évite un blocage
                 infini si Subfinder reste bloqué, ex: souci réseau).

    Returns:
        Une liste de sous-domaines (list[str]). Liste vide si aucun
        résultat ou en cas d'erreur gérée.
    """

    # --- Étape 1 : Vérifier que l'exécutable existe avant de lancer quoi que ce soit ---
    if not SUBFINDER_PATH.is_file():
        print(f"[ERREUR] Exécutable introuvable : {SUBFINDER_PATH}")
        print("Vérifiez que subfinder.exe est bien présent dans le dossier ./tools/")
        return []

    # --- Étape 2 : Construire la commande ---
    # Subfinder : -d <domaine> pour cibler un domaine, -silent pour n'avoir
    # que les résultats bruts (un sous-domaine par ligne, sans bannière/logo).
    command: list[str] = [
        str(SUBFINDER_PATH),
        "-d", domain,
        "-silent",
    ]

    # --- Étape 3 : Exécution sécurisée avec subprocess.run ---
    try:
        result = subprocess.run(
            command,
            capture_output=True,   # récupère stdout/stderr au lieu de les afficher
            text=True,             # décode automatiquement en str (pas de bytes)
            check=True,            # lève une exception si code de retour != 0
            timeout=timeout,       # évite un blocage indéfini
        )

    except FileNotFoundError:
        # Cas où le chemin est invalide ou l'OS ne trouve pas l'exécutable
        print(f"[ERREUR] Impossible de lancer l'exécutable : {SUBFINDER_PATH}")
        return []

    except subprocess.TimeoutExpired:
        print(f"[ERREUR] Subfinder a dépassé le délai de {timeout}s (timeout).")
        return []

    except subprocess.CalledProcessError as e:
        # Cas où Subfinder démarre mais retourne un code d'erreur
        # (ex: argument invalide, domaine mal formé, etc.)
        print(f"[ERREUR] Subfinder a échoué (code {e.returncode}).")
        if e.stderr:
            print(f"Détail stderr : {e.stderr.strip()}")
        return []

    except Exception as e:
        # Filet de sécurité générique pour toute autre erreur imprévue
        print(f"[ERREUR] Erreur inattendue lors de l'exécution : {e}")
        return []

    # --- Étape 4 : Nettoyage de la sortie brute ---
    raw_output: str = result.stdout

    subdomains: list[str] = [
        line.strip()
        for line in raw_output.splitlines()
        if line.strip()  # exclut les lignes vides ou uniquement des espaces
    ]

    return subdomains


# ---------------------------------------------------------------------------
# Bloc de test manuel
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_domain: str = ""

    print(f"[INFO] Lancement de Subfinder sur : {test_domain}")
    found_subdomains: list[str] = run_subfinder(test_domain)

    if found_subdomains:
        print(f"[OK] {len(found_subdomains)} sous-domaine(s) trouvé(s) :")
        for sub in found_subdomains:
            print(f"  - {sub}")
    else:
        print("[INFO] Aucun sous-domaine trouvé (ou erreur pendant l'exécution).")