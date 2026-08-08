"""
nuclei_scanner.py

Module autonome pour exécuter Nuclei sur une URL cible et récupérer les
vulnérabilités/misconfigurations détectées, sous une forme prête à insérer
dans la table `vulnerabilities`.

"""

import json
import time
import subprocess
from pathlib import Path
from typing import Any
import os


import shutil
import platform

BASE_DIR: Path = Path(__file__).resolve().parent

def _find_nuclei() -> Path:
    """
    Cherche l'exécutable nuclei : d'abord dans le PATH système (cas
    du déploiement Linux/Docker, où l'outil est installé globalement),
    sinon dans tools/ (cas du développement local Windows).
    """
    system_path = shutil.which("nuclei")
    if system_path:
        return Path(system_path)

    exe_name = "nuclei.exe" if platform.system() == "Windows" else "nuclei"
    return BASE_DIR / "tools" / exe_name

NUCLEI_PATH: Path = _find_nuclei()

# Correspondance entre les sévérités renvoyées par Nuclei (minuscules) et
# les valeurs acceptées par la contrainte CHECK de la table vulnerabilities.
SEVERITY_MAPPING: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Info",  # repli si Nuclei ne classe pas la sévérité
}


def run_nuclei(target_url: str, timeout: int = 450) -> list[dict[str, Any]]:
    """
    Exécute Nuclei sur une URL cible et retourne la liste des findings
    détectés (CVEs, misconfigurations, headers manquants, etc.).

    Args:
        target_url: L'URL à scanner (ex: "https://scanme.nmap.org").
        timeout: Délai maximal d'exécution en secondes pour cette cible.

    Returns:
        Une liste de dictionnaires, chacun avec les clés :
            - "titre_cve": nom/identifiant du finding
            - "severite": 'Critical', 'High', 'Medium', 'Low' ou 'Info'
            - "description": description du problème détecté
        Liste vide si rien trouvé ou en cas d'erreur.
    """

    if not NUCLEI_PATH.is_file():
        print(f"[ERREUR] Exécutable introuvable : {NUCLEI_PATH}")
        return []

    # -jsonl        : une ligne JSON par finding, directement sur stdout
    # -silent       : pas de bannière/logo, juste les résultats
    # -severity     : on exclut volontairement "unknown" pour rester sur
    #                 des résultats classés (templates légers, non intrusifs)
    # -timeout      : délai par requête HTTP individuelle de Nuclei (secondes)
    # -no-color     : évite les codes couleur ANSI qui polluent le JSON
    #"-rate-limit"  : limite le nombre de requêtes/seconde envoyées, pour éviter de déclencher un blocage côté serveur
    #"-ni"          : désactive les templates nécessitant un serveur externe (interactsh/OAST)
    # "-bulk-size", "10",       # nombre d'hôtes traités en parallèle (par défaut plus élevé)
    # "-concurrency", "10",     # nombre de templates exécutés en parallèle    

    command: list[str] = [
        str(NUCLEI_PATH),
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-severity", "info,low,medium,high,critical",  
        "-timeout", "5",
        "-rate-limit", "15", 
        "-ni",     
        "-bulk-size", "1",      
        "-concurrency", "3",
        "-disable-clustering", # Empêche le regroupement lourd de requêtes en mémoire
        "-duc",
        "-tags", "cve,misconfig,exposure", # <--- Limite drastiquement les templates chargés
    ]

    start_time = time.time()

    # --- Brider le runtime Go ---
    custom_env = os.environ.copy()
    custom_env["GOMAXPROCS"] = "1"

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Nuclei peut retourner un code non-zéro même en
                          # fonctionnement normal (ex: cible injoignable
                          # sur certains templates) ; on gère ça via le
                          # contenu plutôt que via le code de retour strict.
            env=custom_env,
        )

    except FileNotFoundError:
        print(f"[ERREUR] Impossible de lancer l'exécutable : {NUCLEI_PATH}")
        return []

    except subprocess.TimeoutExpired:
        print(f"  [WARN] Nuclei a dépassé le délai de {timeout}s sur {target_url}")
        return []

    except Exception as e:
        print(f"  [ERREUR] Erreur inattendue lors du scan Nuclei sur {target_url} : {e}")
        return []

    if result.stderr and result.stderr.strip():
        print(f"  [DEBUG NUCLEI] stderr : {result.stderr.strip()[:300]}")

    print(f"[DEBUG NUCLEI] Scan terminé pour {target_url}. Lignes JSON récupérées : {len(result.stdout.splitlines())}")

    findings: list[dict[str, Any]] = []

    # Chaque ligne de stdout est un objet JSON indépendant (format -jsonl).
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            raw_finding: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            # Ligne non-JSON (rare, mais on ignore plutôt que de planter)
            continue

        info: dict[str, Any] = raw_finding.get("info", {})

        titre: str = info.get("name") or raw_finding.get("template-id", "Finding Nuclei")
        raw_severity: str = (info.get("severity") or "unknown").lower()
        severite: str = SEVERITY_MAPPING.get(raw_severity, "Info")
        description: str = info.get("description") or raw_finding.get("matched-at", "")

        findings.append({
            "titre_cve": titre,
            "severite": severite,
            "description": description,
        })

    return findings


# ---------------------------------------------------------------------------
# Bloc de test manuel
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_url: str = ""

    print(f"[INFO] Lancement de Nuclei sur : {test_url}")
    print("[INFO] Ça peut prendre 30s à 2 minutes selon le nombre de templates...")

    results = run_nuclei(test_url)

    if results:
        print(f"[OK] {len(results)} finding(s) détecté(s) :")
        for finding in results:
            print(f"  - [{finding['severite']}] {finding['titre_cve']}")
    else:
        print("[INFO] Aucun finding détecté (ou erreur pendant l'exécution).")