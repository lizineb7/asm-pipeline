"""
main_scanner.py

Script principal du pipeline ASM :
    1. Demande un domaine cible à l'utilisateur
    2. Enregistre un nouveau scan en base (statut "En cours")
    3. Subfinder -> découverte des sous-domaines
    4. Résolution DNS -> IP de chaque sous-domaine
    5. Shodan -> informations sur chaque IP unique
    6. Enregistrement de chaque asset en base
    7. Clôture du scan (statut "Terminé" ou "Erreur")
"""

import socket
import time
from typing import Any, Optional

from subfinder_scanner import run_subfinder
from shodan_scanner import run_shodan_lookup
import database
from httpx_scanner import check_http
from nuclei_scanner import run_nuclei
from secrets_scanner import scan_js_files, check_sensitive_endpoints


def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """
    Résout un nom de domaine (ou sous-domaine) en adresse IP.

    Returns:
        L'adresse IP, ou None si la résolution échoue.
    """
    try:
        return socket.gethostbyname(domain)

    except socket.gaierror:
        print(f"  [WARN] Résolution DNS impossible pour : {domain}")
        return None

    except Exception as e:
        print(f"  [WARN] Erreur inattendue lors de la résolution de {domain} : {e}")
        return None


def extract_ports_and_technologies(shodan_data: dict[str, Any]) -> tuple[list[int], list[str]]:
    """
    Extrait proprement la liste des ports ouverts et des technologies/produits
    détectés à partir du dictionnaire brut retourné par Shodan.

    Args:
        shodan_data: Le dictionnaire retourné par run_shodan_lookup.
                     Peut être vide {} si Shodan n'a rien retourné.

    Returns:
        Un tuple (ports, technologies) prêt à être passé à add_asset().
    """
    if not shodan_data:
        return [], []

    ports: list[int] = shodan_data.get("ports", [])

    # Chaque service détecté (un par port/protocole) est dans "data".
    # On récupère le champ "product" quand il existe, sans doublons.
    services: list[dict[str, Any]] = shodan_data.get("data", [])
    technologies: list[str] = []
    for service in services:
        product = service.get("product")
        if product and product not in technologies:
            technologies.append(product)

    return ports, technologies


def run_pipeline(root_domain: str, shodan_delay: float = 1.5) -> None:
    """
    Enchaîne Subfinder -> résolution DNS -> Shodan -> stockage SQLite
    pour un domaine racine donné.

    Args:
        root_domain: Le domaine cible (ex: "example.com").
        shodan_delay: Pause en secondes entre deux requêtes Shodan, pour
                      respecter le rate limiting des comptes gratuits.
    """

    # --- Création de l'entrée de scan en base, statut initial "En cours" ---
    scan_id: int = database.create_scan(root_domain)
    print(f"[INFO] Scan créé en base avec l'id {scan_id} (domaine : {root_domain})")

    try:
        # --- Étape 1 : Découverte des sous-domaines ---
        print(f"\n[1/3] Recherche des sous-domaines de {root_domain} via Subfinder...")
        subdomains: list[str] = run_subfinder(root_domain)

        if not subdomains:
            print("[STOP] Aucun sous-domaine trouvé.")
            database.update_scan_status(scan_id, "Terminé")
            return

        print(f"       -> {len(subdomains)} sous-domaine(s) trouvé(s).")
        database.update_scan_progress(scan_id, total=len(subdomains), traites=0, etape="Résolution DNS et analyse en cours...")

        # --- Étape 2 : Résolution DNS + Étape 3 : Shodan, asset par asset ---
        # On traite chaque sous-domaine dans la même boucle : on résout son
        # IP, on interroge Shodan si l'IP est nouvelle, puis on enregistre
        # l'asset en base immédiatement (pas besoin d'attendre la fin de
        # tout le scan pour commencer à écrire des résultats).
        print("\n[2/3] Résolution DNS + [3/3] Interrogation Shodan...")

        # Cache pour éviter d'interroger Shodan deux fois pour la même IP
        # (plusieurs sous-domaines pointent souvent vers le même serveur).
        shodan_cache: dict[str, dict[str, Any]] = {}
        nuclei_cache: dict[str, list[dict[str, Any]]] = {}

        for subdomain in subdomains:
            ip: Optional[str] = resolve_domain_to_ip(subdomain)

            http_info = check_http(subdomain)
            if http_info["status_code"] is not None:
                print(
                    f"  [HTTP] {subdomain} -> {http_info['status_code']} "
                    f"({http_info['server'] or 'serveur non identifié'})"
                )

            if ip is None:
                asset_id = database.add_asset(scan_id, subdomain, None, [], http_info["technologies"])
            else:
                print(f"  {subdomain} -> {ip}")

                if ip not in shodan_cache:
                    try:
                        shodan_data = run_shodan_lookup(ip)
                        shodan_cache[ip] = shodan_data
                    except Exception as e:
                        print(f"  [ERREUR] Shodan a échoué pour {ip} : {e}")
                        shodan_cache[ip] = {}
                    time.sleep(shodan_delay)

                shodan_data = shodan_cache[ip]
                ports, shodan_technologies = extract_ports_and_technologies(shodan_data)

                combined_technologies: list[str] = list(
                    dict.fromkeys(shodan_technologies + http_info["technologies"])
                )

                asset_id = database.add_asset(scan_id, subdomain, ip, ports, combined_technologies)

            # --- Nuclei : uniquement si httpx a confirmé un service web actif ---
            # Pas d'intérêt à scanner une cible qui n'a répondu ni en HTTP ni en
            # HTTPS (économise du temps, Nuclei étant plus lent que httpx).
            if http_info["status_code"] is not None and http_info["url"]:
                # On utilise l'IP comme clé de cache : si cette IP a déjà été
                # scannée par Nuclei via un autre sous-domaine dans ce même
                # run, on réutilise le résultat au lieu de rescanner la même
                # infrastructure réelle plusieurs fois (évite de saturer un
                # serveur partagé par plusieurs sous-domaines).
                cache_key = ip if ip else http_info["url"]

                if cache_key not in nuclei_cache:
                    print(f"  [NUCLEI] Scan de {http_info['url']}...")
                    nuclei_cache[cache_key] = run_nuclei(http_info["url"])
                else:
                    print(f"  [NUCLEI] IP {cache_key} déjà scannée dans ce run, résultat réutilisé.")

                findings = nuclei_cache[cache_key]

                for finding in findings:
                    database.add_vulnerability(
                        asset_id,
                        finding["titre_cve"],
                        finding["severite"],
                        finding["description"],
                    )

                if findings:
                    print(f"  [NUCLEI] {len(findings)} finding(s) enregistré(s) pour {subdomain}")

            # --- Détection de secrets JS + endpoints sensibles ---
            # Uniquement si httpx a confirmé une page active avec du HTML récupéré.
            if http_info["status_code"] is not None and http_info["html"]:
                js_findings = scan_js_files(http_info["html"], http_info["url"])
                endpoint_findings = check_sensitive_endpoints(http_info["url"])

                all_secret_findings = js_findings + endpoint_findings

                for finding in all_secret_findings:
                    database.add_vulnerability(
                        asset_id,
                        finding["titre_cve"],
                        finding["severite"],
                        finding["description"],
                    )

                if all_secret_findings:
                    print(f"  [SECRETS] {len(all_secret_findings)} finding(s) enregistré(s) pour {subdomain}")

                # Mise à jour de la progression après chaque sous-domaine traité.
            processed_count = subdomains.index(subdomain) + 1
            database.update_scan_progress(
                scan_id,
                traites=processed_count,
                etape=f"Analyse de {subdomain}...",
            )
                            
        # --- Tout s'est bien passé : on clôture le scan proprement ---
        database.update_scan_progress(scan_id, etape="Scan terminé.")
        database.update_scan_status(scan_id, "Terminé")
        print(f"\n[OK] Scan {scan_id} terminé et enregistré en base.")

    except Exception as e:
        # N'importe quelle erreur critique et imprévue dans le pipeline
        # (bug, exception non gérée plus haut, etc.) marque le scan comme
        # "Erreur" plutôt que de laisser une entrée bloquée sur "En cours".
        print(f"\n[ERREUR CRITIQUE] Le scan a été interrompu : {e}")
        database.update_scan_status(scan_id, "Erreur")

    finally:
        # Le finally garantit que ce message s'affiche dans tous les cas
        # (succès, erreur gérée, ou exception critique).
        print(f"[INFO] Fin de traitement pour le scan id {scan_id}.")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Initialisation de la base (créé le fichier + les tables si besoin)
    database.init_db()

    target_domain: str = input("Domaine cible à scanner (ex: scanme.nmap.org) : ").strip()

    if not target_domain:
        print("[ERREUR] Aucun domaine saisi, arrêt du script.")
    else:
        run_pipeline(target_domain)