"""
shodan_scanner.py

Module autonome pour interroger l'API Shodan et récupérer les informations
connues sur une adresse IP donnée (ports ouverts, services, bannières, etc.).

"""

import os
from typing import Any

import shodan
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Chargement de la clé API depuis le fichier .env
# ---------------------------------------------------------------------------

load_dotenv()  # lit le fichier .env à la racine et charge les variables

SHODAN_API_KEY: str | None = os.getenv("SHODAN_API_KEY")


def run_shodan_lookup(ip_address: str) -> dict[str, Any]:
    """
    Interroge Shodan sur une adresse IP donnée et retourne les informations
    connues (ports ouverts, services détectés, etc.).

    Args:
        ip_address: L'adresse IP cible (ex: "8.8.8.8").

    Returns:
        Un dictionnaire contenant les données brutes retournées par Shodan.
        Dictionnaire vide {} en cas d'erreur.
    """

    # --- Étape 1 : Vérifier que la clé API est bien chargée ---
    if not SHODAN_API_KEY:
        print("[ERREUR] Clé API Shodan introuvable.")
        print("Vérifiez que le fichier .env existe et contient SHODAN_API_KEY=...")
        return {}

    # --- Étape 2 : Créer le "badge d'accès" (client Shodan) ---
    api = shodan.Shodan(SHODAN_API_KEY)

    # --- Étape 3 : Interroger Shodan sur l'IP demandée ---
    try:
        result: dict[str, Any] = api.host(ip_address)

    except shodan.exception.APIError as e:
        # Erreur renvoyée par Shodan lui-même :
        # - clé API invalide
        # - IP non trouvée dans leur base
        # - quota de requêtes dépassé
        print(f"[ERREUR] Shodan a renvoyé une erreur : {e}")
        return {}

    except Exception as e:
        # Filet de sécurité pour toute autre erreur (ex: pas de connexion internet)
        print(f"[ERREUR] Erreur inattendue lors de la requête Shodan : {e}")
        return {}

    return result


def print_shodan_summary(result: dict[str, Any]) -> None:
    """
    Affiche un résumé lisible des informations Shodan dans la console.

    Args:
        result: Le dictionnaire retourné par run_shodan_lookup.
    """

    if not result:
        print("[INFO] Aucune donnée à afficher.")
        return

    ip_str: str = result.get("ip_str", "N/A")
    org: str = result.get("org", "N/A")
    os_name: str = result.get("os") or "N/A"
    ports: list[int] = result.get("ports", [])

    print(f"\n=== Résumé Shodan pour {ip_str} ===")
    print(f"Organisation   : {org}")
    print(f"Système (OS)   : {os_name}")
    print(f"Ports ouverts  : {ports}")

    # Chaque "service" détecté est dans result["data"], un par port/protocole
    services: list[dict[str, Any]] = result.get("data", [])
    print(f"\nServices détectés ({len(services)}) :")
    for service in services:
        port: int = service.get("port", "?")
        transport: str = service.get("transport", "?")
        product: str = service.get("product", "Inconnu")
        banner: str = (service.get("data") or "").strip().splitlines()[0] if service.get("data") else ""

        print(f"  - Port {port}/{transport} | Produit : {product}")
        if banner:
            print(f"    Bannière : {banner[:100]}")  # tronquée à 100 caractères


# ---------------------------------------------------------------------------
# Bloc de test manuel
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_ip: str = ""

    print(f"[INFO] Interrogation de Shodan pour l'IP : {test_ip}")
    shodan_result: dict[str, Any] = run_shodan_lookup(test_ip)

    print_shodan_summary(shodan_result)