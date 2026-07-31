"""
httpx_scanner.py

Module autonome pour interroger un sous-domaine en HTTP/HTTPS et récupérer
des informations sur le service web exposé : code de statut, titre de page,
en-têtes révélant la technologie utilisée (Server, X-Powered-By).

"""

import re
from typing import Any, Optional

import httpx


DEFAULT_TIMEOUT: float = 10.0  # secondes, pour ne pas rester bloqué sur un hôte lent/mort


def _extract_title(html: str) -> Optional[str]:
    """
    Extrait le contenu de la balise <title> d'une page HTML, si présent.

    Args:
        html: Le contenu HTML brut de la réponse.

    Returns:
        Le titre de la page (tronqué à 200 caractères), ou None si absent.
    """
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:200]
    return None


def check_http(hostname: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Teste un sous-domaine en HTTPS puis en HTTP (repli), et retourne les
    informations récupérées sur le service web trouvé, s'il y en a un.

    Args:
        hostname: Le sous-domaine à tester (ex: "www.example.com").
        timeout: Délai maximal d'attente par requête, en secondes.

    Returns:
        Un dictionnaire avec les clés :
            - "url": l'URL qui a effectivement répondu (ou None)
            - "status_code": le code de statut HTTP (ou None)
            - "server": la valeur de l'en-tête Server (ou None)
            - "title": le titre de la page (ou None)
            - "technologies": liste de technologies détectées (ex: ["Apache/2.4.41"])
            - "html": contenu brut, réutilisé pour chercher les fichiers .js
        Toutes les valeurs restent None / liste vide si rien n'a répondu
        (sous-domaine mort, timeout, connexion refusée, etc.).
    """
    result: dict[str, Any] = {
        "url": None,
        "status_code": None,
        "server": None,
        "title": None,
        "technologies": [],
        "html": None,
    }

    # On essaie HTTPS d'abord, puis HTTP en repli
    # si HTTPS ne répond pas du tout.
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"

        try:
            response = httpx.get(
                url,
                timeout=timeout,
                follow_redirects=True,
                verify=False,  # on ignore les erreurs de certificat : en reconnaissance
                                # ASM, un certificat expiré/auto-signé est une INFO en soi,
                                # pas une raison d'ignorer le service qui répond derrière.
            )

            result["url"] = str(response.url)
            result["status_code"] = response.status_code

            server_header: Optional[str] = response.headers.get("server")
            if server_header:
                result["server"] = server_header
                result["technologies"].append(server_header)

            powered_by: Optional[str] = response.headers.get("x-powered-by")
            if powered_by:
                result["technologies"].append(powered_by)

            title = _extract_title(response.text)
            result["html"] = response.text
            if title:
                result["title"] = title

            # Une réponse a été obtenue : pas besoin de tester l'autre schéma.
            return result

        except httpx.ConnectError:
            # Rien n'écoute sur ce schéma (port fermé, hôte mort) : on essaie l'autre.
            continue

        except httpx.TimeoutException:
            print(f"  [WARN] Timeout HTTP sur {url}")
            continue

        except Exception as e:
            print(f"  [WARN] Erreur HTTP inattendue sur {url} : {e}")
            continue

    # Ni HTTPS ni HTTP n'ont répondu.
    return result


# ---------------------------------------------------------------------------
# Bloc de test manuel
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_hosts: list[str] = ["", ""]

    for host in test_hosts:
        print(f"\n[INFO] Test HTTP/HTTPS sur : {host}")
        info = check_http(host)

        if info["status_code"] is not None:
            print(f"  URL      : {info['url']}")
            print(f"  Statut   : {info['status_code']}")
            print(f"  Serveur  : {info['server']}")
            print(f"  Titre    : {info['title']}")
            print(f"  Technos  : {info['technologies']}")
        else:
            print("  [INFO] Aucune réponse HTTP/HTTPS obtenue.")