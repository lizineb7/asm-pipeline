"""
secrets_scanner.py

Module autonome pour détecter :
    1. Des secrets exposés dans les fichiers JavaScript chargés par une page
       (clés API, tokens JWT, URLs internes).
    2. Des endpoints sensibles accessibles publiquement (/admin, /.env, etc.).

"""

import re
from typing import Any
from urllib.parse import urljoin

import httpx


DEFAULT_TIMEOUT: float = 8.0
MAX_JS_FILES_PER_SITE: int = 5  # limite pour ne pas ralentir excessivement le scan


# ---------------------------------------------------------------------------
# Partie 1 : détection de secrets par motif (regex)
# ---------------------------------------------------------------------------

# Chaque motif associe un nom lisible à une regex et une sévérité par défaut.
# Les regex restent volontairement simples : on privilégie la détection de
# "formes" reconnaissables plutôt qu'une validation cryptographique complète.
SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "nom": "Clé d'accès AWS (AKIA...)",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severite": "Critical",
    },
    {
        "nom": "Token JWT",
        "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severite": "High",
    },
    {
        "nom": "Clé API Google",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severite": "High",
    },
    {
        "nom": "Clé API Stripe",
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "severite": "Critical",
    },
    {
        "nom": "URL interne potentiellement oubliée",
        "regex": re.compile(r"https?://[a-zA-Z0-9.\-]+\.(internal|local|corp)(?::\d+)?[/\w\-.]*"),
        "severite": "Medium",
    },
]


def _mask_secret(value: str) -> str:
    """
    Masque partiellement un secret trouvé avant de le stocker/afficher :
    on garde les 4 premiers et 4 derniers caractères, le reste devient '***'.
    Évite de stocker le secret complet en clair dans la base ou les logs.
    """
    if len(value) <= 10:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def find_secrets_in_text(text: str, source_label: str) -> list[dict[str, Any]]:
    """
    Recherche tous les motifs de SECRET_PATTERNS dans un texte donné.

    Args:
        text: Le contenu à analyser (typiquement le contenu d'un fichier .js).
        source_label: Un identifiant de la source, pour la description
                      (ex: l'URL du fichier .js concerné).

    Returns:
        Une liste de findings, chacun avec titre_cve/severite/description,
        prête à être insérée via database.add_vulnerability.
    """
    findings: list[dict[str, Any]] = []

    for pattern in SECRET_PATTERNS:
        matches = pattern["regex"].findall(text)
        for match in set(matches):  # set() pour dédupliquer les répétitions
            findings.append({
                "titre_cve": f"Secret exposé : {pattern['nom']}",
                "severite": pattern["severite"],
                "description": f"Motif détecté dans {source_label} : {_mask_secret(match)}",
            })

    return findings


# ---------------------------------------------------------------------------
# Partie 2 : extraction et scan des fichiers JS référencés par une page
# ---------------------------------------------------------------------------

def extract_js_urls(html: str, base_url: str) -> list[str]:
    """
    Extrait les URLs de fichiers .js référencés dans une page HTML.

    Args:
        html: Le contenu HTML brut de la page.
        base_url: L'URL de la page, utilisée pour résoudre les chemins
                  relatifs (ex: "/static/app.js" -> URL complète).

    Returns:
        Une liste d'URLs absolues de fichiers .js, sans doublons.
    """
    # Cherche les valeurs src="..." ou src='...' se terminant par .js
    raw_srcs: list[str] = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)

    absolute_urls: list[str] = []
    for src in raw_srcs:
        full_url = urljoin(base_url, src)
        if full_url not in absolute_urls:
            absolute_urls.append(full_url)

    return absolute_urls[:MAX_JS_FILES_PER_SITE]


def scan_js_files(html: str, base_url: str, timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """
    Télécharge chaque fichier .js référencé par une page et cherche des
    secrets dedans.

    Args:
        html: Le contenu HTML de la page principale (déjà récupéré par httpx_scanner).
        base_url: L'URL de la page principale.
        timeout: Délai maximal par téléchargement de fichier .js.

    Returns:
        La liste combinée des findings trouvés dans tous les fichiers .js.
    """
    js_urls = extract_js_urls(html, base_url)
    all_findings: list[dict[str, Any]] = []

    for js_url in js_urls:
        try:
            response = httpx.get(js_url, timeout=timeout, verify=False, follow_redirects=True)
            if response.status_code == 200:
                findings = find_secrets_in_text(response.text, source_label=js_url)
                all_findings.extend(findings)

        except httpx.TimeoutException:
            print(f"  [WARN] Timeout lors du téléchargement de {js_url}")
        except Exception as e:
            print(f"  [WARN] Erreur lors du téléchargement de {js_url} : {e}")

    return all_findings


# ---------------------------------------------------------------------------
# Partie 3 : détection d'endpoints sensibles exposés
# ---------------------------------------------------------------------------

# Chemins connus pour être sensibles s'ils sont accessibles publiquement.
SENSITIVE_PATHS: list[str] = [
    "/.env",
    "/.git/config",
    "/admin",
    "/api/internal",
    "/backup.zip",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/.aws/credentials",
]


def check_sensitive_endpoints(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """
    Teste une liste de chemins sensibles connus sur la cible, et signale
    ceux qui répondent avec un code 200 (accessibles publiquement).

    Args:
        base_url: L'URL racine de la cible (ex: "https://example.com").
        timeout: Délai maximal par requête.

    Returns:
        Une liste de findings pour chaque endpoint sensible accessible.
    """
    findings: list[dict[str, Any]] = []

    for path in SENSITIVE_PATHS:
        target_url = urljoin(base_url, path)

        try:
            response = httpx.get(target_url, timeout=timeout, verify=False, follow_redirects=False)

            # On ne signale que les vraies réponses positives (200) : un 403/401
            # veut dire que le chemin existe mais est bien protégé, ce n'est
            # pas un problème. Un 404 veut dire qu'il n'existe pas.
            if response.status_code == 200:
                findings.append({
                    "titre_cve": f"Endpoint sensible exposé : {path}",
                    "severite": "High" if path in (".env", "/.aws/credentials") else "Medium",
                    "description": f"Le chemin {target_url} répond avec un code 200 (accessible publiquement).",
                })

        except httpx.TimeoutException:
            continue
        except Exception:
            continue

    return findings

def _run_self_test() -> None:
    """
    Auto-test avec des données fabriquées, pour valider la logique de
    détection indépendamment de la disponibilité réseau d'un vrai site.
    """
    print("[SELF-TEST] Vérification des regex avec des données fabriquées...\n")

    fake_js = """
    const config = {
        awsKey: "AKIAIOSFODNN7EXAMPLE",
        authToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dQw4w9WgXcQ",
        internalApi: "http://backend.internal:8080/debug"
    };
    """

    findings = find_secrets_in_text(fake_js, source_label="fake_test.js")

    print(f"[SELF-TEST] {len(findings)} finding(s) détecté(s) sur données fabriquées :")
    for f in findings:
        print(f"  - [{f['severite']}] {f['titre_cve']} : {f['description']}")

    expected_minimum = 2  # AWS + JWT au minimum attendus
    if len(findings) >= expected_minimum:
        print("\n[SELF-TEST] La logique de détection fonctionne correctement.")
    else:
        print("\n[SELF-TEST] Résultat inattendu : la regex ne détecte pas ce qu'elle devrait.")

    # Test de extract_js_urls avec du HTML fabriqué
    fake_html = '<html><script src="/static/app.js"></script><script src="https://cdn.test.com/vendor.js"></script></html>'
    js_urls = extract_js_urls(fake_html, "https://example.com")
    print(f"\n[SELF-TEST] URLs JS extraites : {js_urls}")


# ---------------------------------------------------------------------------
# Bloc de test manuel
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _run_self_test()
    print("\n" + "="*60 + "\n")

    test_url: str = ""

    print(f"[INFO] Récupération de la page principale : {test_url}")
    try:
        main_response = httpx.get(test_url, timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True)
        html_content = main_response.text
    except Exception as e:
        print(f"[ERREUR] Impossible de récupérer la page : {e}")
        html_content = ""

    if html_content:
        print("\n[1/2] Scan des fichiers JS pour des secrets...")
        js_findings = scan_js_files(html_content, test_url)
        if js_findings:
            for f in js_findings:
                print(f"  - [{f['severite']}] {f['titre_cve']} : {f['description']}")
        else:
            print("  Aucun secret détecté dans les fichiers JS.")

    print("\n[2/2] Test des endpoints sensibles...")
    endpoint_findings = check_sensitive_endpoints(test_url)
    if endpoint_findings:
        for f in endpoint_findings:
            print(f"  - [{f['severite']}] {f['titre_cve']}")
    else:
        print("  Aucun endpoint sensible accessible détecté.")