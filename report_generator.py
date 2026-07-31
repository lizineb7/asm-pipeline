"""
report_generator.py

Génère un rapport de scan au format HTML (via Jinja2) et PDF (via xhtml2pdf,
qui convertit ce même HTML en PDF sans dépendance système externe).
"""

import io
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa

import database


BASE_DIR: Path = Path(__file__).resolve().parent
TEMPLATES_DIR: Path = BASE_DIR / "templates"

_jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))

# Ordre d'affichage des sévérités : les plus critiques en premier.
SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


def _group_and_sort_vulnerabilities(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Regroupe les vulnérabilités identiques (même asset + même titre + même
    sévérité) en une seule ligne avec un compteur d'occurrences, puis trie
    le résultat par sévérité décroissante (Critical en premier, Info en dernier).

    Args:
        vulnerabilities: Liste brute des vulnérabilités (peut contenir des
                         doublons, ex: 10 lignes "HTTP Missing Security Headers"
                         pour le même asset).

    Returns:
        Liste dédupliquée, chaque élément ayant une clé "count" en plus.
    """
    grouped: dict[tuple, dict[str, Any]] = {}

    for vuln in vulnerabilities:
        key = (vuln["asset_id"], vuln["titre_cve"], vuln["severite"])
        if key not in grouped:
            grouped[key] = {
                "asset_id": vuln["asset_id"],
                "titre_cve": vuln["titre_cve"],
                "severite": vuln["severite"],
                "description": vuln["description"],
                "count": 0,
            }
        grouped[key]["count"] += 1

    result = list(grouped.values())
    # Tri : d'abord par sévérité (Critical -> Info), puis par nombre
    # d'occurrences décroissant à sévérité égale.
    result.sort(key=lambda v: (SEVERITY_ORDER.get(v["severite"], 99), -v["count"]))

    return result


def _build_report_context(scan_id: int) -> Optional[dict]:
    """
    Prépare toutes les données nécessaires au template : récupère les
    données brutes via database.py, puis calcule des éléments utiles
    à l'affichage (compteurs de sévérité, dédoublonnage, correspondance
    asset_id -> nom).

    Args:
        scan_id: L'id du scan à générer.

    Returns:
        Le contexte prêt pour le rendu Jinja2, ou None si le scan n'existe pas.
    """
    data = database.get_scan_full_data(scan_id)
    if data is None:
        return None

    # Compteur de vulnérabilités par sévérité (sur les données brutes, avant
    # dédoublonnage), pour que le résumé reflète le nombre réel de détections.
    severity_counts: dict[str, int] = {}
    for vuln in data["vulnerabilities"]:
        sev = vuln["severite"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    asset_lookup: dict[int, str] = {
        asset["id"]: asset["sous_domaine"] for asset in data["assets"]
    }

    grouped_vulnerabilities = _group_and_sort_vulnerabilities(data["vulnerabilities"])

    return {
        "scan": data["scan"],
        "assets": data["assets"],
        "vulnerabilities": grouped_vulnerabilities,
        "total_findings_raw": len(data["vulnerabilities"]),  # avant regroupement
        "severity_counts": severity_counts,
        "asset_lookup": asset_lookup,
    }


def generate_report_html(scan_id: int) -> Optional[str]:
    """
    Génère le rapport au format HTML (une chaîne de caractères prête à
    être servie directement dans un navigateur).
    """
    context = _build_report_context(scan_id)
    if context is None:
        return None

    template = _jinja_env.get_template("report.html")
    return template.render(**context)


def generate_report_pdf(scan_id: int) -> Optional[bytes]:
    """
    Génère le rapport au format PDF, à partir du même template HTML.
    """
    html_content = generate_report_html(scan_id)
    if html_content is None:
        return None

    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf_buffer)

    if pisa_status.err:
        print(f"[ERREUR] xhtml2pdf a rencontré {pisa_status.err} erreur(s) lors de la génération du PDF.")
        return None

    return pdf_buffer.getvalue()


# ---------------------------------------------------------------------------
# Bloc de test manuel
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_scan_id = None

    print(f"[INFO] Génération du rapport HTML pour le scan {test_scan_id}...")
    html = generate_report_html(test_scan_id)

    if html is None:
        print(f"[ERREUR] Aucun scan trouvé avec l'id {test_scan_id}.")
    else:
        output_html_path = Path("test_report.html")
        output_html_path.write_text(html, encoding="utf-8")
        print(f"[OK] Rapport HTML écrit dans : {output_html_path.resolve()}")

        print(f"[INFO] Génération du rapport PDF pour le scan {test_scan_id}...")
        pdf_bytes = generate_report_pdf(test_scan_id)

        if pdf_bytes:
            output_pdf_path = Path("test_report.pdf")
            output_pdf_path.write_bytes(pdf_bytes)
            print(f"[OK] Rapport PDF écrit dans : {output_pdf_path.resolve()}")
        else:
            print("[ERREUR] La génération du PDF a échoué.")