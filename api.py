"""
api.py

API REST FastAPI exposant le pipeline ASM (Subfinder + DNS + Shodan + SQLite).

Lancement :
    uvicorn api:app --reload

Documentation interactive générée automatiquement, une fois le serveur lancé :
    http://127.0.0.1:8000/docs
"""

import sqlite3
from typing import Any, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, Response
import report_generator
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import database
from main_scanner import run_pipeline


# ---------------------------------------------------------------------------
# Schémas Pydantic : décrivent la forme des données attendues/renvoyées.
# FastAPI s'en sert pour valider automatiquement les requêtes entrantes et
# pour générer la documentation /docs.
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Corps attendu pour POST /api/scan."""
    domain: str


class ScanStartedResponse(BaseModel):
    """Réponse renvoyée après le lancement d'un scan."""
    message: str
    domain: str


class ScanSummary(BaseModel):
    id: int
    domaine_cible: str
    date_debut: str
    statut: str
    total_sous_domaines: int = 0
    sous_domaines_faits: int = 0
    etape_actuelle: str = ""


# ---------------------------------------------------------------------------
# Initialisation de l'application FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ASM Pipeline API",
    description="API REST pour piloter le pipeline de découverte de surface d'attaque.",
    version="1.0.0",
)

# --- Configuration CORS ---
# Sans ça, un futur frontend (React/Vue lancé sur un autre port, ex: localhost:3000)
# serait bloqué par le navigateur quand il essaie d'appeler cette API.
# En développement, on autorise tout ("*") ; à restreindre en production
# (ex: n'autoriser que le vrai domaine du frontend final).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    """
    Exécuté une seule fois, au démarrage du serveur.
    Garantit que la base et ses tables existent avant de recevoir
    la moindre requête.
    """
    database.init_db()

# Sert le dossier static/ pour tout fichier statique 
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    """
    Sert le dashboard HTML à la racine du site. include_in_schema=False
    évite que cette route n'encombre la documentation Swagger (/docs),
    qui reste dédiée aux routes de l'API elle-même.
    """
    return FileResponse("static/dashboard.html")


# ---------------------------------------------------------------------------
# Fonction utilitaire : convertir des lignes sqlite3.Row en dictionnaires
# ---------------------------------------------------------------------------

def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convertit une ligne sqlite3.Row en dictionnaire JSON-sérialisable."""
    return dict(row)


# ---------------------------------------------------------------------------
# Route 1 : POST /api/scan — lance un scan en arrière-plan
# ---------------------------------------------------------------------------

@app.post("/api/scan", response_model=ScanStartedResponse)
def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks) -> ScanStartedResponse:
    """
    Démarre un nouveau scan pour le domaine fourni.

    Le scan tourne en arrière-plan via BackgroundTasks : la requête HTTP
    répond immédiatement, sans attendre que Subfinder/Shodan aient fini
    (ce qui peut prendre du temps). Le client consultera l'avancement
    ensuite via GET /api/scans ou GET /api/scan/{id}/results.
    """
    domain: str = scan_request.domain.strip()

    if not domain:
        # 400 Bad Request : la requête elle-même est invalide
        raise HTTPException(status_code=400, detail="Le champ 'domain' ne peut pas être vide.")

    # On planifie l'exécution de run_pipeline() APRÈS l'envoi de la réponse HTTP.
    # C'est ça qui empêche le client de rester bloqué en attente pendant
    # tout le scan (qui peut durer plusieurs dizaines de secondes/minutes).
    background_tasks.add_task(run_pipeline, domain)

    return ScanStartedResponse(message="Scan démarré", domain=domain)


# ---------------------------------------------------------------------------
# Route 2 : GET /api/scans — liste tous les scans passés
# ---------------------------------------------------------------------------

@app.get("/api/scans", response_model=list[ScanSummary])
def list_scans() -> list[dict[str, Any]]:
    """
    Retourne la liste complète des scans enregistrés, du plus récent
    au plus ancien.
    """
    conn = database.get_connection()
    conn.row_factory = sqlite3.Row  # permet d'accéder aux colonnes par nom
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, domaine_cible, date_debut, statut, total_sous_domaines, sous_domaines_faits, etape_actuelle FROM scans ORDER BY id DESC;"
    )
    rows = cursor.fetchall()
    conn.close()

    return [row_to_dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Route 3 : GET /api/scan/{scan_id}/results — détails complets d'un scan
# ---------------------------------------------------------------------------

@app.get("/api/scan/{scan_id}/results")
def get_scan_results(scan_id: int) -> dict[str, Any]:
    """
    Retourne les métadonnées d'un scan, ainsi que tous ses assets et
    toutes les vulnérabilités associées.

    Raises:
        HTTPException 404 si le scan_id n'existe pas en base.
    """
    conn = database.get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # --- Métadonnées du scan ---
    cursor.execute("SELECT id, domaine_cible, date_debut, statut FROM scans WHERE id = ?;", (scan_id,))
    scan_row: Optional[sqlite3.Row] = cursor.fetchone()

    if scan_row is None:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Aucun scan trouvé avec l'id {scan_id}.")

    # --- Assets liés à ce scan ---
    cursor.execute(
        "SELECT id, sous_domaine, adresse_ip, ports_ouverts, technologies FROM assets WHERE scan_id = ?;",
        (scan_id,),
    )
    asset_rows = cursor.fetchall()
    assets: list[dict[str, Any]] = [row_to_dict(row) for row in asset_rows]

    # --- Vulnérabilités liées aux assets de ce scan ---
    # On récupère les vulnérabilités via une jointure sur les ids d'assets
    # trouvés ci-dessus, pour ne renvoyer que celles pertinentes à ce scan.
    asset_ids: list[int] = [asset["id"] for asset in assets]
    vulnerabilities: list[dict[str, Any]] = []

    if asset_ids:
        # Construction dynamique des "?" pour la clause IN (...), en toute
        # sécurité (pas de concaténation de chaînes, toujours des paramètres liés).
        placeholders: str = ",".join("?" * len(asset_ids))
        cursor.execute(
            f"""
            SELECT id, asset_id, titre_cve, severite, description
            FROM vulnerabilities
            WHERE asset_id IN ({placeholders});
            """,
            asset_ids,
        )
        vuln_rows = cursor.fetchall()
        vulnerabilities = [row_to_dict(row) for row in vuln_rows]

    conn.close()

    return {
        "scan": row_to_dict(scan_row),
        "assets": assets,
        "vulnerabilities": vulnerabilities,
    }

@app.get("/api/scan/{scan_id}/report.html", response_class=HTMLResponse)
def get_scan_report_html(scan_id: int) -> str:
    """
    Génère et retourne le rapport de scan au format HTML, directement
    affichable dans un navigateur.
    """
    html = report_generator.generate_report_html(scan_id)

    if html is None:
        raise HTTPException(status_code=404, detail=f"Aucun scan trouvé avec l'id {scan_id}.")

    return html


@app.get("/api/scan/{scan_id}/report.pdf")
def get_scan_report_pdf(scan_id: int) -> Response:
    """
    Génère et retourne le rapport de scan au format PDF, en téléchargement.
    """
    pdf_bytes = report_generator.generate_report_pdf(scan_id)

    if pdf_bytes is None:
        raise HTTPException(status_code=404, detail=f"Aucun scan trouvé avec l'id {scan_id}, ou erreur de génération PDF.")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=rapport_scan_{scan_id}.pdf"},
    )


# ---------------------------------------------------------------------------
# Route 4 : DELETE /api/scan/{scan_id} — supprime un scan
# ---------------------------------------------------------------------------

@app.delete("/api/scan/{scan_id}")
def delete_scan(scan_id: int) -> dict[str, str]:
    """
    Supprime un scan et, grâce à ON DELETE CASCADE (activé via
    PRAGMA foreign_keys = ON dans database.py), tous ses assets et
    vulnérabilités associés sont supprimés automatiquement.

    Raises:
        HTTPException 404 si le scan_id n'existe pas.
    """
    conn = database.get_connection()
    cursor = conn.cursor()

    # On vérifie d'abord l'existence, pour renvoyer une 404 propre
    # plutôt qu'un "succès" silencieux sur un id inexistant.
    cursor.execute("SELECT id FROM scans WHERE id = ?;", (scan_id,))
    if cursor.fetchone() is None:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Aucun scan trouvé avec l'id {scan_id}.")

    cursor.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
    conn.commit()
    conn.close()

    return {"message": f"Scan {scan_id} supprimé avec succès."}