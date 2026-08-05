"""
database.py

Module de persistance pour le pipeline ASM.
Gère la création du schéma SQLite et toutes les opérations d'écriture
(création de scan, ajout d'assets, ajout de vulnérabilités).

Utilise uniquement le module standard sqlite3 (pas d'ORM).
"""

import sqlite3
from typing import Any, Optional
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Emplacement de la base de données
# ---------------------------------------------------------------------------

DB_PATH: Path = Path(__file__).resolve().parent / "asm_pipeline.db"


def get_connection() -> sqlite3.Connection:
    """
    Ouvre une connexion à la base SQLite avec les clés étrangères activées.

    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# ---------------------------------------------------------------------------
# Initialisation du schéma
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Crée le fichier asm_pipeline.db et les 3 tables si elles n'existent pas
    encore. Peut être appelée à chaque lancement du script sans risque
    (CREATE TABLE IF NOT EXISTS).
    """
    conn = get_connection()
    cursor = conn.cursor()

    # --- Table des scans (une ligne = un lancement de scan sur un domaine) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            domaine_cible       TEXT NOT NULL,
            date_debut          TEXT NOT NULL,
            statut              TEXT NOT NULL CHECK (statut IN ('En cours', 'Terminé', 'Erreur')),
            total_sous_domaines INTEGER DEFAULT 0,
            sous_domaines_faits INTEGER DEFAULT 0,
            etape_actuelle      TEXT DEFAULT ''
            session_id          TEXT DEFAULT ''
        );
    """)

    # Migration : ajoute les colonnes de progression si la table existait
    # déjà avant cette mise à jour (ALTER TABLE échoue silencieusement si
    # la colonne existe déjà, ce qui est le comportement voulu ici).
    for column_def in [
        "ALTER TABLE scans ADD COLUMN total_sous_domaines INTEGER DEFAULT 0;",
        "ALTER TABLE scans ADD COLUMN sous_domaines_faits INTEGER DEFAULT 0;",
        "ALTER TABLE scans ADD COLUMN etape_actuelle TEXT DEFAULT '';",
        "ALTER TABLE scans ADD COLUMN session_id TEXT DEFAULT '';",
    ]:
        try:
            cursor.execute(column_def)
        except sqlite3.OperationalError:
            pass  # la colonne existe déjà, rien à faire

    # --- Table des assets (un asset = un sous-domaine + son IP + ses infos) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL,
            sous_domaine   TEXT NOT NULL,
            adresse_ip     TEXT,
            ports_ouverts  TEXT,
            technologies   TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    # --- Table des vulnérabilités (liée à un asset précis) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id    INTEGER NOT NULL,
            titre_cve   TEXT NOT NULL,
            severite    TEXT NOT NULL CHECK (severite IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
            description TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Fonctions helper : scans
# ---------------------------------------------------------------------------

def create_scan(domaine_cible: str, session_id: str = "") -> int:
    conn = get_connection()
    cursor = conn.cursor()

    date_debut: str = datetime.now().isoformat(timespec="seconds")

    cursor.execute(
        "INSERT INTO scans (domaine_cible, date_debut, statut, session_id) VALUES (?, ?, ?, ?);",
        (domaine_cible, date_debut, "En cours", session_id),
    )

    scan_id: int = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


"""fonction pour lister les scans filtrés par session"""
def list_scans_by_session(session_id: str) -> list[dict[str, Any]]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, domaine_cible, date_debut, statut, total_sous_domaines,
               sous_domaines_faits, etape_actuelle
        FROM scans
        WHERE session_id = ?
        ORDER BY id DESC;
        """,
        (session_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_scan_status(scan_id: int, statut: str) -> None:
    """
    Met à jour le statut d'un scan existant.

    Args:
        scan_id: L'id du scan à mettre à jour.
        statut: 'En cours', 'Terminé' ou 'Erreur'.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE scans SET statut = ? WHERE id = ?;",
        (statut, scan_id),
    )

    conn.commit()
    conn.close()

def update_scan_progress(
    scan_id: int,
    total: Optional[int] = None,
    traites: Optional[int] = None,
    etape: Optional[str] = None,
) -> None:
    """
    Met à jour les indicateurs de progression d'un scan en cours. Chaque
    paramètre est optionnel : seuls les champs fournis sont mis à jour,
    les autres restent inchangés.

    Args:
        scan_id: L'id du scan à mettre à jour.
        total: Nombre total de sous-domaines à traiter (défini une seule
               fois, après Subfinder).
        traites: Nombre de sous-domaines déjà traités jusqu'ici.
        etape: Texte court décrivant l'étape en cours (ex: "Scan Nuclei
               en cours...").
    """
    conn = get_connection()
    cursor = conn.cursor()

    updates: list[str] = []
    params: list[Any] = []

    if total is not None:
        updates.append("total_sous_domaines = ?")
        params.append(total)
    if traites is not None:
        updates.append("sous_domaines_faits = ?")
        params.append(traites)
    if etape is not None:
        updates.append("etape_actuelle = ?")
        params.append(etape)

    if updates:
        params.append(scan_id)
        cursor.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = ?;", params)
        conn.commit()

    conn.close()


# ---------------------------------------------------------------------------
# Fonctions helper : assets
# ---------------------------------------------------------------------------

def add_asset(
    scan_id: int,
    sous_domaine: str,
    adresse_ip: Optional[str],
    ports: list[int],
    technologies: list[str],
) -> int:
    """
    Ajoute un asset (sous-domaine découvert) à la base, lié à un scan.

    Args:
        scan_id: L'id du scan parent (retourné par create_scan).
        sous_domaine: Le sous-domaine découvert (ex: "www.example.com").
        adresse_ip: L'IP résolue, ou None si la résolution DNS a échoué.
        ports: Liste de ports ouverts (ex: [80, 443]), stockée sous forme
               de chaîne "80,443" en base (SQLite n'a pas de type "liste").
        technologies: Liste de technologies/produits détectés (ex: ["nginx",
                      "OpenSSH"]), stockée en chaîne séparée par des virgules.

    Returns:
        L'id (int) de l'asset créé, à réutiliser pour lier d'éventuelles
        vulnérabilités.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Conversion des listes en chaînes "propres" séparées par des virgules.
    # On filtre les valeurs vides/None avant de joindre, pour éviter des
    # chaînes du type "80,,443".
    ports_str: str = ",".join(str(p) for p in ports if p is not None)
    technologies_str: str = ",".join(t for t in technologies if t)

    cursor.execute(
        """
        INSERT INTO assets (scan_id, sous_domaine, adresse_ip, ports_ouverts, technologies)
        VALUES (?, ?, ?, ?, ?);
        """,
        (scan_id, sous_domaine, adresse_ip, ports_str, technologies_str),
    )

    asset_id: int = cursor.lastrowid

    conn.commit()
    conn.close()

    return asset_id


# ---------------------------------------------------------------------------
# Fonctions helper : vulnerabilities
# ---------------------------------------------------------------------------

def add_vulnerability(
    asset_id: int,
    titre_cve: str,
    severite: str,
    description: str,
) -> int:
    """
    Ajoute une vulnérabilité liée à un asset précis.

    Args:
        asset_id: L'id de l'asset concerné (retourné par add_asset).
        titre_cve: Identifiant ou titre de la vulnérabilité (ex: "CVE-2021-41773").
        severite: 'Critical', 'High', 'Medium', 'Low' ou 'Info'.
        description: Description libre de la vulnérabilité.

    Returns:
        L'id (int) de la vulnérabilité créée.

    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO vulnerabilities (asset_id, titre_cve, severite, description)
        VALUES (?, ?, ?, ?);
        """,
        (asset_id, titre_cve, severite, description),
    )

    vuln_id: int = cursor.lastrowid

    conn.commit()
    conn.close()

    return vuln_id

def get_scan_full_data(scan_id: int) -> Optional[dict[str, Any]]:
    """
    Récupère les métadonnées d'un scan, ses assets, et les vulnérabilités
    associées, sous une forme unique réutilisable par l'API et le générateur
    de rapport.

    Args:
        scan_id: L'id du scan à récupérer.

    Returns:
        Un dictionnaire {"scan": ..., "assets": [...], "vulnerabilities": [...]}
        ou None si le scan_id n'existe pas.
    """
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, domaine_cible, date_debut, statut, total_sous_domaines, sous_domaines_faits, etape_actuelle FROM scans WHERE id = ?;",
        (scan_id,),
    )
    scan_row = cursor.fetchone()

    if scan_row is None:
        conn.close()
        return None

    cursor.execute(
        "SELECT id, sous_domaine, adresse_ip, ports_ouverts, technologies FROM assets WHERE scan_id = ?;",
        (scan_id,),
    )
    assets = [dict(row) for row in cursor.fetchall()]

    asset_ids = [asset["id"] for asset in assets]
    vulnerabilities: list[dict[str, Any]] = []

    if asset_ids:
        placeholders = ",".join("?" * len(asset_ids))
        cursor.execute(
            f"""
            SELECT id, asset_id, titre_cve, severite, description
            FROM vulnerabilities
            WHERE asset_id IN ({placeholders});
            """,
            asset_ids,
        )
        vulnerabilities = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "scan": dict(scan_row),
        "assets": assets,
        "vulnerabilities": vulnerabilities,
    }