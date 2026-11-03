"""
Projet 1 — Analyse des journaux d'un pare-feu (Réseaux / Sécurité / IoT)
Auteur : Mame Awa NDIAYE

Lancement :  python analyse.py

Le script :
  1. lit data/logs_reseau.csv ;
  2. nettoie les données (doublons, casse du protocole, valeurs manquantes) ;
  3. calcule les 5 résultats demandés et les écrit dans resultats.json ;
  4. enregistre les figures dans le dossier figures/.
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                    # pas de fenêtre : on enregistre seulement les images
import matplotlib.pyplot as plt
import pandas as pd

DOSSIER = Path(__file__).resolve().parent
FICHIER_DONNEES = DOSSIER / "data" / "logs_reseau.csv"
FICHIER_RESULTATS = DOSSIER / "resultats.json"
DOSSIER_FIGURES = DOSSIER / "figures"

NOMS_PORTS = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS", 1883: "MQTT",
              23: "Telnet", 3389: "RDP", 8080: "HTTP-alt"}


# ----------------------------------------------------------------------------
# 1. Chargement et nettoyage
# ----------------------------------------------------------------------------
def charger_donnees(chemin: Path) -> pd.DataFrame:
    """Lit le CSV et convertit la colonne timestamp en date."""
    df = pd.read_csv(chemin)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """Applique les 3 étapes de nettoyage demandées, dans l'ordre de l'énoncé."""
    df = df.drop_duplicates().copy()                          # 1. doublons exacts
    df["protocol"] = df["protocol"].str.upper()               # 2. tcp -> TCP
    mediane = df["bytes_sent"].median()                       # 3. médiane après doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    return df.reset_index(drop=True)


# ----------------------------------------------------------------------------
# 2. Calcul des résultats
# ----------------------------------------------------------------------------
def calculer_resultats(df: pd.DataFrame) -> dict:
    """Calcule les 5 indicateurs demandés dans l'énoncé."""
    ports_distincts = df.groupby("src_ip")["dst_port"].nunique()
    octets_par_ip = df.groupby("src_ip")["bytes_sent"].sum()
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(ports_distincts.idxmax()),
        "ip_exfiltration": str(octets_par_ip.idxmax()),
    }


# ----------------------------------------------------------------------------
# 3. Figures
# ----------------------------------------------------------------------------
def enregistrer(fig, nom: str) -> None:
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / nom, dpi=120)
    plt.close(fig)


def figure_top_ports(df: pd.DataFrame) -> None:
    top = df["dst_port"].value_counts().head(10)
    etiquettes = [f"{p}\n{NOMS_PORTS.get(p, '')}" for p in top.index]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(etiquettes, top.values, color="#2b6cb0")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination (service)")
    ax.set_ylabel("Nombre de connexions")
    enregistrer(fig, "01_top_ports.png")


def figure_connexions_par_heure(df: pd.DataFrame) -> None:
    par_heure = df.groupby([df["timestamp"].dt.hour, "action"]).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    par_heure.plot(kind="bar", stacked=True, ax=ax, color={"ALLOW": "#38a169", "DENY": "#e53e3e"})
    ax.set_title("Connexions par heure de la journée (semaine complète)")
    ax.set_xlabel("Heure")
    ax.set_ylabel("Nombre de connexions")
    ax.legend(title="Action")
    enregistrer(fig, "02_connexions_par_heure.png")


def figure_octets_par_appareil(df: pd.DataFrame) -> None:
    octets = df.groupby("device_type")["bytes_sent"].sum().sort_values() / 1e6
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(octets.index, octets.values, color="#dd6b20")
    ax.set_title("Volume total d'octets envoyés par type d'appareil")
    ax.set_xlabel("Octets envoyés (millions)")
    ax.set_ylabel("Type d'appareil")
    enregistrer(fig, "03_octets_par_appareil.png")


def figure_allow_deny(df: pd.DataFrame) -> None:
    repartition = df["action"].value_counts()
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.pie(repartition.values, labels=repartition.index, autopct="%1.1f %%",
           colors=["#38a169", "#e53e3e"], startangle=90)
    ax.set_title("Répartition des connexions ALLOW / DENY")
    enregistrer(fig, "04_allow_deny.png")


def figure_ports_distincts(df: pd.DataFrame) -> None:
    top = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(top.index, top.values, color="#805ad5")
    ax.set_title("Adresses source ayant contacté le plus de ports distincts")
    ax.set_xlabel("Adresse IP source")
    ax.set_ylabel("Nombre de ports distincts")
    ax.tick_params(axis="x", rotation=45)
    enregistrer(fig, "05_ports_distincts_par_ip.png")


def figure_octets_par_ip(df: pd.DataFrame) -> None:
    top = (df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10)) / 1e6
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(top.index, top.values, color="#c53030")
    ax.set_title("Adresses source ayant envoyé le plus d'octets")
    ax.set_xlabel("Adresse IP source")
    ax.set_ylabel("Octets envoyés (millions)")
    ax.tick_params(axis="x", rotation=45)
    enregistrer(fig, "06_octets_par_ip.png")


# ----------------------------------------------------------------------------
# Programme principal
# ----------------------------------------------------------------------------
def main() -> None:
    brut = charger_donnees(FICHIER_DONNEES)
    df = nettoyer(brut)
    print(f"Lignes lues : {len(brut)}  ->  après nettoyage : {len(df)}")

    resultats = calculer_resultats(df)
    with open(FICHIER_RESULTATS, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print("Résultats :", json.dumps(resultats, ensure_ascii=False))

    DOSSIER_FIGURES.mkdir(exist_ok=True)
    for fonction in (figure_top_ports, figure_connexions_par_heure, figure_octets_par_appareil,
                     figure_allow_deny, figure_ports_distincts, figure_octets_par_ip):
        fonction(df)
    print(f"Figures enregistrées dans {DOSSIER_FIGURES.name}/")


if __name__ == "__main__":
    main()
