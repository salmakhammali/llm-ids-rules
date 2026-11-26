"""Fonctions communes : chemins, lecture des labels, appel de commandes."""
import csv
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = ROOT / "data" / "pcap"
LABELS = ROOT / "data" / "labels.csv"
SURICATA_YAML = "/etc/suricata/suricata.yaml"


def read_labels():
    """Lit data/labels.csv et renvoie une liste de dictionnaires."""
    with open(LABELS, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pcap_path(row):
    """Chemin du PCAP : data/pcap/<label>/<filename>."""
    return PCAP_DIR / row["label"] / row["filename"]


def run(cmd, timeout=120):
    """Execute une commande et renvoie l'objet CompletedProcess."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
