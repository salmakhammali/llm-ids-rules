"""Rejoue les PCAP avec chaque regle et calcule TPR / FPR / precision."""
import argparse
import csv
import json
import shutil
from pathlib import Path

from utils import ROOT, SURICATA_YAML, pcap_path, read_labels, run


def safe_div(a, b):
    return round(a / b, 3) if b else ""


def compute_metrics(tp, fn, fp, tn):
    return {
        "tpr": safe_div(tp, tp + fn),
        "fpr": safe_div(fp, fp + tn),
        "precision": safe_div(tp, tp + fp),
    }


def count_alerts(pcap, rules_file, workdir):
    """Rejoue un PCAP avec UNIQUEMENT ce fichier de regles ; compte les alertes."""
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    cmd = ["suricata", "-c", SURICATA_YAML, "-S", str(rules_file),
           "-r", str(pcap), "-l", str(workdir), "-k", "none"]
    run(cmd, timeout=300)
    eve = workdir / "eve.json"
    n = 0
    if eve.exists():
        with open(eve, encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("event_type") == "alert":
                    n += 1
    return n


def evaluate_rules_file(rules_file, rows, workdir):
    attack_type = rules_file.stem
    present = [r for r in rows if pcap_path(r).exists()]
    for r in rows:
        if r not in present:
            print(f"! PCAP absent (ignore) : {r['filename']}")
    positives = [r for r in present if r["label"] == "attack" and r["type"] == attack_type]
    negatives = [r for r in present if r["label"] == "benign"]
    if not positives:
        print(f"! Aucun PCAP d'attaque de type '{attack_type}' dans labels.csv")
        return None
    tp = fn = fp = tn = benign_alerts = 0
    for r in positives:
        n = count_alerts(pcap_path(r), rules_file, workdir)
        tp += int(n > 0)
        fn += int(n == 0)
    for r in negatives:
        n = count_alerts(pcap_path(r), rules_file, workdir)
        fp += int(n > 0)
        tn += int(n == 0)
        benign_alerts += n
    row = {"attack_type": attack_type, "rules_file": rules_file.name,
           "tp": tp, "fn": fn, "fp": fp, "tn": tn,
           "alerts_on_benign": benign_alerts}
    row.update(compute_metrics(tp, fn, fp, tn))
    return row


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rules-dir", required=True)
    p.add_argument("--run", required=True, help="nom du run (nom du CSV de sortie)")
    a = p.parse_args()

    rows = read_labels()
    workdir = ROOT / "results" / "tmp" / "eval"
    results = []
    for rules_file in sorted(Path(a.rules_dir).glob("*.rules")):
        res = evaluate_rules_file(rules_file, rows, workdir)
        if res:
            res["run"] = a.run
            results.append(res)
            print(res)

    out = ROOT / "results" / "metrics" / f"{a.run}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = ["run", "attack_type", "rules_file", "tp", "fn", "fp", "tn",
            "tpr", "fpr", "precision", "alerts_on_benign"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        writer.writerows(results)
    print("Resultats ecrits dans", out)
