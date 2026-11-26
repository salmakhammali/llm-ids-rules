"""Boucle : generer -> valider -> corriger (max N fois) -> sauvegarder."""
import argparse
import csv

from extract_features import summarize
from generate_rules import fix, generate
from utils import ROOT
from validate_rules import validate

LOG = ROOT / "results" / "metrics" / "generation_log.csv"


def run_loop(strategy, features, description, sid, max_iter=3):
    rule = generate(strategy, features, description, sid)
    ok, err = validate(rule)
    iterations = 0
    while not ok and iterations < max_iter:
        iterations += 1
        rule = fix(rule, err, sid)
        ok, err = validate(rule)
    return rule, ok, iterations, err


def log_row(row):
    new = not LOG.exists()
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new:
            writer.writerow(["run", "attack_type", "strategy", "valid",
                             "iterations", "rule"])
        writer.writerow(row)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attack-type", required=True)
    p.add_argument("--description", required=True)
    p.add_argument("--pcap", help="PCAP a resumer (optionnel)")
    p.add_argument("--strategy", default="constrained")
    p.add_argument("--run", help="nom du run (defaut : nom de la strategie)")
    p.add_argument("--sid", type=int, default=9100001)
    p.add_argument("--max-iter", type=int, default=3)
    a = p.parse_args()

    run_name = a.run or a.strategy
    features = summarize(a.pcap) if a.pcap else None
    rule, ok, iters, err = run_loop(a.strategy, features, a.description,
                                    a.sid, a.max_iter)

    out_dir = ROOT / "rules" / "generated" / run_name
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".rules" if ok else ".rules.invalid"
    (out_dir / f"{a.attack_type}{suffix}").write_text(rule + "\n", encoding="utf-8")
    log_row([run_name, a.attack_type, a.strategy, ok, iters, rule])

    print(f"[{run_name}] {a.attack_type} : valide={ok} corrections={iters}")
    print(rule)
    if err:
        print("Derniere erreur :", err)
