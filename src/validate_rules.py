"""Validation syntaxique d'une regle avec `suricata -T`."""
import re
import sys
import tempfile
from pathlib import Path

from utils import SURICATA_YAML, run


def validate(rule_text):
    """Renvoie (ok, message_d_erreur)."""
    if not rule_text.strip():
        return False, "Aucune regle trouvee (pas de ligne 'alert ...')."
    with tempfile.TemporaryDirectory() as tmp:
        rules = Path(tmp) / "test.rules"
        rules.write_text(rule_text.strip() + "\n", encoding="utf-8")
        cmd = ["suricata", "-T", "-c", SURICATA_YAML, "-S", str(rules), "-l", tmp]
        res = run(cmd, timeout=180)
    output = res.stdout + res.stderr
    failed = re.search(r"(\d+) rules failed", output)
    ok = res.returncode == 0 and not (failed and int(failed.group(1)) > 0)
    if ok:
        return True, ""
    lines = [l for l in output.splitlines()
             if "rror" in l or "ailed" in l or "arning" in l]
    return False, "\n".join(lines[-10:]) or output[-800:]


if __name__ == "__main__":
    for name in sys.argv[1:]:
        ok, err = validate(Path(name).read_text(encoding="utf-8"))
        print(("VALIDE  " if ok else "INVALIDE"), name)
        if err:
            print(err)
