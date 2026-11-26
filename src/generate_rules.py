"""Generation et correction de regles Suricata via l'API Gemini."""
import json
import os
import re
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types

from utils import ROOT

load_dotenv(ROOT / ".env")
MODELS = [m for m in (os.getenv("LLM_MODEL"), os.getenv("LLM_FALLBACK")) if m]
SYSTEM = (
    "Tu es un expert en detection d'intrusion reseau (Suricata 7). "
    "Tu reponds UNIQUEMENT par une regle sur une seule ligne, "
    "sans explication et sans bloc de code."
)
_client = None


def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(http_options=types.HttpOptions(api_version="v1beta"))
    return _client


def ask(user_message, retries=4):
    """Appelle Gemini ; reessaie (503, 429...) puis bascule sur le modele de secours."""
    last = None
    for model in MODELS:
        for attempt in range(retries):
            try:
                resp = _get_client().models.generate_content(
                    model=model,
                    contents=user_message,
                    config=types.GenerateContentConfig(system_instruction=SYSTEM),
                )
                if resp.text:
                    return resp.text
            except Exception as e:  # erreur reseau ou API
                last = e
                print(f"  [{model}] essai {attempt + 1} : {str(e)[:100]}")
                if "404" in str(e) or "NOT_FOUND" in str(e):
                    break  # modele inexistant : inutile de reessayer
                time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"Tous les modeles ont echoue : {last}")


def extract_rule(text):
    """Renvoie la premiere regle ('alert ...') sur une ligne ('' si aucune)."""
    text = re.sub(r"\\\s*\n\s*", " ", text)  # recolle les lignes finissant par \
    for line in text.splitlines():
        line = line.strip().strip("`")
        if re.match(r"^alert\s", line):
            return line
    return ""


def force_sid(rule, sid):
    """Impose le SID demande (evite les doublons ou les SID inventes)."""
    return re.sub(r"sid:\s*\d+\s*;", f"sid:{sid};", rule)


def build_prompt(strategy, features, description, sid):
    path = ROOT / "prompts" / f"{strategy}.txt"
    text = path.read_text(encoding="utf-8")
    feats = json.dumps(features, ensure_ascii=False, indent=1) if features \
        else "(aucun PCAP fourni)"
    return (text.replace("<<DESCRIPTION>>", description)
                .replace("<<FEATURES>>", feats)
                .replace("<<SID>>", str(sid)))


def generate(strategy, features, description, sid):
    raw = ask(build_prompt(strategy, features, description, sid))
    return force_sid(extract_rule(raw), sid)


def fix(rule, error, sid):
    """Demande au LLM de corriger une regle rejetee par Suricata."""
    message = (
        "Cette regle Suricata est rejetee par le moteur.\n\n"
        f"Regle :\n{rule}\n\nErreur Suricata :\n{error}\n\n"
        "Corrige la regle (une seule ligne, meme sid) et renvoie-la seule."
    )
    return force_sid(extract_rule(ask(message)), sid)
