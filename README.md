# Generation de signatures IDS Suricata/Snort assistee par LLM
Projet de fin de module : a partir de PCAP, de logs ou d'une description d'un
comportement reseau, un LLM propose des regles Suricata, qui sont ensuite
validees (syntaxe), testees (rejeu de PCAP) et evaluees (taux de detection et
faux positifs).
## Pipeline
PCAP -> extract_features -> prompt -> LLM -> validation (suricata -T)
 -> boucle de correction -> evaluation (TPR / FPR) -> graphiques
## Installation
 bash scripts/setup_env.sh
 cp .env.example .env # puis renseigner ANTHROPIC_API_KEY
 source .venv/bin/activate
## Utilisation
 bash scripts/make_pcaps.sh # genere les PCAP de test
 python src/evaluate.py --rules-dir rules/manual --run manual
 bash scripts/run_all.sh zero_shot zero_shot 0
 bash scripts/run_all.sh constrained constrained_fb 3
 python src/plot_results.py
## Structure
- src/ code Python (extraction, generation, validation, evaluation)
- prompts/ strategies de prompt (zero_shot, few_shot, constrained)
- rules/ regles manuelles (baseline) et generees (un dossier par run)
- results/ metriques CSV et figures
- docs/ notes hebdomadaires et rapport
## Avertissement
Les attaques sont generees uniquement en local (127.0.0.1) a des fins
pedagogiques.
