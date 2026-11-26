#!/usr/bin/env bash
# Genere des PCAP d'attaque et de trafic normal sur 127.0.0.1.
# A utiliser UNIQUEMENT sur votre propre machine.
set -euo pipefail
cd "$(dirname "$0")/.."
A=data/pcap/attack
B=data/pcap/benign
mkdir -p "$A" "$B" /tmp/www
echo "<html><body>Bienvenue</body></html>" > /tmp/www/index.html

# Petit serveur web de test (cible des attaques)
python3 -m http.server 8000 --directory /tmp/www >/dev/null 2>&1 &
WEB_PID=$!
trap 'kill $WEB_PID 2>/dev/null || true' EXIT
sleep 1

capture() {   # usage : capture <fichier.pcap> <commande...>
  local out="$1"; shift
  sudo tcpdump -i lo -U -w "$out" >/dev/null 2>&1 &
  sleep 1
  "$@" >/dev/null 2>&1 || true
  sleep 1
  sudo pkill -INT -f "tcpdump -i lo -U -w $out" || true
  sleep 1
  echo "OK : $out"
}

# --- Attaques ---
capture $A/nmap_syn_scan.pcap     sudo nmap -sS -p 1-1000 127.0.0.1
capture $A/nmap_connect_scan.pcap nmap -sT -p 1-1000 127.0.0.1

capture $A/sqli_union.pcap curl -s \
  "http://127.0.0.1:8000/item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
capture $A/sqli_union_all.pcap curl -s \
  "http://127.0.0.1:8000/item.php?id=1%20UNION%20ALL%20SELECT%20NULL,NULL,version()--"
capture $A/sqli_boolean.pcap curl -s \
  "http://127.0.0.1:8000/login.php?user=admin%27%20OR%20%271%27=%271&pass=x"

capture $A/ssh_bruteforce.pcap bash -c \
  'for i in $(seq 1 15); do ssh -o BatchMode=yes -o ConnectTimeout=2 \
   -o StrictHostKeyChecking=no -p 22 user$i@127.0.0.1; done'

capture $A/c2_beacon.pcap bash -c \
  'for i in $(seq 1 10); do curl -s -A "EvilBot/1.0" \
   "http://127.0.0.1:8000/beacon?id=AB12CD&n=$i"; sleep 1; done'

# --- Trafic normal ---
capture $B/browsing_local.pcap bash -c \
  'for p in index.html about.html contact.html; do curl -s \
   -A "Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0" "http://127.0.0.1:8000/$p"; done'

# Trafic legitime mais "piegeux" : contient les mots union et select
capture $B/benign_tricky.pcap curl -s \
  -A "Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0" \
  "http://127.0.0.1:8000/blog?q=trade+union+members+select+committee"

ls -lh $A $B
