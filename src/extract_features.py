"""Resume un PCAP en JSON compact (le LLM ne lit pas un PCAP brut)."""
import argparse
import json
from collections import Counter, defaultdict

from utils import run

FIELDS = [
    "ip.src", "ip.dst", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack",
    "http.request.method", "http.host", "http.request.uri", "http.user_agent",
]


def is_true(value):
    return value.strip().lower() in ("1", "true")


def cut(text, size=200):
    return text if len(text) <= size else text[:size] + "..."


def tshark_rows(pcap):
    # -d : force le decodage HTTP sur le port 8000 (non standard pour Wireshark)
    cmd = ["tshark", "-r", str(pcap), "-d", "tcp.port==8000,http",
           "-T", "fields", "-E", "separator=/t"]
    for field in FIELDS:
        cmd += ["-e", field]
    res = run(cmd, timeout=300)
    if res.returncode != 0:
        raise RuntimeError(res.stderr)
    for line in res.stdout.split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        parts += [""] * (len(FIELDS) - len(parts))
        yield dict(zip(FIELDS, parts))


def top(counter, n):
    return [{"value": k, "count": c} for k, c in counter.most_common(n)]


def summarize(pcap, max_items=8):
    ports, methods, hosts, uris, agents = (Counter() for _ in range(5))
    syn_count = Counter()
    syn_ports = defaultdict(set)
    total = 0
    for r in tshark_rows(pcap):
        total += 1
        if r["tcp.dstport"]:
            ports[r["tcp.dstport"]] += 1
        if is_true(r["tcp.flags.syn"]) and not is_true(r["tcp.flags.ack"]):
            syn_count[r["ip.src"]] += 1
            syn_ports[r["ip.src"]].add(r["tcp.dstport"])
        if r["http.request.method"]:
            methods[r["http.request.method"]] += 1
            hosts[r["http.host"]] += 1
            uris[cut(r["http.request.uri"])] += 1
            agents[cut(r["http.user_agent"])] += 1
    return {
        "total_packets": total,
        "top_dst_ports": top(ports, max_items),
        "syn_sources": [
            {"src": s, "syn_packets": c, "distinct_dst_ports": len(syn_ports[s])}
            for s, c in syn_count.most_common(5)
        ],
        "http_methods": top(methods, max_items),
        "http_hosts": top(hosts, max_items),
        "http_uris": top(uris, max_items),
        "http_user_agents": top(agents, max_items),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap")
    parser.add_argument("-o", "--output", help="fichier JSON de sortie")
    args = parser.parse_args()
    result = json.dumps(summarize(args.pcap), indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
    print(result)
