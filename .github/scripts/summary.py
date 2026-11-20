"""Résumés Markdown des rapports de sécurité pour $GITHUB_STEP_SUMMARY.

Usage :
  summary.py gitleaks gitleaks-report.json
  summary.py iac trivy-iac.json
  summary.py image trivy-image.json <image>
  summary.py sbom sbom.cdx.json
"""
import json
import os
import sys
from collections import Counter

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def load(path):
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def gitleaks(path):
    data = load(path) or []
    print("## Gitleaks : secrets dans le code et l'historique Git\n")
    if not data:
        print("**Aucun secret détecté** dans les commits analysés. :white_check_mark:")
        return
    print(f"**{len(data)} secret(s) détecté(s)** : le pipeline est bloqué. :x:\n")
    print("| Règle | Fichier | Ligne | Commit | Date | Secret |")
    print("|---|---|---|---|---|---|")
    for f in data:
        print(f"| {f['RuleID']} | `{f['File']}` | {f['StartLine']} | `{f['Commit'][:7]}` "
              f"| {f.get('Date', '')[:10]} | `{f['Secret']}` |")
    print("\nLes valeurs sont masquées (`--redact`). Un secret présent dans un ancien commit "
          "reste exploitable : il faut le révoquer puis réécrire l'historique.")


def iac(path):
    data = load(path) or {}
    rows, count = [], Counter()
    for res in data.get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            count[m["Severity"]] += 1
            rows.append((SEV.index(m["Severity"]), res["Target"], m["ID"], m["Severity"], m["Title"]))
    print("## Trivy config : analyse IaC des manifestes Kubernetes\n")
    print("| " + " | ".join(SEV[:4]) + " | Total |")
    print("|" + "---|" * 5)
    print("| " + " | ".join(str(count[s]) for s in SEV[:4]) + f" | {sum(count.values())} |\n")
    blocking = count["CRITICAL"] + count["HIGH"]
    if blocking:
        print(f"**{blocking} non-conformité(s) CRITICAL/HIGH** : le build est bloqué. :x:\n")
    else:
        print("**Aucune non-conformité CRITICAL/HIGH** : la gate IaC est passée. :white_check_mark:\n")
    if rows:
        print("| Fichier | ID | Sévérité | Problème |")
        print("|---|---|---|---|")
        for _, t, i, s, title in sorted(rows):
            print(f"| `{t}` | {i} | {s} | {title} |")


def checkov(path):
    data = load(path) or {}
    reports = data if isinstance(data, list) else [data]
    failed, passed = [], 0
    for r in reports:
        res = r.get("results", {})
        passed += r.get("summary", {}).get("passed", len(res.get("passed_checks", [])))
        failed += res.get("failed_checks", [])
    print("## Checkov : bonnes pratiques Kubernetes\n")
    print(f"Contrôles réussis : **{passed}**, échoués : **{len(failed)}**\n")
    if not failed:
        print("**Tous les contrôles Checkov sont conformes.** :white_check_mark:")
        return
    print("| Check | Ressource | Fichier | Problème |")
    print("|---|---|---|---|")
    for c in failed:
        print(f"| {c['check_id']} | `{c['resource']}` | `{c['file_path'].lstrip('/')}` | {c['check_name']} |")


def image(path, name):
    data = load(path) or {}
    count, rows = Counter(), []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            count[v["Severity"]] += 1
            if v["Severity"] in ("CRITICAL", "HIGH"):
                rows.append((v["PkgName"], v["VulnerabilityID"], v["Severity"], v.get("FixedVersion", "")))
    print(f"## Trivy image : `{name}`\n")
    print("| " + " | ".join(SEV) + " | Total |")
    print("|" + "---|" * 6)
    print("| " + " | ".join(str(count[s]) for s in SEV) + f" | {sum(count.values())} |\n")
    if rows:
        print("| Paquet | CVE | Sévérité | Corrigé en |")
        print("|---|---|---|---|")
        for r in rows[:20]:
            print("| " + " | ".join(r) + " |")
    else:
        print("**Aucune vulnérabilité HIGH/CRITICAL** : l'image peut être signée. :white_check_mark:")


def sbom(path):
    data = load(path) or {}
    comps = data.get("components", [])
    types = Counter(c.get("type", "?") for c in comps)
    langs = Counter()
    for c in comps:
        purl = c.get("purl", "")
        langs[purl.split("/")[0].replace("pkg:", "") if purl else "autre"] += 1
    meta = data.get("metadata", {}).get("component", {})
    print("## SBOM (Syft, CycloneDX)\n")
    print(f"- Format : **{data.get('bomFormat')} {data.get('specVersion')}**")
    print(f"- Image : `{meta.get('name', '')}`")
    print(f"- Composants inventoriés : **{len(comps)}** "
          f"({', '.join(f'{k} : {v}' for k, v in types.most_common())})")
    print(f"- Écosystèmes : {', '.join(f'{k} : {v}' for k, v in langs.most_common())}\n")
    print("| Composant | Version | Type | Licence |")
    print("|---|---|---|---|")
    py = [c for c in comps if c.get("purl", "").startswith("pkg:pypi")]
    for c in py[:15]:
        lic = ", ".join(
            (l.get("license", {}).get("id") or l.get("license", {}).get("name") or l.get("expression", ""))
            for l in c.get("licenses", [])
        )
        print(f"| {c['name']} | {c.get('version', '')} | {c.get('type')} | {lic} |")


if __name__ == "__main__":
    kind = sys.argv[1]
    if kind == "gitleaks":
        gitleaks(sys.argv[2])
    elif kind == "iac":
        iac(sys.argv[2])
    elif kind == "checkov":
        checkov(sys.argv[2])
    elif kind == "image":
        image(sys.argv[2], sys.argv[3])
    elif kind == "sbom":
        sbom(sys.argv[2])
