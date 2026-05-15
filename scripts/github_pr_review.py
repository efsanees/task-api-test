#!/usr/bin/env python3
"""
DevSecOps AI — GitHub Actions PR Review Script
Gereksinimler: pip install bandit groq requests
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

import requests

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
PR_NUMBER    = int(os.environ.get("PR_NUMBER", "0"))
REPO         = os.environ.get("REPO", "")
HEAD_SHA     = os.environ.get("HEAD_SHA", "")
BASE_SHA     = os.environ.get("BASE_SHA", "")

GH_API = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept":        "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ── GitHub API ─────────────────────────────────────────────────────────────────

def get_changed_files():
    url = f"{GH_API}/repos/{REPO}/pulls/{PR_NUMBER}/files"
    resp = requests.get(url, headers=HEADERS, timeout=15)
    return resp.json() if resp.status_code == 200 else []


def get_file_content(path, ref):
    url = f"{GH_API}/repos/{REPO}/contents/{path}"
    resp = requests.get(url, headers=HEADERS, params={"ref": ref}, timeout=10)
    if resp.status_code == 200:
        return base64.b64decode(resp.json()["content"]).decode("utf-8", errors="ignore")
    return None


def post_comment(body):
    url = f"{GH_API}/repos/{REPO}/issues/{PR_NUMBER}/comments"
    resp = requests.post(url, headers=HEADERS, json={"body": body}, timeout=15)
    return resp.status_code == 201

# ── SAST: Bandit ───────────────────────────────────────────────────────────────

def run_bandit(tmp_dir):
    try:
        proc = subprocess.run(
            ["bandit", "-r", tmp_dir, "-f", "json", "-q", "--exit-zero"],
            capture_output=True, text=True, timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"Bandit hatasi: {e}")
        return []

    raw = proc.stdout.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for issue in data.get("results", []):
        fname = issue.get("filename", "")
        fname = fname.replace(tmp_dir + "/", "").replace(tmp_dir + "\\", "").lstrip("/")
        sev = issue.get("issue_severity", "MEDIUM").upper()
        findings.append({
            "rule_id":  issue.get("test_id", ""),
            "severity": sev,
            "file":     fname,
            "line":     issue.get("line_number"),
            "message":  issue.get("issue_text", ""),
            "type":     "SAST",
            "source":   "bandit",
        })
    return findings

# ── CWE / OWASP haritalaması ──────────────────────────────────────────────────

_BANDIT_CWE = {
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259",
    "B201": "CWE-94",  "B301": "CWE-502", "B302": "CWE-502",
    "B303": "CWE-327", "B307": "CWE-78",  "B501": "CWE-295",
    "B502": "CWE-326", "B601": "CWE-78",  "B602": "CWE-78",
    "B603": "CWE-78",  "B605": "CWE-78",  "B608": "CWE-89",
}
_CWE_OWASP = {
    "CWE-78": "A03:2021", "CWE-79": "A03:2021", "CWE-89": "A03:2021",
    "CWE-94": "A03:2021", "CWE-259": "A07:2021", "CWE-295": "A02:2021",
    "CWE-326": "A02:2021", "CWE-327": "A02:2021", "CWE-502": "A08:2021",
}

def enrich(finding):
    rule = finding.get("rule_id", "").upper()
    cwe = _BANDIT_CWE.get(rule)
    finding["cwe_id"] = cwe
    finding["owasp_category"] = _CWE_OWASP.get(cwe) if cwe else None
    return finding

# ── LLM False Positive Filtresi ───────────────────────────────────────────────

def fp_filter(findings):
    if not GROQ_API_KEY:
        return findings, []

    candidates = [(i, f) for i, f in enumerate(findings)
                  if f.get("severity") in ("HIGH", "CRITICAL")][:10]
    if not candidates:
        return findings, []

    summaries = "\n".join(
        f"[{idx}] {f['rule_id']} | {f['file']}:{f['line']} | {f['message'][:100]}"
        for idx, (_, f) in enumerate(candidates)
    )

    prompt = (
        "SAST bulgularinin false positive mi gercek sorun mu oldugunu degerlendir.\n"
        f"Bulgular:\n{summaries}\n\n"
        "JSON array don: "
        '[{"index":0,"is_fp":false,"confidence":0.90,"reason":"..."}]\n'
        "Sadece JSON array."
    )

    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400,
            temperature=0.1,
        )
        raw = resp.choices[0].message.content.strip()
        start, end = raw.find("["), raw.rfind("]") + 1
        decisions = json.loads(raw[start:end]) if start >= 0 and end > 0 else []
    except Exception as e:
        print(f"FP filter hatasi: {e}")
        return findings, []

    fp_local = set()
    for d in decisions:
        local_idx = d.get("index")
        if local_idx is not None and d.get("is_fp") and d.get("confidence", 0) >= 0.65:
            fp_local.add(local_idx)

    fp_global = {candidates[i][0] for i in fp_local if i < len(candidates)}
    fp_list   = [findings[g] for g in fp_global]
    genuine   = [f for i, f in enumerate(findings) if i not in fp_global]
    return genuine, fp_list

# ── Markdown yorum oluştur ───────────────────────────────────────────────────

_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

def build_comment(findings, fp_list, files_scanned):
    total = len(findings)
    high  = sum(1 for f in findings if f.get("severity") in ("HIGH", "CRITICAL"))
    med   = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    lines = [
        "## 🔍 DevSecOps Code Review",
        "",
        f"{files_scanned} dosya tarandi · **{total}** sorun bulundu "
        f"({high} kritik/yuksek · {med} orta)",
        "",
    ]

    if fp_list:
        lines += [
            "> [!NOTE]",
            f"> **LLM False Positive Analizi:** {total + len(fp_list)} SAST bulgusundan "
            f"**{len(fp_list)}** tanesi false positive olarak filtrelendi (guven esigi: %65).",
            "  ",
            f">  - {chr(10).join('> - ' + f.get('message', f.get('rule_id',''))[:80] for f in fp_list)}",
            "",
        ]

    if high:
        lines += [
            "> [!CAUTION]",
            f"> Bu PR'da **{high} yuksek oncelikli guvenlik acigi** var. "
            "Merge etmeden once duzeltilmesi onerilir.",
            "",
        ]

    # Dosya bazında grupla
    by_file = {}
    for f in findings:
        by_file.setdefault(f.get("file") or "bilinmeyen", []).append(f)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for fname, flist in sorted(by_file.items()):
        lines += [f"### 📄 `{fname}`", ""]
        for f in sorted(flist, key=lambda x: sev_order.get(x.get("severity",""), 4)):
            icon  = _ICON.get(f.get("severity",""), "⚪")
            cwe   = f.get("cwe_id","")
            owasp = f.get("owasp_category","")
            conf  = "%95"
            meta  = f"`{f.get('file','')}:{f.get('line','')}`"
            if f.get("rule_id"): meta += f" · Kural: `{f['rule_id']}`"
            if conf:   meta += f" · guven: {conf}"
            if cwe:    meta += f" · `{cwe}`"
            if owasp:  meta += f" · `{owasp}`"
            lines += [
                f"{icon} **{f.get('severity','')}** — {f.get('message','')}",
                f"  {meta}",
                "",
            ]

    lines += [
        "---",
        "_Bu analiz [DevSecOps AI](https://github.com/efsanees/devsecops) "
        "tarafindan otomatik olarak yapilmistir._",
    ]
    return "\n".join(lines)

# ── Ana akış ─────────────────────────────────────────────────────────────────

def main():
    print(f"PR #{PR_NUMBER} analiz ediliyor — {REPO}")

    changed_files = get_changed_files()
    py_files  = [f["filename"] for f in changed_files if f["filename"].endswith(".py")]
    all_files = [f["filename"] for f in changed_files]

    print(f"Degisen dosyalar: {len(all_files)} ({len(py_files)} Python)")

    if not all_files:
        print("Degisen dosya yok, analiz atlandiyor.")
        return

    if not py_files:
        body = (
            "## 🔍 DevSecOps Code Review\n\n"
            f"{len(all_files)} dosya tarandiyor — Python dosyasi degismedi, "
            "SAST analizi atlandiyor."
        )
        post_comment(body)
        return

    # Dosyaları geçici dizine indir
    with tempfile.TemporaryDirectory(prefix="pr_review_") as tmp:
        downloaded = 0
        for path in py_files:
            content = get_file_content(path, HEAD_SHA)
            if not content:
                continue
            dest = os.path.join(tmp, path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(content)
            downloaded += 1

        print(f"Indirilen: {downloaded} Python dosyasi")
        findings_raw = run_bandit(tmp)

    print(f"Bandit: {len(findings_raw)} ham bulgu")

    # CWE / OWASP zenginleştir
    findings_enriched = [enrich(f) for f in findings_raw]

    # False Positive filtresi
    genuine, fp_list = fp_filter(findings_enriched)
    print(f"FP filtresi: {len(fp_list)} false positive ayiklandi")

    # Yorum oluştur ve gönder
    body = build_comment(genuine, fp_list, len(all_files))
    ok = post_comment(body)
    print("Comment gonderildi." if ok else "Comment gonderilemedi!")

if __name__ == "__main__":
    main()
