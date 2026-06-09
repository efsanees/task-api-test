#!/usr/bin/env python3
"""
DevSecOps AI — GitHub Actions PR Review Script

Özellikler:
  1. Bandit SAST taraması (PR'da değişen .py dosyaları)
  2. CWE / OWASP Top 10 zenginleştirme
  3. LLM false positive filtresi (Groq, Llama-3.3-70b)
  4. AI düzeltme önerileri — tüm bulgulara somut fix
  5. Baseline karşılaştırma — kaç yeni sorun eklendi / kaçı düzeltildi
  6. SCA bağımlılık taraması — requirements.txt / package.json → OSV.dev
"""
import base64
import json
import os
import subprocess
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

# ── GitHub API ────────────────────────────────────────────────────────────────

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


def post_check_run(conclusion: str, title: str, summary: str) -> None:
    """GitHub Checks API ile 'Security Gate' check oluşturur."""
    if not HEAD_SHA or not REPO:
        return
    payload = {
        "name":       "Security Gate",
        "head_sha":   HEAD_SHA,
        "status":     "completed",
        "conclusion": conclusion,
        "output": {"title": title, "summary": summary},
    }
    resp = requests.post(
        f"{GH_API}/repos/{REPO}/check-runs",
        headers=HEADERS, json=payload, timeout=15,
    )
    ok = resp.status_code in (200, 201)
    print(f"[CheckRun] {'OK' if ok else 'HATA ' + str(resp.status_code)}: {conclusion} — {title}")

# ── SAST: Bandit ──────────────────────────────────────────────────────────────

def run_bandit(tmp_dir: str) -> list[dict]:
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

# ── Türkçe bulgu mesajları ────────────────────────────────────────────────────

_BANDIT_TR = {
    "B101": "assert ifadesi üretim kodunda güvenlik açığı oluşturabilir",
    "B102": "exec() kullanımı kod enjeksiyonuna yol açabilir",
    "B103": "Güvensiz dosya izinleri tespit edildi",
    "B104": "0.0.0.0 adresine bağlama — tüm ağ arayüzleri açık",
    "B105": "Hardcoded şifre tespit edildi",
    "B106": "Fonksiyon argümanında hardcoded şifre",
    "B107": "Varsayılan parametrede hardcoded şifre",
    "B108": "Güvensiz geçici dosya kullanımı",
    "B201": "Flask debug=True ile çalışıyor — üretimde kapatılmalı",
    "B301": "pickle modülü güvensiz veri deserializasyonuna yol açabilir",
    "B302": "marshal modülü güvensiz veri deserializasyonuna yol açabilir",
    "B303": "MD5/SHA1 kriptografik olarak güvensiz hash algoritması",
    "B304": "Zayıf şifreleme algoritması kullanımı",
    "B305": "Güvensiz şifreleme modu kullanımı",
    "B306": "mktemp() yarış koşulu açığı oluşturabilir",
    "B307": "eval() kullanımı kod enjeksiyonuna yol açabilir",
    "B308": "mark_safe() XSS açığına yol açabilir",
    "B310": "urllib ile URL açma — SSRF riski",
    "B311": "random modülü kriptografik amaçlı kullanılamaz",
    "B312": "telnetlib şifresiz protokol — güvensiz",
    "B314": "xml.etree XML injection açığına karşı savunmasız",
    "B318": "xml.dom XML injection açığına karşı savunmasız",
    "B320": "lxml XML injection açığına karşı savunmasız",
    "B321": "FTP şifresiz protokol — güvensiz",
    "B323": "SSL sertifikası doğrulanmıyor",
    "B324": "MD5/SHA1 zayıf hash algoritması kullanımı",
    "B401": "telnetlib modülü import edildi — şifresiz protokol",
    "B402": "ftplib modülü import edildi — şifresiz protokol",
    "B403": "pickle modülü import edildi — güvensiz deserializasyon riski",
    "B404": "subprocess modülü kullanılıyor — güvenli kullanım gerekli",
    "B405": "xml.etree modülü import edildi — XML injection riski",
    "B501": "SSL sertifika doğrulaması devre dışı",
    "B502": "Eski SSL/TLS protokol sürümü kullanılıyor",
    "B503": "Zayıf SSL cipher suite kullanımı",
    "B504": "Güvensiz SSL protokol sürümü",
    "B505": "Zayıf kriptografik anahtar boyutu",
    "B506": "yaml.load() güvensiz — arbitrary kod çalıştırabilir",
    "B601": "Paramiko shell komutu enjeksiyona açık",
    "B602": "shell=True ile subprocess — komut enjeksiyonu riski",
    "B603": "subprocess çağrısı — shell argümanları doğrulanmalı",
    "B604": "Shell fonksiyon çağrısı — enjeksiyon riski",
    "B605": "Shell ile process başlatma — enjeksiyon tespit edildi",
    "B606": "os.popen() kullanımı — komut enjeksiyonu riski",
    "B607": "Kısmi yürütülebilir dosya yolu — PATH hijacking riski",
    "B608": "String birleştirme ile SQL sorgusu — SQL injection riski",
    "B609": "Wildcard ile shell komutu — enjeksiyon riski",
    "B610": "Django extra() SQL injection içerebilir",
    "B611": "Django RawSQL() doğrudan SQL enjeksiyonu riski",
    "B701": "Jinja2 autoescape kapalı — XSS riski",
    "B702": "Mako template kullanımı — XSS riski",
    "B703": "Django mark_safe() XSS açığına yol açabilir",
}

def tr_message(finding: dict) -> str:
    """Bandit İngilizce mesajını Türkçe karşılığıyla değiştirir, yoksa orijinali döner."""
    rule = finding.get("rule_id", "").upper()
    return _BANDIT_TR.get(rule, finding.get("message", ""))

# ── CWE / OWASP haritalaması ──────────────────────────────────────────────────

_BANDIT_CWE = {
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259",
    "B201": "CWE-94",  "B301": "CWE-502", "B302": "CWE-502",
    "B303": "CWE-327", "B307": "CWE-78",  "B324": "CWE-327",
    "B404": "CWE-78",  "B501": "CWE-295",
    "B502": "CWE-326", "B601": "CWE-78",  "B602": "CWE-78",
    "B603": "CWE-78",  "B605": "CWE-78",  "B608": "CWE-89",
}
_CWE_OWASP = {
    "CWE-78":  "A03:2021", "CWE-79": "A03:2021", "CWE-89": "A03:2021",
    "CWE-94":  "A03:2021", "CWE-259": "A07:2021", "CWE-295": "A02:2021",
    "CWE-326": "A02:2021", "CWE-327": "A02:2021", "CWE-502": "A08:2021",
}

def enrich(finding: dict) -> dict:
    rule = finding.get("rule_id", "").upper()
    cwe  = _BANDIT_CWE.get(rule)
    finding["cwe_id"]        = cwe
    finding["owasp_category"] = _CWE_OWASP.get(cwe) if cwe else None
    return finding

# ── 1. LLM False Positive Filtresi ───────────────────────────────────────────

def fp_filter(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    HIGH/CRITICAL bulguları LLM'e gönderir.
    Gerçek sorun olmayanları (is_fp=True, confidence>=0.65) filtreler.
    Döner: (genuine_findings, fp_list)
    """
    if not GROQ_API_KEY:
        return findings, []

    candidates = [
        (i, f) for i, f in enumerate(findings)
        if f.get("severity") in ("HIGH", "CRITICAL")
    ][:10]
    if not candidates:
        return findings, []

    summaries = "\n".join(
        f"[{idx}] {f['rule_id']} | {f['file']}:{f['line']} | {f['message'][:120]}"
        for idx, (_, f) in enumerate(candidates)
    )

    prompt = (
        "Asagidaki Python SAST bulgularinin false positive mi yoksa gercek guvenlik sorunu mu "
        "oldugunu belirle. Proje bir web API.\n\n"
        f"Bulgular:\n{summaries}\n\n"
        "Her bulgu icin karar ver. JSON array don:\n"
        '[{"index":0,"is_fp":false,"confidence":0.90,"reason":"Gercek shell injection riski"}]\n'
        "Yalnizca JSON array, baska hicbir sey yazma."
    )

    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.1,
        )
        raw   = resp.choices[0].message.content.strip()
        start = raw.find("[")
        end   = raw.rfind("]") + 1
        decisions = json.loads(raw[start:end]) if start >= 0 and end > 0 else []
    except Exception as e:
        print(f"FP filter hatasi: {e}")
        return findings, []

    fp_local = set()
    for d in decisions:
        local_idx = d.get("index")
        if local_idx is not None and d.get("is_fp") and d.get("confidence", 0) >= 0.65:
            fp_local.add(local_idx)
            # reason'ı orijinal bulguya ekle (comment'te göstermek için)
            if local_idx < len(candidates):
                candidates[local_idx][1]["fp_reason"] = d.get("reason", "")

    fp_global = {candidates[i][0] for i in fp_local if i < len(candidates)}
    fp_list   = [findings[g] for g in sorted(fp_global)]
    genuine   = [f for i, f in enumerate(findings) if i not in fp_global]
    return genuine, fp_list

# ── 2. AI Düzeltme Önerileri (Remediation) ───────────────────────────────────

def add_fix_suggestions(findings: list[dict], language: str = "Python") -> None:
    """
    Tüm bulgulara in-place olarak fix_suggestion alanı ekler.
    Severity sırasına göre önceliklendirilir (HIGH önce), max 15 bulgu.
    Tek bir Groq çağrısı kullanılır.
    """
    if not GROQ_API_KEY or not findings:
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        enumerate(findings),
        key=lambda x: sev_order.get(x[1].get("severity", ""), 4),
    )
    candidates = sorted_findings[:15]
    if not candidates:
        return

    def _summarize(idx: int, f: dict) -> str:
        cwe  = f.get("cwe_id", "?")
        owasp = f.get("owasp_category", "?")
        return (
            f"[{idx}] {f.get('rule_id','')} | {f.get('severity','')} | "
            f"{f.get('file','')}:{f.get('line','')} | "
            f"{f.get('message','')[:120]} | CWE: {cwe} | OWASP: {owasp}"
        )

    summaries = "\n".join(_summarize(i, f) for i, (_, f) in enumerate(candidates))

    prompt = (
        f"Sen bir kıdemli {language} güvenlik mühendisisin.\n"
        "Aşağıdaki SAST bulgularının her biri için kısa, teknik ve uygulanabilir "
        "Türkçe düzeltme önerisi yaz.\n\n"
        f"Bulgular:\n{summaries}\n\n"
        "Yanıt formatı — yalnızca JSON array, başka hiçbir şey yazma:\n"
        '[{"index":0,"fix":"...somut tek-cümle düzeltme adımı..."}]\n\n'
        "Kurallar:\n"
        "- Türkçe karakter kullan: ş, ç, ö, ü, ğ, ı, İ harflerini doğru yaz\n"
        "- Her fix en fazla 2 kısa cümle\n"
        "- Somut ol: fonksiyon adı, parametre, sürüm numarası belirt\n"
        '- Örnek: "subprocess.run() çağrısında shell=False kullanın, '
        "komutları liste olarak geçirin: subprocess.run(['cmd', arg1])\"\n"
        "- Sadece JSON array döndür, açıklama ekleme"
    )

    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=900,
            temperature=0.1,
        )
        raw   = resp.choices[0].message.content.strip()
        start = raw.find("[")
        end   = raw.rfind("]") + 1
        fixes = json.loads(raw[start:end]) if start >= 0 and end > 0 else []
    except Exception as e:
        print(f"Remediation hatasi: {e}")
        return

    applied = 0
    for item in fixes:
        local_idx = item.get("index")
        fix = (item.get("fix") or "").strip()
        if fix and local_idx is not None and local_idx < len(candidates):
            candidates[local_idx][1]["fix_suggestion"] = fix
            applied += 1

    print(f"Remediation: {applied}/{len(candidates)} bulguya duzeltme onerisi eklendi")

# ── 3. Baseline Karşılaştırma ─────────────────────────────────────────────────

def _finding_key(f: dict) -> str:
    """Bulguyu tanımlayan kararlı anahtar — line numarası dahil değil (PR'da kayabilir)."""
    return f"{f.get('rule_id','')}::{f.get('file','')}::{f.get('message','')[:60]}"


def compute_baseline_diff(
    py_files: list[str],
    head_findings: list[dict],
) -> dict:
    """
    BASE_SHA'daki haliyle aynı dosyaları tarar, HEAD ile karşılaştırır.
    Döner: {"added": [...], "fixed": [...], "unchanged_count": int}
    """
    if not BASE_SHA:
        return {}

    base_findings: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="pr_base_") as base_tmp:
        downloaded = 0
        for path in py_files:
            content = get_file_content(path, BASE_SHA)
            if not content:
                continue
            dest = os.path.join(base_tmp, path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(content)
            downloaded += 1

        if downloaded:
            raw_base = run_bandit(base_tmp)
            base_findings = [enrich(f) for f in raw_base]

    base_keys  = {_finding_key(f) for f in base_findings}
    head_keys  = {_finding_key(f) for f in head_findings}

    added   = [f for f in head_findings if _finding_key(f) not in base_keys]
    fixed   = [f for f in base_findings if _finding_key(f) not in head_keys]
    unchanged = len(base_keys & head_keys)

    print(f"Baseline: {len(base_findings)} bulgu → HEAD: {len(head_findings)} bulgu "
          f"(+{len(added)} yeni, -{len(fixed)} duzeltildi, ={unchanged} degismedi)")

    return {"added": added, "fixed": fixed, "unchanged_count": unchanged}

# ── Markdown yorum oluştur ────────────────────────────────────────────────────

_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

def build_comment(
    findings: list[dict],
    fp_list: list[dict],
    files_scanned: int,
    diff: dict,
    sca_findings: list[dict] = None,
    packages_checked: int = 0,
) -> str:
    total = len(findings)
    high  = sum(1 for f in findings if f.get("severity") in ("HIGH", "CRITICAL"))
    med   = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    lines = ["## 🔍 DevSecOps Code Review", ""]

    # ── Baseline karşılaştırma özeti ──
    if diff:
        added_count   = len(diff.get("added", []))
        fixed_count   = len(diff.get("fixed", []))
        unchanged_cnt = diff.get("unchanged_count", 0)
        diff_parts = []
        if added_count:
            diff_parts.append(f"🆕 **{added_count} yeni**")
        if fixed_count:
            diff_parts.append(f"✅ **{fixed_count} düzeltildi**")
        if unchanged_cnt:
            diff_parts.append(f"📌 {unchanged_cnt} değişmedi")
        lines += [
            "> [!TIP]",
            f"> **Baseline karşılaştırma:** {' · '.join(diff_parts) if diff_parts else 'Değişiklik yok'}",
            "",
        ]

    lines += [
        f"{files_scanned} dosya tarandı · **{total}** sorun bulundu "
        f"({high} kritik/yüksek · {med} orta)",
        "",
    ]

    # ── False Positive notu ──
    if fp_list:
        fp_messages = []
        for f in fp_list:
            msg = f.get("message", f.get("rule_id", ""))[:80]
            reason = f.get("fp_reason", "")
            fp_messages.append(f"> - {msg}" + (f" *(_{reason}_)*" if reason else ""))

        lines += [
            "> [!NOTE]",
            f"> **LLM False Positive Analizi:** {total + len(fp_list)} SAST bulgusundan "
            f"**{len(fp_list)}** tanesi false positive olarak filtrelendi (güven eşiği: %65).",
            *fp_messages,
            "",
        ]

    # ── Caution ──
    if high:
        lines += [
            "> [!CAUTION]",
            f"> Bu PR'da **{high} yüksek öncelikli güvenlik açığı** var. "
            "Merge etmeden önce düzeltilmesi önerilir.",
            "",
        ]

    # ── Bulgular (dosya bazında) ──
    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f.get("file") or "bilinmeyen", []).append(f)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for fname, flist in sorted(by_file.items()):
        lines += [f"### 📄 `{fname}`", ""]
        for f in sorted(flist, key=lambda x: sev_order.get(x.get("severity", ""), 4)):
            icon  = _ICON.get(f.get("severity", ""), "⚪")
            cwe   = f.get("cwe_id", "")
            owasp = f.get("owasp_category", "")
            meta  = f"`{f.get('file','')}:{f.get('line','')}`"
            if f.get("rule_id"): meta += f" · Kural: `{f['rule_id']}`"
            if cwe:   meta += f" · `{cwe}`"
            if owasp: meta += f" · `{owasp}`"

            lines += [
                f"{icon} **{f.get('severity','')}** — {tr_message(f)}",
                f"  {meta}",
            ]

            # Düzeltme önerisi
            fix = f.get("fix_suggestion", "")
            if fix:
                lines.append(f"  > 💡 **Düzeltme:** {fix}")

            lines.append("")

    # ── Yeni eklenen bulgular özeti (baseline'da yoktu) ──
    if diff and diff.get("added"):
        lines += ["### 🆕 Bu PR ile Eklenen Yeni Sorunlar", ""]
        for f in diff["added"][:5]:
            icon = _ICON.get(f.get("severity", ""), "⚪")
            lines.append(
                f"- {icon} `{f.get('file','')}:{f.get('line','')}` — "
                f"{tr_message(f)[:80]}"
            )
        if len(diff["added"]) > 5:
            lines.append(f"- _...ve {len(diff['added']) - 5} tane daha_")
        lines.append("")

    # ── Düzeltilen bulgular özeti ──
    if diff and diff.get("fixed"):
        lines += ["### ✅ Bu PR ile Düzeltilen Sorunlar", ""]
        for f in diff["fixed"][:5]:
            lines.append(
                f"- ~~`{f.get('file','')}` — {tr_message(f)[:60]}~~"
            )
        lines.append("")

    # ── SCA bağımlılık bulguları ──
    if sca_findings is not None:
        sca_high = sum(1 for f in sca_findings if f.get("severity") in ("CRITICAL", "HIGH"))
        sca_title = (
            f"### 📦 Bağımlılık Güvenliği — SCA "
            f"({packages_checked} paket · {len(sca_findings)} CVE)"
        )
        lines += ["", sca_title, ""]

        if not sca_findings:
            lines.append("✅ Bilinen CVE bulunamadı.")
        else:
            if sca_high:
                lines += [
                    "> [!WARNING]",
                    f"> **{sca_high} kritik/yüksek CVE** tespit edildi. "
                    "Paketleri güncellemeden merge etmeyin.",
                    "",
                ]

            # Paket bazında grupla — her paketten en kötü CVE'yi öne çıkar
            by_pkg: dict[str, list] = {}
            for f in sca_findings:
                by_pkg.setdefault(f["package"], []).append(f)

            shown = 0
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for pkg_name, pkg_findings in by_pkg.items():
                pkg_findings.sort(key=lambda x: sev_order.get(x.get("severity", ""), 4))
                worst = pkg_findings[0]
                icon    = _ICON.get(worst.get("severity", ""), "⚪")
                sev     = worst.get("severity", "")
                ver     = worst.get("version", "")
                vuln_id = worst.get("vuln_id", "")
                fixed   = worst.get("fixed_in", "bilinmiyor")
                cvss    = worst.get("cvss_score")

                count = len(pkg_findings)

                # Türkçe açıklama öncelikli, yoksa İngilizce fallback
                summary = (
                    worst.get("summary_tr")
                    or next(
                        (f["summary"] for f in pkg_findings
                         if f.get("summary") and not f["summary"].startswith(("GHSA-", "CVE-", "PYSEC-"))),
                        worst.get("summary", ""),
                    )
                )
                fix_suggestion = worst.get("fix_suggestion", "")

                meta = f"`{pkg_name}@{ver}`"
                if count > 1: meta += f" · **{count} CVE**"
                if vuln_id:   meta += f" · `{vuln_id}`"
                if cvss:      meta += f" · CVSS {cvss}"

                lines += [
                    f"{icon} **{sev}** — {summary}",
                    f"  {meta}",
                ]
                if fix_suggestion:
                    lines.append(f"  > 💡 **Düzeltme:** `{fix_suggestion}`")
                lines.append("")
                shown += 1
                if shown >= 15:
                    remaining = len(by_pkg) - shown
                    if remaining > 0:
                        lines.append(f"_...ve {remaining} paket daha_\n")
                    break

    lines += [
        "---",
        "_Bu analiz [DevSecOps AI](https://github.com/efsanees/devsecops) "
        "tarafından otomatik olarak yapılmıştır._",
    ]
    return "\n".join(lines)

# ── 6. SCA: Bağımlılık Güvenlik Taraması ─────────────────────────────────────

_SEVERITY_FROM_CVSS = {
    lambda s: s >= 9.0: "CRITICAL",
    lambda s: s >= 7.0: "HIGH",
    lambda s: s >= 4.0: "MEDIUM",
}

def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _parse_requirements(content: str) -> list[dict]:
    """requirements.txt → [{name, version}, ...]"""
    import re
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*(?:[><=!~]+\s*([^\s,;]+))?", line)
        if m:
            packages.append({
                "name":    m.group(1).strip(),
                "version": (m.group(2) or "").strip().lstrip("="),
            })
    return packages


def _parse_package_json(content: str) -> list[dict]:
    """package.json → [{name, version}, ...]"""
    import re
    packages = []
    try:
        pkg = json.loads(content)
        all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        for name, ver in all_deps.items():
            packages.append({
                "name":    name,
                "version": re.sub(r"[^0-9.]", "", str(ver)).strip("."),
            })
    except Exception:
        pass
    return packages


def _query_osv(packages: list[dict], ecosystem: str) -> list[dict]:
    """
    OSV.dev Batch API — birden fazla paketi tek istekte sorgular.
    Versiyonsuz paketleri atlar (sürüm bilinmeden sorgu anlamsız).
    """
    # Versiyonsuz paketleri atla — wildcard sonuç gürültü yaratır
    versioned = [p for p in packages if p.get("version")]
    if not versioned:
        return []

    queries = [
        {
            "package": {"name": p["name"], "ecosystem": ecosystem},
            "version": p["version"],
        }
        for p in versioned
    ]
    packages = versioned  # zip için hizala

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
            timeout=20,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception as e:
        print(f"OSV.dev hatası ({ecosystem}): {e}")
        return []

    findings = []
    for pkg, result in zip(packages, results):
        for vuln in result.get("vulns", []):
            severity = "MEDIUM"
            cvss_score = None
            for sev in vuln.get("severity", []):
                if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
                    try:
                        cvss_score = float(sev.get("score", 0))
                        severity = _cvss_to_severity(cvss_score)
                    except (TypeError, ValueError):
                        pass
                    break

            fixed_in = "bilinmiyor"
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_in = event["fixed"]

            # summary → details → aliases → fallback sırasıyla dene
            summary = (
                vuln.get("summary")
                or vuln.get("details", "")[:120]
                or next(iter(vuln.get("aliases", [])), vuln.get("id", ""))
            )

            findings.append({
                "type":       "SCA",
                "package":    pkg["name"],
                "version":    pkg.get("version") or "?",
                "ecosystem":  ecosystem,
                "vuln_id":    vuln.get("id", "?"),
                "severity":   severity,
                "cvss_score": cvss_score,
                "summary":    (summary or "Açıklama yok")[:120],
                "fixed_in":   fixed_in,
            })
    return findings


def _fetch_vuln_summary(vuln_id: str) -> str:
    """OSV.dev tekil endpoint'inden summary çeker (batch API'si döndürmüyor)."""
    try:
        r = requests.get(
            f"https://api.osv.dev/v1/vulns/{vuln_id}",
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            return (
                data.get("summary")
                or (data.get("details", "") or "")[:120]
                or ""
            )
    except Exception:
        pass
    return ""


_DEP_FILES = {
    "requirements.txt": ("PyPI",   _parse_requirements),
    "package.json":     ("npm",    _parse_package_json),
}

def run_sca(all_filenames: list[str]) -> tuple[list[dict], int]:
    """
    PR'da bulunan bağımlılık dosyalarını okur, OSV.dev ile CVE tarar.
    Döner: (findings, packages_checked)
    """
    findings: list[dict] = []
    packages_checked = 0

    for fname, (ecosystem, parser) in _DEP_FILES.items():
        if fname not in all_filenames:
            continue
        content = get_file_content(fname, HEAD_SHA)
        if not content:
            continue
        packages = parser(content)
        packages_checked += len(packages)
        found = _query_osv(packages, ecosystem)
        findings.extend(found)
        print(f"SCA [{ecosystem}]: {len(packages)} paket → {len(found)} CVE")

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", ""), 4))

    # Batch API summary döndürmüyor — paket başına worst CVE için tekil endpoint çağır
    by_pkg: dict[str, list] = {}
    for f in findings:
        by_pkg.setdefault(f["package"], []).append(f)

    for pkg_findings in by_pkg.values():
        worst = pkg_findings[0]
        if not worst.get("summary") or worst["summary"].startswith(("GHSA-", "CVE-", "PYSEC-")):
            fetched = _fetch_vuln_summary(worst["vuln_id"])
            if fetched:
                worst["summary"] = fetched

    # Türkçe açıklama + güncelleme önerisi (tek Groq çağrısı)
    _add_sca_turkish(by_pkg)

    return findings, packages_checked


def _add_sca_turkish(by_pkg: dict) -> None:
    """
    Her paketin worst CVE'sine Türkçe açıklama ve fix_suggestion ekler.
    Tek Groq çağrısı kullanır.
    """
    if not GROQ_API_KEY:
        return

    items = []
    for pkg_name, pkg_findings in by_pkg.items():
        worst = pkg_findings[0]
        items.append({
            "index":   len(items),
            "pkg":     pkg_name,
            "version": worst.get("version", "?"),
            "vuln_id": worst.get("vuln_id", ""),
            "summary": worst.get("summary", ""),
            "fixed_in": worst.get("fixed_in", "bilinmiyor"),
            "cve_count": len(pkg_findings),
        })

    if not items:
        return

    pkg_list = "\n".join(
        f"[{it['index']}] {it['pkg']}@{it['version']} | {it['cve_count']} CVE | "
        f"düzeltme sürümü: {it['fixed_in']} | açıklama: {it['summary'][:100]}"
        for it in items
    )

    prompt = (
        "Aşağıdaki Python bağımlılık güvenlik açıkları için:\n"
        "1. Türkçe kısa açıklama (max 1 cümle, teknik)\n"
        "2. Türkçe güncelleme önerisi (hangi sürüme geçmeli, nasıl)\n\n"
        f"Paketler:\n{pkg_list}\n\n"
        "Yanıt formatı — yalnızca JSON array:\n"
        '[{"index":0,"description":"Türkçe açıklama...","fix":"pip install paket==X.Y.Z"}]\n'
        "Kurallar:\n"
        "- Türkçe karakter kullan: ş, ç, ö, ü, ğ, ı\n"
        "- description: güvenlik riskini 1 cümlede açıkla\n"
        "- fix: 'pip install paket==SÜRÜM' formatında somut komut ver, "
        "düzeltme sürümü bilinmiyorsa 'pip install paket --upgrade' yaz\n"
        "- Sadece JSON array döndür"
    )

    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.1,
        )
        raw   = resp.choices[0].message.content.strip()
        start = raw.find("[")
        end   = raw.rfind("]") + 1
        results = json.loads(raw[start:end]) if start >= 0 and end > 0 else []
    except Exception as e:
        print(f"SCA Türkçe çeviri hatası: {e}")
        return

    for r in results:
        idx = r.get("index")
        if idx is None or idx >= len(items):
            continue
        pkg_name = items[idx]["pkg"]
        worst = by_pkg[pkg_name][0]
        if r.get("description"):
            worst["summary_tr"] = r["description"]
        if r.get("fix"):
            worst["fix_suggestion"] = r["fix"]

    print(f"SCA Türkçe: {len(results)} paket işlendi")


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
        post_comment(
            "## 🔍 DevSecOps Code Review\n\n"
            f"{len(all_files)} dosya tarandı — Python dosyası değişmedi, "
            "SAST analizi atlanıyor."
        )
        return

    # HEAD dosyaları indir ve tara
    with tempfile.TemporaryDirectory(prefix="pr_head_") as tmp:
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

    # 1. False Positive filtresi
    genuine, fp_list = fp_filter(findings_enriched)
    print(f"FP filtresi: {len(fp_list)} false positive ayiklandi")

    # 2. AI Düzeltme önerileri (genuine HIGH/CRITICAL bulgulara)
    add_fix_suggestions(genuine)

    # 3. Baseline karşılaştırma
    diff = compute_baseline_diff(py_files, genuine)

    # 4. SCA — bağımlılık taraması (tüm değişen dosyalar arasında dep dosyası var mı)
    all_filenames = [f["filename"] for f in changed_files]
    sca_findings, packages_checked = run_sca(all_filenames)

    # Yorum oluştur ve gönder
    body = build_comment(genuine, fp_list, len(all_files), diff, sca_findings, packages_checked)
    ok = post_comment(body)
    print("Comment gonderildi." if ok else "Comment gonderilemedi!")

    # ── Security Gate check ──────────────────────────────────────────────────
    high_sast  = [f for f in genuine      if f.get("severity") in ("HIGH", "CRITICAL")]
    high_sca   = [f for f in sca_findings if f.get("severity") in ("HIGH", "CRITICAL")]
    total_high = len(high_sast) + len(high_sca)

    if total_high > 0:
        parts = []
        if high_sast: parts.append(f"{len(high_sast)} SAST")
        if high_sca:  parts.append(f"{len(high_sca)} SCA")
        title   = f"Security Gate: {total_high} HIGH/CRITICAL bulgu ({' + '.join(parts)}) — merge edilemez"
        summary = (
            f"**{total_high} yüksek/kritik güvenlik açığı** tespit edildi.\n\n"
            f"- Kod (SAST): {len(high_sast)} bulgu\n"
            f"- Bağımlılık (SCA): {len(high_sca)} CVE\n\n"
            "Güvenlik açıkları giderilmeden merge yapılamaz."
        )
        post_check_run("failure", title, summary)
        print(f"\n❌ MERGE ENGELLENDI: {title}")
    else:
        post_check_run(
            "success",
            "Security Gate: Güvenlik kontrolü geçti",
            "HIGH/CRITICAL seviyede güvenlik açığı bulunamadı. Merge güvenli.",
        )
        print("\n✅ Güvenlik kontrolü geçti.")


if __name__ == "__main__":
    main()
