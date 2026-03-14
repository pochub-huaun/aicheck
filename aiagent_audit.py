#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import stat
import shutil
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

try:
    import pandas as pd
except Exception:
    pd = None

AGENT_KEYWORDS = [
    "openclaw", "opencode", "agent", "aiagent", "autogen",
    "langchain", "crewai", "llama_index", "mcp"
]

CONFIG_EXTS = {".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".env", ".md"}
SCRIPT_EXTS = {".sh", ".py", ".js", ".ts", ".bash"}
LLM_KEYS = {"openai_api_key", "api_key", "base_url", "model", "models", "llm", "provider", "azure_openai"}
MCP_KEYS = {"mcp", "mcp_servers", "servers", "tools", "tool_servers"}

HIGH_RISK_KWS = [
    "remote code execution", "rce", "command injection",
    "shell injection", "privilege escalation", "local privilege escalation",
    "arbitrary command", "os command injection"
]

COMMON_SEARCH_PATHS = ["/opt", "/srv", "/usr/local", "/home", "/root", "/etc"]


def run_cmd(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def is_text_file(p: Path):
    try:
        with open(p, "rb") as f:
            chunk = f.read(4096)
        return b"\x00" not in chunk
    except Exception:
        return False


def safe_read(p: Path, max_bytes=1024 * 1024):
    try:
        if p.stat().st_size > max_bytes:
            return ""
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def likely_agent_path(path: Path):
    s = str(path).lower()
    return any(k in s for k in AGENT_KEYWORDS)


def extract_urls(text):
    return re.findall(r"https?://[^\s'\"<>]+", text)


def extract_ip_port(text):
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b", text)


def is_executable(path: Path):
    try:
        mode = path.stat().st_mode
        return bool(mode & stat.S_IXUSR) or path.suffix.lower() in SCRIPT_EXTS
    except Exception:
        return False


def discover_processes():
    rc, out, _ = run_cmd("ps aux")
    rows = []
    if rc == 0 and out:
        for line in out.splitlines()[1:]:
            low = line.lower()
            if any(k in low for k in AGENT_KEYWORDS):
                rows.append(line)
    return rows


def discover_systemd_services():
    rc, out, _ = run_cmd("systemctl list-units --type=service --all --no-pager")
    rows = []
    if rc == 0 and out:
        for line in out.splitlines():
            low = line.lower()
            if any(k in low for k in AGENT_KEYWORDS):
                rows.append(line.strip())
    return rows


def discover_candidate_dirs(depth=4):
    candidates = set()
    for base in COMMON_SEARCH_PATHS:
        bp = Path(base)
        if not bp.exists():
            continue
        try:
            for p in bp.rglob("*"):
                rel_depth = len(p.parts) - len(bp.parts)
                if rel_depth > depth:
                    continue
                if p.is_dir() and likely_agent_path(p):
                    candidates.add(p)
        except Exception:
            continue

    cwd = Path.cwd()
    for p in cwd.rglob("*"):
        if p.is_dir() and likely_agent_path(p):
            candidates.add(p)

    return sorted(candidates)


def parse_configs(target_dirs):
    llm_records, mcp_records, skill_records, script_records = [], [], [], []

    for d in target_dirs:
        for p in d.rglob("*"):
            if p.is_dir():
                if "skill" in p.name.lower():
                    skill_records.append({"path": str(p), "type": "skill_dir", "detail": "directory name contains skill"})
                continue

            suffix = p.suffix.lower()
            name_low = p.name.lower()

            if p.name == "SKILL.md" or "skill" in name_low:
                skill_records.append({"path": str(p), "type": "skill_file", "detail": "skill marker file"})

            if suffix in SCRIPT_EXTS or is_executable(p):
                content_head = safe_read(p, max_bytes=20000)[:400]
                script_records.append({
                    "path": str(p),
                    "ext": suffix or "no_ext",
                    "executable": is_executable(p),
                    "shebang": content_head.splitlines()[0] if content_head.startswith("#!") else ""
                })

            if suffix in CONFIG_EXTS and is_text_file(p):
                txt = safe_read(p)
                if not txt:
                    continue
                low = txt.lower()

                if any(k in low for k in LLM_KEYS):
                    llm_records.append({
                        "path": str(p),
                        "urls": ", ".join(extract_urls(txt)[:10]),
                        "endpoints_ip_port": ", ".join(extract_ip_port(txt)[:10]),
                        "hints": ", ".join(sorted(set(k for k in LLM_KEYS if k in low)))
                    })

                if any(k in low for k in MCP_KEYS):
                    mcp_records.append({
                        "path": str(p),
                        "urls": ", ".join(extract_urls(txt)[:10]),
                        "hints": ", ".join(sorted(set(k for k in MCP_KEYS if k in low)))
                    })

    def dedup(records):
        seen, out = set(), []
        for r in records:
            if r["path"] in seen:
                continue
            seen.add(r["path"])
            out.append(r)
        return out

    return dedup(llm_records), dedup(mcp_records), dedup(skill_records), dedup(script_records)


def generate_sbom(target_dirs, out_dir):
    sbom_files = []
    syft = shutil.which("syft")
    if not syft:
        return sbom_files, "syft not found, skip SBOM generation"

    for d in target_dirs:
        name = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(d).strip("/")) or "root"
        sbom_path = Path(out_dir) / f"sbom_{name}.cyclonedx.json"
        rc, _, err = run_cmd(f'{syft} dir:{str(d)} -o cyclonedx-json > "{sbom_path}"', timeout=600)
        if rc == 0 and sbom_path.exists():
            sbom_files.append(str(sbom_path))
        else:
            (Path(out_dir) / f"sbom_{name}.error.txt").write_text(err or "unknown syft error", encoding="utf-8")

    return sbom_files, ("ok" if sbom_files else "no sbom produced")


def scan_vulns_from_sbom(sbom_files, out_dir):
    vulns = []
    grype = shutil.which("grype")
    osv = shutil.which("osv-scanner")

    if not grype and not osv:
        return [], "No grype/osv-scanner found, skip vulnerability scan"

    for sbom in sbom_files:
        if grype:
            out_json = Path(out_dir) / (Path(sbom).stem + ".grype.json")
            rc, _, _ = run_cmd(f'{grype} sbom:"{sbom}" -o json > "{out_json}"', timeout=900)
            if rc == 0 and out_json.exists():
                try:
                    data = json.loads(out_json.read_text(encoding="utf-8", errors="ignore"))
                    for m in data.get("matches", []):
                        vuln = m.get("vulnerability", {})
                        art = m.get("artifact", {})
                        desc = (vuln.get("description") or "").lower()
                        vulns.append({
                            "source_sbom": sbom,
                            "component": art.get("name"),
                            "version": art.get("version"),
                            "cve": vuln.get("id"),
                            "severity": vuln.get("severity"),
                            "fix_versions": ",".join(vuln.get("fix", {}).get("versions", [])[:10]) if vuln.get("fix") else "",
                            "description": vuln.get("description", "")[:2000],
                            "high_risk_focus": "YES" if any(k in desc for k in HIGH_RISK_KWS) else ""
                        })
                except Exception:
                    pass
        else:
            out_json = Path(out_dir) / (Path(sbom).stem + ".osv.json")
            rc, _, _ = run_cmd(f'{osv} scan --sbom="{sbom}" --json > "{out_json}"', timeout=900)
            if rc == 0 and out_json.exists():
                try:
                    data = json.loads(out_json.read_text(encoding="utf-8", errors="ignore"))
                    for r in data.get("results", []):
                        pkg = r.get("packages", {})
                        for v in r.get("vulnerabilities", []):
                            txt = ((v.get("summary") or "") + " " + (v.get("details") or "")).lower()
                            vulns.append({
                                "source_sbom": sbom,
                                "component": pkg.get("name"),
                                "version": pkg.get("version"),
                                "cve": v.get("id"),
                                "severity": v.get("severity", ""),
                                "fix_versions": "",
                                "description": (v.get("summary", "") + "\n" + v.get("details", ""))[:2000],
                                "high_risk_focus": "YES" if any(k in txt for k in HIGH_RISK_KWS) else ""
                            })
                except Exception:
                    pass

    return vulns, "ok"


def build_graph_html(target_dirs, llm_records, mcp_records, skill_records, script_records, vulns, out_dir):
    graph_json = {"nodes": [], "edges": []}
    node_map = {}
    node_id = 0

    def add_node(label, ntype):
        nonlocal node_id
        key = f"{ntype}:{label}"
        if key in node_map:
            return node_map[key]
        node_id += 1
        node_map[key] = node_id
        graph_json["nodes"].append({"id": node_id, "label": label, "type": ntype})
        return node_id

    for d in target_dirs:
        did = add_node(str(d), "agent_dir")
        for rec in llm_records:
            if rec["path"].startswith(str(d)):
                graph_json["edges"].append({"from": did, "to": add_node(rec["path"], "llm_config"), "relation": "contains"})
        for rec in mcp_records:
            if rec["path"].startswith(str(d)):
                graph_json["edges"].append({"from": did, "to": add_node(rec["path"], "mcp_config"), "relation": "contains"})
        for rec in skill_records:
            if rec["path"].startswith(str(d)):
                graph_json["edges"].append({"from": did, "to": add_node(rec["path"], "skill"), "relation": "contains"})
        for rec in script_records:
            if rec["path"].startswith(str(d)):
                graph_json["edges"].append({"from": did, "to": add_node(rec["path"], "script"), "relation": "contains"})

    for v in vulns:
        cnode = add_node(f'{v.get("component", "?")}@{v.get("version", "?")}', "component")
        vnode = add_node(v.get("cve", "UNKNOWN-CVE"), "cve")
        graph_json["edges"].append({"from": cnode, "to": vnode, "relation": v.get("severity", "")})

    graph_path = Path(out_dir) / "relation_graph.json"
    graph_path.write_text(json.dumps(graph_json, ensure_ascii=False, indent=2), encoding="utf-8")

    html_path = Path(out_dir) / "relation_graph.html"
    html_path.write_text(
        "<!doctype html><html><head><meta charset='UTF-8'><title>AI Agent Relation Graph</title></head>"
        "<body><h2>AI Agent Relation Graph (JSON based)</h2><p>可用 Gephi/Cytoscape/前端图组件加载 relation_graph.json。</p>"
        f"<pre>{json.dumps(graph_json, ensure_ascii=False, indent=2)[:200000]}</pre></body></html>",
        encoding="utf-8"
    )

    return str(html_path), str(graph_path)


def write_reports(out_dir, summary, process_rows, service_rows, llm_records, mcp_records, skill_records, script_records, sbom_files, vulns):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    html_path = out / "audit_report.html"
    html = [
        "<html><head><meta charset='utf-8'><title>AI Agent Audit Report</title></head><body>",
        "<h1>AI Agent Audit Report</h1>",
        f"<p>Generated: {datetime.now().isoformat()}</p>",
        "<h2>Summary</h2><ul>"
    ]
    for k, v in summary.items():
        html.append(f"<li><b>{k}</b>: {v}</li>")
    html.append("</ul>")

    def tbl(title, rows):
        html.append(f"<h2>{title}</h2>")
        if not rows:
            html.append("<p><i>None</i></p>")
            return
        cols = sorted({c for r in rows for c in r.keys()})
        html.append("<table border='1' cellspacing='0' cellpadding='4'>")
        html.append("<tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>")
        for r in rows:
            html.append("<tr>" + "".join(f"<td>{str(r.get(c, ''))}</td>" for c in cols) + "</tr>")
        html.append("</table>")

    tbl("Detected LLM Configs", llm_records)
    tbl("Detected MCP Configs", mcp_records)
    tbl("Detected Skills", skill_records)
    tbl("Detected Executable Scripts", script_records)
    tbl("Vulnerability Findings", vulns)

    html.extend([
        "<h2>Process Hits</h2><pre>",
        "\n".join(process_rows[:500]),
        "</pre><h2>Service Hits</h2><pre>",
        "\n".join(service_rows[:500]),
        "</pre><h2>SBOM Files</h2><ul>"
    ])
    for s in sbom_files:
        html.append(f"<li>{s}</li>")
    html.append("</ul></body></html>")
    html_path.write_text("\n".join(html), encoding="utf-8")

    xlsx_path = out / "audit_report.xlsx"
    if pd is not None:
        with pd.ExcelWriter(xlsx_path, engine="xlsxwriter") as writer:
            pd.DataFrame([summary]).to_excel(writer, sheet_name="summary", index=False)
            pd.DataFrame({"process_hits": process_rows}).to_excel(writer, sheet_name="processes", index=False)
            pd.DataFrame({"service_hits": service_rows}).to_excel(writer, sheet_name="services", index=False)
            pd.DataFrame(llm_records).to_excel(writer, sheet_name="llm_configs", index=False)
            pd.DataFrame(mcp_records).to_excel(writer, sheet_name="mcp_configs", index=False)
            pd.DataFrame(skill_records).to_excel(writer, sheet_name="skills", index=False)
            pd.DataFrame(script_records).to_excel(writer, sheet_name="scripts", index=False)
            pd.DataFrame([{"sbom_file": s} for s in sbom_files]).to_excel(writer, sheet_name="sbom_files", index=False)
            pd.DataFrame(vulns).to_excel(writer, sheet_name="vulns", index=False)

    return str(html_path), str(xlsx_path if xlsx_path.exists() else "")


def main():
    parser = argparse.ArgumentParser(description="AI Agent local deployment audit + SBOM + CVE analysis")
    parser.add_argument("--search-path", action="append", default=[], help="additional search path(s)")
    parser.add_argument("--depth", type=int, default=4, help="directory scan depth")
    parser.add_argument("--output", default="./aiagent_audit_output", help="output directory")
    args = parser.parse_args()

    global COMMON_SEARCH_PATHS
    if args.search_path:
        COMMON_SEARCH_PATHS.extend(args.search_path)

    Path(args.output).mkdir(parents=True, exist_ok=True)

    process_rows = discover_processes()
    service_rows = discover_systemd_services()
    target_dirs = discover_candidate_dirs(depth=args.depth)

    llm_records, mcp_records, skill_records, script_records = parse_configs(target_dirs)
    sbom_files, sbom_status = generate_sbom(target_dirs, args.output)
    vulns, vuln_status = scan_vulns_from_sbom(sbom_files, args.output)
    graph_html, graph_json = build_graph_html(target_dirs, llm_records, mcp_records, skill_records, script_records, vulns, args.output)

    summary = {
        "target_dirs": len(target_dirs),
        "process_hits": len(process_rows),
        "service_hits": len(service_rows),
        "llm_configs": len(llm_records),
        "mcp_configs": len(mcp_records),
        "skills": len(skill_records),
        "scripts": len(script_records),
        "sbom_files": len(sbom_files),
        "vuln_findings": len(vulns),
        "sbom_status": sbom_status,
        "vuln_status": vuln_status,
        "graph_html": graph_html,
        "graph_json": graph_json,
    }

    html_report, xlsx_report = write_reports(
        args.output, summary, process_rows, service_rows,
        llm_records, mcp_records, skill_records, script_records,
        sbom_files, vulns
    )

    print(json.dumps({
        "ok": True,
        "output_dir": str(Path(args.output).resolve()),
        "html_report": html_report,
        "xlsx_report": xlsx_report,
        "graph_html": graph_html,
        "graph_json": graph_json,
        "summary": summary,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
