#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
OUT_DIR="./aiagent_audit_output"
DEPTH=4
SEARCH_PATHS=(/opt /srv /usr/local /home /root /etc)
EXTRA_SEARCH=()

AGENT_RE='openclaw|opencode|aiagent|agent|autogen|langchain|crewai|llama[_-]?index|mcp'
LLM_RE='openai_api_key|api_key|base_url|azure_openai|model|models|llm|provider'
MCP_RE='mcp|mcp_servers|tool_servers|tools|servers'
HIGH_RISK_RE='remote code execution|\brce\b|command injection|shell injection|privilege escalation|local privilege escalation|arbitrary command|os command injection'

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]
  -o, --output DIR         Output directory (default: ./aiagent_audit_output)
  -d, --depth N            Discovery max depth (default: 4)
  -s, --search-path PATH   Extra search path (repeatable)
  -h, --help               Show help
EOF
}

log() { printf '[%s] %s\n' "$(date +'%F %T')" "$*"; }
warn() { printf '[%s] WARN: %s\n' "$(date +'%F %T')" "$*" >&2; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

escape_csv() {
  local s="$1"
  s=${s//\"/\"\"}
  printf '"%s"' "$s"
}

append_csv() {
  local f="$1"; shift
  local first=1 col
  {
    for col in "$@"; do
      if [[ $first -eq 1 ]]; then first=0; else printf ','; fi
      escape_csv "$col"
    done
    printf '\n'
  } >> "$f"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output) OUT_DIR="$2"; shift 2 ;;
      -d|--depth) DEPTH="$2"; shift 2 ;;
      -s|--search-path) EXTRA_SEARCH+=("$2"); shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) warn "Unknown arg: $1"; usage; exit 1 ;;
    esac
  done
}

init_output() {
  mkdir -p "$OUT_DIR"
  : > "$OUT_DIR/process_hits.txt"
  : > "$OUT_DIR/service_hits.txt"
  : > "$OUT_DIR/candidate_dirs.txt"
  : > "$OUT_DIR/sbom_files.txt"

  printf 'path,urls,ip_port,hints\n' > "$OUT_DIR/llm_configs.csv"
  printf 'path,urls,hints\n' > "$OUT_DIR/mcp_configs.csv"
  printf 'path,type,detail\n' > "$OUT_DIR/skills.csv"
  printf 'path,ext,executable,shebang\n' > "$OUT_DIR/scripts.csv"
  printf 'source_sbom,component,version,cve,severity,fix_versions,high_risk_focus,description\n' > "$OUT_DIR/vulns.csv"
}

discover_processes() {
  ps aux | awk 'NR>1' | grep -Ei "$AGENT_RE" > "$OUT_DIR/process_hits.txt" || true
}

discover_services() {
  if has_cmd systemctl; then
    systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -Ei "$AGENT_RE" > "$OUT_DIR/service_hits.txt" || true
  fi
}

discover_candidates() {
  local all=("${SEARCH_PATHS[@]}" "${EXTRA_SEARCH[@]}" "$(pwd)")
  local base
  for base in "${all[@]}"; do
    [[ -d "$base" ]] || continue
    find "$base" -maxdepth "$DEPTH" -type d 2>/dev/null | grep -Ei "$AGENT_RE" >> "$OUT_DIR/candidate_dirs.txt" || true
  done
  sort -u "$OUT_DIR/candidate_dirs.txt" -o "$OUT_DIR/candidate_dirs.txt"
}

scan_one_dir() {
  local d="$1"

  find "$d" -type d -iname '*skill*' 2>/dev/null | while IFS= read -r p; do
    append_csv "$OUT_DIR/skills.csv" "$p" "skill_dir" "directory name contains skill"
  done

  find "$d" -type f 2>/dev/null | while IFS= read -r f; do
    local bn ext shebang exec="false"
    bn="$(basename "$f")"
    ext="${f##*.}"; [[ "$f" == *.* ]] || ext="no_ext"
    [[ -x "$f" ]] && exec="true"

    if [[ "$bn" == "SKILL.md" ]] || [[ "$bn" =~ [Ss]kill ]]; then
      append_csv "$OUT_DIR/skills.csv" "$f" "skill_file" "skill marker file"
    fi

    if [[ "$f" =~ \.(sh|py|js|ts|bash)$ ]] || [[ "$exec" == "true" ]]; then
      shebang="$(head -n 1 "$f" 2>/dev/null || true)"
      [[ "$shebang" =~ ^#! ]] || shebang=""
      append_csv "$OUT_DIR/scripts.csv" "$f" "$ext" "$exec" "$shebang"
    fi

    if [[ "$f" =~ \.(ya?ml|json|toml|ini|conf|env|md)$ ]]; then
      local content urls ips hints m_urls m_hints
      content="$(head -c 1048576 "$f" 2>/dev/null || true)"
      [[ -n "$content" ]] || continue

      if printf '%s' "$content" | grep -Eiq "$LLM_RE"; then
        urls="$(printf '%s' "$content" | grep -Eo 'https?://[^[:space:]"<>]+' | head -n 10 | paste -sd ';' - || true)"
        ips="$(printf '%s' "$content" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+' | head -n 10 | paste -sd ';' - || true)"
        hints="$(printf '%s' "$content" | grep -Eio "$LLM_RE" | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd ';' - || true)"
        append_csv "$OUT_DIR/llm_configs.csv" "$f" "$urls" "$ips" "$hints"
      fi

      if printf '%s' "$content" | grep -Eiq "$MCP_RE"; then
        m_urls="$(printf '%s' "$content" | grep -Eo 'https?://[^[:space:]"<>]+' | head -n 10 | paste -sd ';' - || true)"
        m_hints="$(printf '%s' "$content" | grep -Eio "$MCP_RE" | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd ';' - || true)"
        append_csv "$OUT_DIR/mcp_configs.csv" "$f" "$m_urls" "$m_hints"
      fi
    fi
  done
}

scan_candidates() {
  while IFS= read -r d; do
    [[ -d "$d" ]] || continue
    scan_one_dir "$d"
  done < "$OUT_DIR/candidate_dirs.txt"

  local f tmp
  for f in llm_configs.csv mcp_configs.csv skills.csv scripts.csv; do
    tmp="$OUT_DIR/.tmp_$f"
    { head -n 1 "$OUT_DIR/$f"; tail -n +2 "$OUT_DIR/$f" | sort -u; } > "$tmp"
    mv "$tmp" "$OUT_DIR/$f"
  done
}

generate_sbom() {
  has_cmd syft || { warn "syft missing; skip SBOM"; return 0; }
  while IFS= read -r d; do
    [[ -d "$d" ]] || continue
    local name sbom
    name="$(printf '%s' "$d" | sed 's#^/##; s#[^a-zA-Z0-9._-]#_#g')"
    [[ -n "$name" ]] || name="root"
    sbom="$OUT_DIR/sbom_${name}.cyclonedx.json"
    if syft "dir:$d" -o cyclonedx-json > "$sbom" 2>"$OUT_DIR/sbom_${name}.error.txt"; then
      printf '%s\n' "$sbom" >> "$OUT_DIR/sbom_files.txt"
    fi
  done < "$OUT_DIR/candidate_dirs.txt"
}

scan_vulns() {
  [[ -s "$OUT_DIR/sbom_files.txt" ]] || { warn "no sbom files"; return 0; }

  if has_cmd grype; then
    while IFS= read -r sbom; do
      [[ -f "$sbom" ]] || continue
      local out_json
      out_json="$OUT_DIR/$(basename "${sbom%.json}").grype.json"
      grype "sbom:$sbom" -o json > "$out_json" 2>/dev/null || continue
      if has_cmd jq; then
        jq -r '.matches[]? | [
          $sbom,
          (.artifact.name // ""),
          (.artifact.version // ""),
          (.vulnerability.id // ""),
          (.vulnerability.severity // ""),
          ((.vulnerability.fix.versions // []) | join(";")),
          ((.vulnerability.description // "") | ascii_downcase),
          (.vulnerability.description // "")
        ] | @tsv' --arg sbom "$sbom" "$out_json" | while IFS=$'\t' read -r a b c d e f desc_low desc; do
          local risk=""
          printf '%s' "$desc_low" | grep -Eiq "$HIGH_RISK_RE" && risk="YES" || true
          append_csv "$OUT_DIR/vulns.csv" "$a" "$b" "$c" "$d" "$e" "$f" "$risk" "$desc"
        done
      fi
    done < "$OUT_DIR/sbom_files.txt"
  elif has_cmd osv-scanner; then
    while IFS= read -r sbom; do
      [[ -f "$sbom" ]] || continue
      local out_json
      out_json="$OUT_DIR/$(basename "${sbom%.json}").osv.json"
      osv-scanner scan --sbom="$sbom" --json > "$out_json" 2>/dev/null || continue
      if has_cmd jq; then
        jq -r '.results[]? as $r | ($r.packages // [])[]? as $p | ($r.vulnerabilities // [])[]? | [
          $sbom,
          ($p.name // ""),
          ($p.version // ""),
          (.id // ""),
          (.severity // ""),
          "",
          (((.summary // "") + " " + (.details // "")) | ascii_downcase),
          ((.summary // "") + " " + (.details // ""))
        ] | @tsv' --arg sbom "$sbom" "$out_json" | while IFS=$'\t' read -r a b c d e f desc_low desc; do
          local risk=""
          printf '%s' "$desc_low" | grep -Eiq "$HIGH_RISK_RE" && risk="YES" || true
          append_csv "$OUT_DIR/vulns.csv" "$a" "$b" "$c" "$d" "$e" "$f" "$risk" "$desc"
        done
      fi
    done < "$OUT_DIR/sbom_files.txt"
  else
    warn "grype/osv-scanner missing; skip vulnerability scan"
  fi

  local tmp="$OUT_DIR/.tmp_vulns.csv"
  { head -n 1 "$OUT_DIR/vulns.csv"; tail -n +2 "$OUT_DIR/vulns.csv" | sort -u; } > "$tmp"
  mv "$tmp" "$OUT_DIR/vulns.csv"
}

build_graph() {
  # Minimal graph artifacts for correlation consumers
  printf '{"nodes":[],"edges":[]}\n' > "$OUT_DIR/relation_graph.json"
  {
    echo 'digraph G {'
    echo '  rankdir=LR;'
    echo '}'
  } > "$OUT_DIR/relation_graph.dot"
  cat > "$OUT_DIR/relation_graph.html" <<EOF
<!doctype html><html><head><meta charset="utf-8"><title>AI Agent Relation Graph</title></head>
<body><h2>Relation Graph Artifacts</h2><ul>
<li>relation_graph.json</li><li>relation_graph.dot</li>
</ul></body></html>
EOF
}

build_html() {
  local cands llm mcp sk sc sb vf ph sh
  cands=$(wc -l < "$OUT_DIR/candidate_dirs.txt" | tr -d ' ')
  llm=$(( $(wc -l < "$OUT_DIR/llm_configs.csv") - 1 ))
  mcp=$(( $(wc -l < "$OUT_DIR/mcp_configs.csv") - 1 ))
  sk=$(( $(wc -l < "$OUT_DIR/skills.csv") - 1 ))
  sc=$(( $(wc -l < "$OUT_DIR/scripts.csv") - 1 ))
  vf=$(( $(wc -l < "$OUT_DIR/vulns.csv") - 1 ))
  sb=$(wc -l < "$OUT_DIR/sbom_files.txt" | tr -d ' ')
  ph=$(wc -l < "$OUT_DIR/process_hits.txt" | tr -d ' ')
  sh=$(wc -l < "$OUT_DIR/service_hits.txt" | tr -d ' ')

  cat > "$OUT_DIR/audit_report.html" <<EOF
<!doctype html>
<html><head><meta charset="utf-8"><title>AI Agent Audit Report</title></head>
<body>
<h1>AI Agent Audit Report (Shell)</h1>
<p>Generated: $(date +'%F %T')</p>
<ul>
<li>candidate_dirs: $cands</li>
<li>process_hits: $ph</li>
<li>service_hits: $sh</li>
<li>llm_configs: $llm</li>
<li>mcp_configs: $mcp</li>
<li>skills: $sk</li>
<li>scripts: $sc</li>
<li>sbom_files: $sb</li>
<li>vuln_findings: $vf</li>
</ul>
<h2>High-risk vuln rows</h2>
<pre>$(awk -F',' 'NR==1 || $7 ~ /YES/ {print}' "$OUT_DIR/vulns.csv")</pre>
</body></html>
EOF

  cat > "$OUT_DIR/summary.json" <<EOF
{
  "ok": true,
  "output_dir": "$(cd "$OUT_DIR" && pwd)",
  "candidate_dirs": $cands,
  "process_hits": $ph,
  "service_hits": $sh,
  "llm_configs": $llm,
  "mcp_configs": $mcp,
  "skills": $sk,
  "scripts": $sc,
  "sbom_files": $sb,
  "vuln_findings": $vf,
  "html_report": "$OUT_DIR/audit_report.html",
  "graph_html": "$OUT_DIR/relation_graph.html"
}
EOF
}

main() {
  parse_args "$@"
  log "Initializing output: $OUT_DIR"
  init_output
  log "Discovering processes/services/candidates"
  discover_processes
  discover_services
  discover_candidates
  log "Scanning candidate directories"
  scan_candidates
  log "SBOM + vulnerability scan"
  generate_sbom
  scan_vulns
  log "Building reports"
  build_graph
  build_html
  log "Done"
  cat "$OUT_DIR/summary.json"
}

main "$@"
