#!/bin/bash
#
# AI Agent Security Audit Script - Pure Bash Version
# 功能：扫描本地 AI Agent 程序，分析配置，检查漏洞，生成报告
# 纯 Bash 脚本实现，兼容 Linux 和 macOS (bash 3.2+)
#
# 作者：AI Security Auditor
# 版本：v2.5.3 (修复 macOS grep -oP 兼容性问题)
#

set -o pipefail

# 捕获错误但不退出
trap '' ERR

# ============================================================================
# 检测操作系统
# ============================================================================
OS_TYPE="linux"
if [[ "$(uname)" == "Darwin" ]]; then
    OS_TYPE="macos"
fi

# ============================================================================
# 配置和常量
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/audit_output_$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${OUTPUT_DIR}/security_report.html"
GRAPH_FILE="${OUTPUT_DIR}/knowledge_graph.html"
SBOM_FILE="${OUTPUT_DIR}/sbom.json"
VULN_FILE="${OUTPUT_DIR}/vulnerabilities.json"
AGENTS_FILE="${OUTPUT_DIR}/agents.json"
SCRIPTS_FILE="${OUTPUT_DIR}/scripts.json"
SKILLS_FILE="${OUTPUT_DIR}/skills.json"
API_CONFIGS_FILE="${OUTPUT_DIR}/api_configs.json"
LOG_FILE="${OUTPUT_DIR}/audit.log"

# 全局变量：使用普通数组存储 agent 映射 (兼容 bash 3.2)
AGENT_ID_LIST=()      # 格式: "key:id"
AGENT_PATH_LIST=()    # 格式: "id:path"
AGENT_COUNTER=0

# 主机信息
HOST_NAME=""
HOST_IP=""

# 颜色输出
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================================
# 兼容性函数 (替代 grep -oP，支持 macOS)
# 说明：macOS 的 grep 不支持 -P (Perl 正则表达式)，使用 perl 替代
# ============================================================================

# 提取 JSON 字段值: "key": "value" -> value
# 用法: echo '{"name": "test"}' | json_extract_value "name"
json_extract_value() {
    local key="$1"
    perl -nle "print \$1 if /\"${key}\"\\s*:\\s*\"([^\"]+)\"/" 2>/dev/null | head -1
}

# 提取 JSON key 名称: "keyname": { -> keyname
# 用法: echo '{"server1": {' | json_extract_key
json_extract_key() {
    perl -nle 'print $1 if /"([a-zA-Z0-9_-]+)"\s*:/' 2>/dev/null | head -1
}

# 提取 JSON 数字值: "count": 123 -> 123
# 用法: echo '{"count": 123}' | json_extract_number "count"
json_extract_number() {
    local key="$1"
    perl -nle "print \$1 if /\"${key}\"\\s*:\\s*([0-9]+)/" 2>/dev/null | head -1
}

# 提取 JSON 数组内容: "args": ["a", "b"] -> "a", "b"
# 用法: echo '{"args": ["a", "b"]}' | json_extract_array "args"
json_extract_array() {
    local key="$1"
    perl -nle "print \$1 if /\"${key}\"\\s*:\\s*\\[([^\\]]*)\\]/" 2>/dev/null | head -1
}

# 提取 JSON 布尔值: "enabled": true -> true
# 用法: echo '{"enabled": true}' | json_extract_bool "enabled"
json_extract_bool() {
    local key="$1"
    perl -nle "print \$1 if /\"${key}\"\\s*:\\s*(true|false)/" 2>/dev/null | head -1
}

# 通用正则提取 (替代 grep -oP)
# 用法: echo 'text' | perl_extract 'pattern_with_capture'
perl_extract() {
    local pattern="$1"
    perl -nle "print \$1 if /${pattern}/" 2>/dev/null | head -1
}

# ============================================================================
# 工具函数 (兼容 bash 3.2)
# ============================================================================

# 获取 agent_id (替代关联数组)
get_agent_id() {
    local key="$1"
    local entry
    for entry in "${AGENT_ID_LIST[@]}"; do
        if [[ "${entry%%:*}" == "${key}" ]]; then
            echo "${entry#*:}"
            return 0
        fi
    done
    return 1
}

# 设置 agent_id (替代关联数组)
set_agent_id() {
    local key="$1"
    local id="$2"
    # 先删除旧的
    local new_list=()
    local entry
    for entry in "${AGENT_ID_LIST[@]}"; do
        if [[ "${entry%%:*}" != "${key}" ]]; then
            new_list+=("$entry")
        fi
    done
    new_list+=("${key}:${id}")
    AGENT_ID_LIST=("${new_list[@]}")
}

# 获取 agent_path (替代关联数组)
get_agent_path() {
    local id="$1"
    local entry
    for entry in "${AGENT_PATH_LIST[@]}"; do
        if [[ "${entry%%:*}" == "${id}" ]]; then
            echo "${entry#*:}"
            return 0
        fi
    done
    return 1
}

# 设置 agent_path (替代关联数组)
set_agent_path() {
    local id="$1"
    local path="$2"
    local new_list=()
    local entry
    for entry in "${AGENT_PATH_LIST[@]}"; do
        if [[ "${entry%%:*}" != "${id}" ]]; then
            new_list+=("$entry")
        fi
    done
    new_list+=("${id}:${path}")
    AGENT_PATH_LIST=("${new_list[@]}")
}

# 获取所有 agent keys
get_all_agent_keys() {
    local entry
    for entry in "${AGENT_ID_LIST[@]}"; do
        echo "${entry%%:*}"
    done
}

# 获取所有 agent IDs
get_all_agent_ids() {
    local entry
    for entry in "${AGENT_ID_LIST[@]}"; do
        echo "${entry#*:}"
    done
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
    case "${level}" in
        "ERROR") echo -e "${RED}[${level}]${NC} ${message}" ;;
        "WARN")  echo -e "${YELLOW}[${level}]${NC} ${message}" ;;
        "INFO")  echo -e "${GREEN}[${level}]${NC} ${message}" ;;
        *)       echo -e "${BLUE}[${level}]${NC} ${message}" ;;
    esac
}

create_output_dir() {
    mkdir -p "${OUTPUT_DIR}"
    touch "${LOG_FILE}"
    log "INFO" "创建输出目录：${OUTPUT_DIR}"
}

# 获取文件大小（兼容 Linux 和 macOS）
get_file_size() {
    local file="$1"
    if [[ "${OS_TYPE}" == "macos" ]]; then
        stat -f%z "${file}" 2>/dev/null || echo "0"
    else
        stat -c%s "${file}" 2>/dev/null || echo "0"
    fi
}

# 采集主机信息
collect_host_info() {
    log "INFO" "采集主机信息..."

    # 获取主机名
    HOST_NAME=$(hostname 2>/dev/null || echo "unknown")

    # 获取主机 IP 地址
    if [[ "${OS_TYPE}" == "macos" ]]; then
        # macOS: 使用 ifconfig 获取 IP
        HOST_IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' || echo "unknown")
    else
        # Linux: 使用 hostname -I 或 ip addr
        HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
        if [[ -z "${HOST_IP}" || "${HOST_IP}" == "unknown" ]]; then
            HOST_IP=$(ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d'/' -f1 || echo "unknown")
        fi
    fi

    log "INFO" "操作系统：${OS_TYPE}, 主机名：${HOST_NAME}, IP: ${HOST_IP}"
}

# JSON 转义函数
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo -n "$str"
}

# 根据配置文件路径获取受影响的 Agent (兼容 bash 3.2)
get_affected_agents_for_mcp() {
    local mcp_file="$1"
    local affected_agents="["
    local first=true
    local key id

    # 检查文件路径中包含的 Agent 标识
    if [[ "${mcp_file}" == *".claude"* ]]; then
        for entry in "${AGENT_ID_LIST[@]}"; do
            key="${entry%%:*}"
            id="${entry#*:}"
            if [[ "${key}" == "claude"* ]]; then
                [[ "${first}" == "true" ]] && first=false || affected_agents+=","
                affected_agents+="\"${id}\""
            fi
        done
    fi
    if [[ "${mcp_file}" == *".cursor"* ]]; then
        for entry in "${AGENT_ID_LIST[@]}"; do
            key="${entry%%:*}"
            id="${entry#*:}"
            if [[ "${key}" == *"cursor"* ]]; then
                [[ "${first}" == "true" ]] && first=false || affected_agents+=","
                affected_agents+="\"${id}\""
            fi
        done
    fi
    if [[ "${mcp_file}" == *".openclaw"* ]] || [[ "${mcp_file}" == *"openclaw"* ]]; then
        for entry in "${AGENT_ID_LIST[@]}"; do
            key="${entry%%:*}"
            id="${entry#*:}"
            if [[ "${key}" == *"openclaw"* ]]; then
                [[ "${first}" == "true" ]] && first=false || affected_agents+=","
                affected_agents+="\"${id}\""
            fi
        done
    fi
    if [[ "${mcp_file}" == *".opencode"* ]] || [[ "${mcp_file}" == *"opencode"* ]]; then
        for entry in "${AGENT_ID_LIST[@]}"; do
            key="${entry%%:*}"
            id="${entry#*:}"
            if [[ "${key}" == *"opencode"* ]]; then
                [[ "${first}" == "true" ]] && first=false || affected_agents+=","
                affected_agents+="\"${id}\""
            fi
        done
    fi
    if [[ "${mcp_file}" == *"mcporter"* ]]; then
        # Mcporter 影响所有 Agent
        for entry in "${AGENT_ID_LIST[@]}"; do
            id="${entry#*:}"
            [[ "${first}" == "true" ]] && first=false || affected_agents+=","
            affected_agents+="\"${id}\""
        done
    fi

    affected_agents+="]"
    echo "${affected_agents}"
}

# ============================================================================
# 发现 AI Agent 程序
# ============================================================================
discover_ai_agents() {
    log "INFO" "===== 开始扫描 AI Agent 程序 ====="

    local agents_json="["
    local first=true
    local count=0
    AGENT_COUNTER=0

    # 检查命令行工具
    for cmd in openclaw opencode claude claude-code cline aider ollama llama zed cursor nanobot; do
        if command -v "${cmd}" &>/dev/null; then
            local path=$(which "${cmd}" 2>/dev/null)
            local agent_id=$(printf "A%03d" ${AGENT_COUNTER})
            ((AGENT_COUNTER++))
            [[ "${first}" == "true" ]] && first=false || agents_json+=","
            agents_json+="{\"agent_id\":\"${agent_id}\",\"name\":\"${cmd}\",\"type\":\"command\",\"path\":\"${path}\",\"hostname\":\"${HOST_NAME}\"}"
            set_agent_id "${cmd}" "${agent_id}"
            set_agent_path "${agent_id}" "${path}"
            ((count++))
            log "INFO" "发现命令：${cmd} -> ${path} (ID: ${agent_id})"
        fi
    done

    # 搜索目录 (兼容 Linux 和 macOS)
    local search_dirs=("/root" "/opt" "/home" "/Users")
    for base in "${search_dirs[@]}"; do
        if [[ -d "${base}" ]]; then
            for pattern in ".openclaw" ".opencode" ".claude" ".nanobot"; do
                while IFS= read -r dir; do
                    [[ -z "${dir}" ]] && continue
                    local agent_name="${pattern#.}"
                    local agent_id=$(printf "A%03d" ${AGENT_COUNTER})
                    ((AGENT_COUNTER++))
                    [[ "${first}" == "true" ]] && first=false || agents_json+=","
                    agents_json+="{\"agent_id\":\"${agent_id}\",\"name\":\"${agent_name}\",\"type\":\"directory\",\"path\":\"${dir}\",\"hostname\":\"${HOST_NAME}\"}"
                    set_agent_id "${agent_name}:${dir}" "${agent_id}"
                    set_agent_path "${agent_id}" "${dir}"
                    ((count++))
                    log "INFO" "发现目录：${agent_name} -> ${dir} (ID: ${agent_id})"
                done < <(find "${base}" -maxdepth 3 -type d -name "*${pattern}*" 2>/dev/null)
            done
        fi
    done

    # 检查 NPM 全局包
    if command -v npm &>/dev/null; then
        for pkg in claude claude-code openclaw opencode nanobot; do
            if npm list -g --depth=0 2>/dev/null | grep -q "${pkg}"; then
                local npm_root=$(npm root -g 2>/dev/null)
                local agent_id=$(printf "A%03d" ${AGENT_COUNTER})
                ((AGENT_COUNTER++))
                [[ "${first}" == "true" ]] && first=false || agents_json+=","
                agents_json+="{\"agent_id\":\"${agent_id}\",\"name\":\"${pkg}\",\"type\":\"npm-global\",\"path\":\"${npm_root}\",\"hostname\":\"${HOST_NAME}\"}"
                set_agent_id "npm:${pkg}" "${agent_id}"
                set_agent_path "${agent_id}" "${npm_root}"
                ((count++))
                log "INFO" "发现 NPM 全局包：${pkg} (ID: ${agent_id})"
            fi
        done
    fi

    # 检查 Python 包
    if command -v pip3 &>/dev/null; then
        for pkg in ollama llama aider; do
            if pip3 list 2>/dev/null | grep -qi "${pkg}"; then
                local loc=$(pip3 show "${pkg}" 2>/dev/null | grep Location | cut -d' ' -f2 || echo "unknown")
                local agent_id=$(printf "A%03d" ${AGENT_COUNTER})
                ((AGENT_COUNTER++))
                [[ "${first}" == "true" ]] && first=false || agents_json+=","
                agents_json+="{\"agent_id\":\"${agent_id}\",\"name\":\"${pkg}\",\"type\":\"python-package\",\"path\":\"${loc}\",\"hostname\":\"${HOST_NAME}\"}"
                set_agent_id "pip:${pkg}" "${agent_id}"
                set_agent_path "${agent_id}" "${loc}"
                ((count++))
                log "INFO" "发现 Python 包：${pkg} (ID: ${agent_id})"
            fi
        done
    fi

    agents_json+="]"
    echo "${agents_json}" > "${AGENTS_FILE}"
    log "INFO" "共发现 ${count} 个 AI Agent"
}

# ============================================================================
# 提取 MCP 服务器配置 (增强版 - 全系统扫描)
# ============================================================================
extract_mcp_config() {
    log "INFO" "===== 提取 MCP 服务器配置 ====="

    local mcp_servers_json="["
    local mcp_files_json="["
    local first_server=true
    local first_file=true
    local server_count=0
    local file_count=0

    # 用于收集所有 MCP 配置文件的临时文件
    local temp_mcp_files=$(mktemp)
    local temp_unique_files=$(mktemp)

    # 1. 搜索标准 MCP 配置文件
    log "INFO" "搜索 MCP 配置文件..."
    local mcp_search_paths=(
        "${HOME}/.claude/mcp.json"
        "${HOME}/.claude/mcp_config.json"
        "${HOME}/.config/claude/mcp.json"
        "${HOME}/.cursor/mcp.json"
        "${HOME}/.cursor/mcp_config.json"
        "${HOME}/.vscode/mcp.json"
        "${HOME}/.codeium/windsurf/mcp.json"
        "${HOME}/.codeium/windsurf/mcp_config.json"
        "/opt/*/mcp.json"
        "/usr/local/*/mcp.json"
    )

    for mcp_file in "${mcp_search_paths[@]}"; do
        for expanded_file in ${mcp_file}; do
            if [[ -f "${expanded_file}" ]]; then
                echo "${expanded_file}" >> "${temp_mcp_files}"
            fi
        done
    done

    # 2. 全系统搜索 MCP 相关文件 (使用 find + grep)
    log "INFO" "全系统扫描 MCP 配置文件 (find / | grep mcp)..."
    find / -type f -name "*.json" 2>/dev/null | grep -iE "mcp" >> "${temp_mcp_files}" || true

    # 3. 搜索插件 .mcp.json 文件
    log "INFO" "搜索插件 MCP 配置 (.mcp.json)..."
    find "${HOME}" -name ".mcp.json" -type f 2>/dev/null >> "${temp_mcp_files}" || true
    find /opt -name ".mcp.json" -type f 2>/dev/null >> "${temp_mcp_files}" || true
    find /usr/local -name ".mcp.json" -type f 2>/dev/null >> "${temp_mcp_files}" || true

    # 4. 搜索 Mcporter 配置
    if [[ -f "${HOME}/.mcporter/mcporter.json" ]]; then
        echo "${HOME}/.mcporter/mcporter.json" >> "${temp_mcp_files}"
    fi

    # 5. 去重并处理文件
    log "INFO" "处理配置文件 (去重)..."
    sort -u "${temp_mcp_files}" > "${temp_unique_files}" 2>/dev/null

    while IFS= read -r mcp_file; do
        [[ -z "${mcp_file}" ]] && continue
        [[ ! -f "${mcp_file}" ]] && continue

        # 检查文件大小（跳过大于 1MB 的文件）
        local file_size=$(get_file_size "${mcp_file}")
        if [[ "${file_size}" -gt 1048576 ]]; then
            log "WARN" "跳过大文件 (>1MB): ${mcp_file}"
            continue
        fi

        # 检查文件是否包含 MCP 相关内容
        if ! grep -qiE '"mcp|"servers|mcpServers' "${mcp_file}" 2>/dev/null; then
            continue
        fi

        log "INFO" "找到 MCP 配置文件：${mcp_file}"
        [[ "${first_file}" == "true" ]] && first_file=false || mcp_files_json+=","
        mcp_files_json+="{\"path\":\"${mcp_file}\",\"type\":\"mcp_config\"}"
        ((file_count++))

        # 根据文件类型解析
        local basename_file=$(basename "${mcp_file}")
        # 获取受影响的 Agent
        local affected_agents=$(get_affected_agents_for_mcp "${mcp_file}")

        if [[ "${basename_file}" == "mcporter.json" ]]; then
            # Mcporter 格式 - 统一处理，支持 3 字段和 6 字段
            while IFS='|' read -r name type url cmd args env; do
                [[ -z "${name}" ]] && continue
                [[ "${first_server}" == "true" ]] && first_server=false || mcp_servers_json+=","
                # 如果有 cmd 则是 stdio 类型，否则是 remote/http 类型
                if [[ -n "${cmd}" ]]; then
                    mcp_servers_json+="{\"name\":\"${name}\",\"type\":\"${type}\",\"url\":\"${url}\",\"command\":\"${cmd}\",\"args\":\"${args}\",\"env\":\"${env}\",\"source\":\"${mcp_file}\",\"affected_agents\":${affected_agents}}"
                else
                    mcp_servers_json+="{\"name\":\"${name}\",\"type\":\"${type}\",\"url\":\"${url}\",\"source\":\"${mcp_file}\",\"affected_agents\":${affected_agents}}"
                fi
                ((server_count++))
                log "INFO" "发现 MCP 服务器：${name} (${type}) - 影响 Agent: ${affected_agents}"
            done < <(parse_mcporter_file "${mcp_file}")
        elif [[ "${basename_file}" == ".mcp.json" ]]; then
            # 插件 MCP 格式 - 统一处理，支持 4 字段和 6 字段
            while IFS='|' read -r name type url cmd args env; do
                [[ -z "${name}" ]] && continue
                [[ "${first_server}" == "true" ]] && first_server=false || mcp_servers_json+=","
                # 如果有 cmd 则是 stdio 类型，否则是 remote/http 类型
                if [[ -n "${cmd}" ]]; then
                    mcp_servers_json+="{\"name\":\"${name}\",\"type\":\"${type}\",\"url\":\"${url}\",\"command\":\"${cmd}\",\"args\":\"${args}\",\"env\":\"${env}\",\"source\":\"${mcp_file}\",\"affected_agents\":${affected_agents}}"
                else
                    mcp_servers_json+="{\"name\":\"${name}\",\"type\":\"${type}\",\"url\":\"${url}\",\"source\":\"${mcp_file}\",\"affected_agents\":${affected_agents}}"
                fi
                ((server_count++))
                log "INFO" "发现 MCP 服务器：${name} (${type}) - 影响 Agent: ${affected_agents}"
            done < <(parse_plugin_mcp_file "${mcp_file}")
        else
            # 标准 MCP 格式 (mcpServers)
            while IFS='|' read -r name type url cmd args env; do
                [[ -z "${name}" ]] && continue
                [[ "${first_server}" == "true" ]] && first_server=false || mcp_servers_json+=","
                mcp_servers_json+="{\"name\":\"${name}\",\"type\":\"${type}\",\"url\":\"${url}\",\"command\":\"${cmd}\",\"args\":\"${args}\",\"env\":\"${env}\",\"source\":\"${mcp_file}\",\"affected_agents\":${affected_agents}}"
                ((server_count++))
                log "INFO" "发现 MCP 服务器：${name} (${type}) - 影响 Agent: ${affected_agents}"
            done < <(parse_mcp_file "${mcp_file}")
        fi
    done < "${temp_unique_files}"

    rm -f "${temp_mcp_files}" "${temp_unique_files}"

    # 6. 检查运行中的 MCP 进程
    log "INFO" "检查运行中的 MCP 进程..."
    local mcp_procs=$(ps aux 2>/dev/null | grep -iE 'mcp|model.*context' | grep -v grep || true)
    local running_mcp="["
    local first_proc=true
    if [[ -n "${mcp_procs}" ]]; then
        while IFS= read -r proc; do
            [[ -z "${proc}" ]] && continue
            local proc_cmd=$(echo "${proc}" | awk '{print $11}')
            [[ "${first_proc}" == "true" ]] && first_proc=false || running_mcp+=","
            running_mcp+="{\"command\":\"${proc_cmd}\"}"
        done <<< "${mcp_procs}"
    fi
    running_mcp+="]"

    mcp_files_json+="]"
    mcp_servers_json+="]"

    # 保存结果
    cat > "${OUTPUT_DIR}/mcp_servers.json" << EOF
{
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_servers": ${server_count},
  "config_files": ${file_count},
  "servers": ${mcp_servers_json}
}
EOF

    cat > "${OUTPUT_DIR}/mcp_files.json" << EOF
{
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_files": ${file_count},
  "files": ${mcp_files_json}
}
EOF

    cat > "${OUTPUT_DIR}/mcp_processes.json" << EOF
{
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "processes": ${running_mcp}
}
EOF

    log "INFO" "共发现 ${server_count} 个 MCP 服务器，${file_count} 个配置文件"
}

# 解析标准 MCP 配置文件 (mcpServers 格式)
parse_mcp_file() {
    local file="$1"
    [[ ! -f "${file}" ]] && return

    local in_mcp_servers=false
    local current_server=""
    local current_type=""
    local current_url=""
    local current_cmd=""
    local current_args=""
    local current_env=""

    while IFS= read -r line; do
        # 检查 mcpServers 块
        if echo "${line}" | grep -qE '"mcpServers"\s*:'; then
            in_mcp_servers=true
            continue
        fi

        if [[ "${in_mcp_servers}" == "true" ]]; then
            # 提取服务器名称
            if echo "${line}" | grep -qE '^\s*"[a-zA-Z0-9_-]+"\s*:\s*\{'; then
                current_server=$(echo "${line}" | json_extract_key)
                current_type=""
                current_url=""
                current_cmd=""
                current_args=""
                current_env=""
            fi

            # 提取 type
            if echo "${line}" | grep -qE '"type"\s*:'; then
                current_type=$(echo "${line}" | json_extract_value "type")
            fi

            # 提取 url
            if echo "${line}" | grep -qE '"(url|baseUrl)"\s*:'; then
                current_url=$(echo "${line}" | perl_extract '"(url|baseUrl)"\s*:\s*"([^"]+)"')
            fi

            # 提取 command
            if echo "${line}" | grep -qE '"command"\s*:'; then
                current_cmd=$(echo "${line}" | json_extract_value "command")
            fi

            # 提取 args
            if echo "${line}" | grep -qE '"args"\s*:'; then
                current_args=$(echo "${line}" | json_extract_array "args")
            fi

            # 提取 env
            if echo "${line}" | grep -qE '"env"\s*:'; then
                current_env="true"
            fi

            # 服务器块结束
            if echo "${line}" | grep -qE '^\s*\}'; then
                if [[ -n "${current_server}" ]]; then
                    [[ -z "${current_type}" ]] && current_type="stdio"
                    echo "${current_server}|${current_type}|${current_url}|${current_cmd}|${current_args}|${current_env}"
                fi
                current_server=""
            fi
        fi
    done < "${file}"
}

# 解析插件 MCP 配置 (.mcp.json 格式) - 支持两种格式
# 格式 1: {"mcpServers": {"server1": {...}, "server2": {...}}}
# 格式 2: {"server1": {...}, "server2": {...}} (顶层直接是服务器)
parse_plugin_mcp_file() {
    local file="$1"
    [[ ! -f "${file}" ]] && return

    local content=$(cat "${file}" 2>/dev/null)

    # 检查是否为 mcpServers 嵌套格式
    if echo "${content}" | grep -qE '"mcpServers"\s*:'; then
        # 格式 1: 委托给 parse_mcp_file 处理 mcpServers 结构
        parse_mcp_file "${file}"
        return
    fi

    # 格式 2: 顶层直接是服务器名称
    local current_name=""
    local current_type=""
    local current_url=""
    local current_oauth=""

    while IFS= read -r line; do
        # 提取服务器名称 (顶层 key)
        if echo "${line}" | grep -qE '^\s*"[a-zA-Z0-9_-]+"\s*:\s*\{'; then
            current_name=$(echo "${line}" | json_extract_key)
            current_type=""
            current_url=""
            current_oauth=""
        fi

        # 提取 type
        if echo "${line}" | grep -qE '"type"\s*:'; then
            current_type=$(echo "${line}" | json_extract_value "type")
        fi

        # 提取 url
        if echo "${line}" | grep -qE '"url"\s*:'; then
            current_url=$(echo "${line}" | json_extract_value "url")
        fi

        # 提取 oauth clientId
        if echo "${line}" | grep -qE '"clientId"\s*:'; then
            current_oauth=$(echo "${line}" | json_extract_value "clientId")
        fi

        # 服务器块结束
        if echo "${line}" | grep -qE '^\s*\}'; then
            if [[ -n "${current_name}" && -n "${current_type}" ]]; then
                echo "${current_name}|${current_type}|${current_url}|${current_oauth}"
            fi
            current_name=""
        fi
    done < "${file}"
}

# 解析 Mcporter 配置文件 - 支持两种格式
# 格式 1: {"mcpServers": {"server1": {...}}} (嵌套格式)
# 格式 2: {"server1": {...}} (顶层直接是服务器)
parse_mcporter_file() {
    local file="$1"
    [[ ! -f "${file}" ]] && return

    local content=$(cat "${file}" 2>/dev/null)

    # 检查是否为 mcpServers 嵌套格式
    if echo "${content}" | grep -qE '"mcpServers"\s*:'; then
        # 格式 1: 使用标准 MCP 解析器处理 mcpServers 结构
        parse_mcp_file "${file}"
        return
    fi

    # 格式 2: 顶层直接是服务器名称 - 逐行解析
    local current_name=""
    local current_type=""
    local current_url=""
    local in_block=false
    local brace_count=0

    while IFS= read -r line; do
        # 检测服务器名称 (顶层 key)
        if echo "${line}" | grep -qE '^\s*"[a-zA-Z0-9_-]+"\s*:\s*\{'; then
            current_name=$(echo "${line}" | json_extract_key)
            current_type=""
            current_url=""
            in_block=true
            brace_count=1
            continue
        fi

        if [[ "${in_block}" == "true" ]]; then
            # 计算括号嵌套
            local open_braces=$(echo "${line}" | grep -o '{' | wc -l)
            local close_braces=$(echo "${line}" | grep -o '}' | wc -l)
            brace_count=$((brace_count + open_braces - close_braces))

            # 提取 type
            if echo "${line}" | grep -qE '"type"\s*:'; then
                current_type=$(echo "${line}" | json_extract_value "type")
            fi

            # 提取 url
            if echo "${line}" | grep -qE '"url"\s*:'; then
                current_url=$(echo "${line}" | json_extract_value "url")
            fi

            # 块结束
            if [[ ${brace_count} -eq 0 ]]; then
                if [[ -n "${current_name}" && -n "${current_type}" ]]; then
                    echo "${current_name}|${current_type}|${current_url}"
                fi
                current_name=""
                in_block=false
            fi
        fi
    done < "${file}"
}

# ============================================================================
# 提取 Skills 列表 (增强版 - 关联 Agent)
# ============================================================================
# ============================================================================
# 提取 Skills 列表 (基于 SKILL.md 文件全盘扫描)
# ============================================================================
extract_skills() {
    log "INFO" "===== 提取 Skills 列表 (基于 SKILL.md) ====="

    local skills_json="["
    local first=true
    local count=0

    # 全盘搜索所有 SKILL.md 文件
    log "INFO" "全盘搜索 SKILL.md 文件..."

    while IFS= read -r skill_md_path; do
        [[ -z "${skill_md_path}" ]] && continue
        [[ ! -f "${skill_md_path}" ]] && continue

        # 从路径提取 skill 名称（SKILL.md 的父目录名）
        local skill_dir=$(dirname "${skill_md_path}")
        local skill_name=$(basename "${skill_dir}")

        # 跳过无效的 skill 名称
        [[ -z "${skill_name}" || "${skill_name}" == "." || "${skill_name}" == ".." ]] && continue

        # 从 SKILL.md 提取 skill 名称（优先使用 YAML frontmatter 中的 name 字段）
        local yaml_name=""
        if [[ -f "${skill_md_path}" ]]; then
            yaml_name=$(grep -m1 "^name:" "${skill_md_path}" 2>/dev/null | sed 's/^name:[[:space:]]*//' | tr -d '\r\n' | head -c 100)
        fi
        [[ -n "${yaml_name}" ]] && skill_name="${yaml_name}"

        # 确定所属 Agent（通过路径判断）
        local agent_name="unknown"
        local agent_id="A000"

        # 检查路径中的 agent 标识
        if [[ "${skill_md_path}" == *"/.claude/"* || "${skill_md_path}" == *"/claude/"* ]]; then
            agent_name="claude"
        elif [[ "${skill_md_path}" == *"/.openclaw/"* || "${skill_md_path}" == *"/openclaw/"* ]]; then
            agent_name="openclaw"
        elif [[ "${skill_md_path}" == *"/.opencode/"* || "${skill_md_path}" == *"/opencode/"* ]]; then
            agent_name="opencode"
        elif [[ "${skill_md_path}" == *"/hagent/"* ]]; then
            agent_name="hagent"
        elif [[ "${skill_md_path}" == *"/nanobot/"* ]]; then
            agent_name="nanobot"
        elif [[ "${skill_md_path}" == *"/aicode/"* ]]; then
            agent_name="aicode"
        fi

        # 从 AGENT_ID_LIST 获取 agent_id (兼容 bash 3.2)
        agent_id=""
        for entry in "${AGENT_ID_LIST[@]}"; do
            key="${entry%%:*}"
            if [[ "${key}" == *"${agent_name}"* ]]; then
                agent_id="${entry#*:}"
                break
            fi
        done

        [[ "${first}" == "true" ]] && first=false || skills_json+=","
        skills_json+="{\"skill_name\":\"${skill_name}\",\"path\":\"${skill_md_path}\",\"skill_dir\":\"${skill_dir}\",\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\"}"
        ((count++))
        log "INFO" "发现 Skill: ${skill_name} (Agent: ${agent_name}) - ${skill_md_path}"

    done < <(find / -name "SKILL.md" -type f 2>/dev/null | grep -v "/proc/" | grep -v "/sys/")

    skills_json+="]"

    # 生成 skills.json
    cat > "${SKILLS_FILE}" << EOF
{
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_skills": ${count},
  "skills": ${skills_json}
}
EOF

    log "INFO" "发现 ${count} 个 Skills (基于 SKILL.md)"
}

# ============================================================================
# 提取 API 配置 (增强版 - API Key 检测)
# ============================================================================
extract_api_configs() {
    log "INFO" "===== 提取 API 配置 ====="

    local configs_json="["
    local first=true
    local count=0

    # 定义 Agent 配置路径映射 (兼容 bash 3.2，使用普通数组)
    local agent_config_paths=(
        "claude:${HOME}/.claude"
        "openclaw:${HOME}/.openclaw"
        "opencode:${HOME}/.opencode"
        "nanobot:${HOME}/.nanobot"
        "hagent:/opt/hagent"
        "aicode:/opt/aicode"
    )

    # API Key 脱敏函数
    mask_api_key() {
        local key="$1"
        if [[ ${#key} -gt 10 ]]; then
            echo "${key:0:8}***"
        else
            echo "${key:0:4}***"
        fi
    }

    # 遍历已发现的 Agent (兼容 bash 3.2)
    for entry in "${AGENT_ID_LIST[@]}"; do
        local agent_key="${entry%%:*}"
        local agent_id="${entry#*:}"
        local agent_name="${agent_key%%:*}"
        # 从 agent_config_paths 查找配置路径
        local config_base=""
        local path_entry
        for path_entry in "${agent_config_paths[@]}"; do
            if [[ "${path_entry%%:*}" == "${agent_name}" ]]; then
                config_base="${path_entry#*:}"
                break
            fi
        done

        [[ -z "${config_base}" || ! -d "${config_base}" ]] && continue

        log "INFO" "扫描 Agent ${agent_name} (${agent_id}) 的 API 配置..."

        # 根据 Agent 类型搜索配置文件
        local config_files=()
        case "${agent_name}" in
            claude)
                config_files=("${config_base}/settings.json" "${config_base}/mcp.json" "${config_base}/mcp_config.json")
                ;;
            openclaw)
                # 搜索 ~/.openclaw/agents/*/agent/models.json 和 auth.json
                # 注意：models.json 会在后面的特殊处理部分统一处理，这里只处理 auth.json
                while IFS= read -r auth_file; do
                    [[ -n "${auth_file}" ]] && config_files+=("${auth_file}")
                done < <(find "${config_base}/agents" -name "auth.json" -type f 2>/dev/null)
                ;;
            opencode)
                config_files=("${config_base}/config.json")
                ;;
            nanobot)
                config_files=("${config_base}/config.json")
                ;;
            hagent)
                config_files=("${config_base}/config.json")
                ;;
            aicode)
                config_files=("${config_base}/nanobot/config.json")
                ;;
        esac

        # 解析每个配置文件
        for config_file in "${config_files[@]}"; do
            [[ ! -f "${config_file}" ]] && continue
            log "INFO" "解析配置文件：${config_file}"

            local file_content=$(cat "${config_file}" 2>/dev/null)

            # 提取 API Key 相关字段
            local api_keys=""
            local base_urls=""
            local models=""
            local providers=""

            # 检测常见 API Key 字段
            # ANTHROPIC_AUTH_TOKEN, apiKey, API_KEY, sk-xxx
            api_keys=$(echo "${file_content}" | perl -nle 'print $1 if /"(ANTHROPIC_AUTH_TOKEN|apiKey|API_KEY|api_key)"\s*:\s*"([^"]+)"/' 2>/dev/null | head -5)

            # 检测 Base URL 字段
            base_urls=$(echo "${file_content}" | perl -nle 'print $1 if /"(baseUrl|BASE_URL|base_url|endpoint|ANTHROPIC_BASE_URL)"\s*:\s*"([^"]+)"/' 2>/dev/null | head -5)

            # 检测 Model 字段
            models=$(echo "${file_content}" | perl -nle 'print $1 if /"(model|MODEL|ANTHROPIC_MODEL)"\s*:\s*"([^"]+)"/' 2>/dev/null | head -5)

            # 检测 Provider 字段 (OpenClaw models.json)
            providers=$(echo "${file_content}" | perl -nle 'print $1 if /"([a-zA-Z]+)"\s*:\s*\{[^}]*"baseUrl"[^}]*\}/' 2>/dev/null | head -5)

            # 如果没有找到 Provider，尝试从路径推断
            if [[ -z "${providers}" && "${config_file}" == *"openclaw"* ]]; then
                providers="bailian"
            fi

            # 获取第一个 base_url 和 model（用于关联）
            local first_base_url=$(echo "${base_urls}" | head -1)
            local first_model=$(echo "${models}" | head -1)

            # 生成配置记录
            if [[ -n "${api_keys}" ]]; then
                while IFS= read -r api_key; do
                    [[ -z "${api_key}" ]] && continue
                    local masked_key=$(mask_api_key "${api_key}")
                    local provider="${providers:-unknown}"

                    [[ "${first}" == "true" ]] && first=false || configs_json+=","
                    configs_json+="{\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\",\"provider\":\"${provider}\",\"api_key\":\"${masked_key}\",\"base_url\":\"${first_base_url:-}\",\"model\":\"${first_model:-}\",\"config_file\":\"${config_file}\"}"
                    ((count++))
                    log "INFO" "发现 API 配置：${agent_name} - ${provider} - ${masked_key}"
                done <<< "${api_keys}"
            fi

            # 处理 base_urls（如果没有 API Key）
            if [[ -n "${base_urls}" && -z "${api_keys}" ]]; then
                while IFS= read -r base_url; do
                    [[ -z "${base_url}" ]] && continue
                    local provider="${providers:-unknown}"

                    [[ "${first}" == "true" ]] && first=false || configs_json+=","
                    configs_json+="{\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\",\"provider\":\"${provider}\",\"api_key\":\"\",\"base_url\":\"${base_url}\",\"model\":\"${first_model:-}\",\"config_file\":\"${config_file}\"}"
                    ((count++))
                    log "INFO" "发现 Base URL 配置：${agent_name} - ${provider} - ${base_url}"
                done <<< "${base_urls}"
            fi

            # 处理 models（如果没有 API Key 和 Base URL）
            if [[ -n "${models}" && -z "${api_keys}" && -z "${base_urls}" ]]; then
                while IFS= read -r model; do
                    [[ -z "${model}" ]] && continue
                    local provider="${providers:-unknown}"

                    [[ "${first}" == "true" ]] && first=false || configs_json+=","
                    configs_json+="{\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\",\"provider\":\"${provider}\",\"api_key\":\"\",\"base_url\":\"\",\"model\":\"${model}\",\"config_file\":\"${config_file}\"}"
                    ((count++))
                    log "INFO" "发现 Model 配置：${agent_name} - ${provider} - ${model}"
                done <<< "${models}"
            fi
        done
    done

    # 特殊处理：OpenClaw agents 目录
    if [[ -d "${HOME}/.openclaw/agents" ]]; then
        for agent_dir in "${HOME}/.openclaw/agents"/*; do
            [[ ! -d "${agent_dir}" ]] && continue
            local openclaw_agent_name=$(basename "${agent_dir}")
            local models_json="${agent_dir}/agent/models.json"

            if [[ -f "${models_json}" ]]; then
                log "INFO" "解析 OpenClaw Agent models.json: ${models_json}"
                local content=$(cat "${models_json}" 2>/dev/null)

                # 提取 providers 名称（有 baseUrl 的）- 简化处理方式
                local provider_names="bailian"

                # 检查 content 中是否包含 bailian provider
                if ! echo "${content}" | grep -q '"bailian"'; then
                    # 如果没有 bailian，尝试动态提取
                    provider_names=$(echo "${content}" | perl -nle 'print $1 if /^\s*"([a-zA-Z_-]+)"\s*:\s*\{/' 2>/dev/null | head -5)
                fi

                for provider in ${provider_names}; do
                    # 检查该 provider 是否存在
                    if ! echo "${content}" | grep -q "\"${provider}\""; then
                        continue
                    fi

                    # 使用更精确的提取方式
                    local provider_block=$(echo "${content}" | grep -A 200 "\"${provider}\"" | head -200)
                    local api_key=$(echo "${provider_block}" | json_extract_value "apiKey")
                    local base_url=$(echo "${provider_block}" | json_extract_value "baseUrl")
                    # 提取该 provider 下的 models（在 provider block 内）
                    local model_list=$(echo "${provider_block}" | perl -nle 'print $1 if /"id"\s*:\s*"([^"]+)"/' 2>/dev/null | head -5 | tr '\n' ',' | sed 's/,$//')

                    if [[ -n "${api_key}" ]]; then
                        local masked_key=$(mask_api_key "${api_key}")
                        local agent_id=$(get_agent_id "openclaw" 2>/dev/null || echo "A000")

                        [[ "${first}" == "true" ]] && first=false || configs_json+=","
                        configs_json+="{\"agent_id\":\"${agent_id}\",\"agent_name\":\"openclaw-${openclaw_agent_name}\",\"provider\":\"${provider}\",\"api_key\":\"${masked_key}\",\"base_url\":\"${base_url:-}\",\"model\":\"${model_list:-}\",\"config_file\":\"${models_json}\"}"
                        ((count++))
                        log "INFO" "发现 OpenClaw API 配置：openclaw-${openclaw_agent_name} - ${provider} - ${masked_key} - models: ${model_list}"
                    fi
                done
            fi
        done
    fi

    configs_json+="]"

    # 生成 api_configs.json
    local api_configs_file="${OUTPUT_DIR}/api_configs.json"
    cat > "${api_configs_file}" << EOF
{
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_configs": ${count},
  "configs": ${configs_json}
}
EOF

    log "INFO" "共发现 ${count} 个 API 配置"
}

scan_scripts() {
    log "INFO" "扫描可执行脚本..."

    local scripts_json="["
    local first=true
    local count=0

    # 定义 Agent 目录与名称的映射 (兼容 bash 3.2)
    local agent_dir_map=(
        "${HOME}/.claude:claude"
        "${HOME}/.openclaw:openclaw"
        "${HOME}/.opencode:opencode"
        "/opt/openclaw:openclaw"
        "/opt/opencode:opencode"
    )

    # 辅助函数：从目录获取 agent_name
    get_agent_name_from_dir() {
        local dir="$1"
        local entry
        for entry in "${agent_dir_map[@]}"; do
            if [[ "${entry%%:*}" == "${dir}" ]]; then
                echo "${entry#*:}"
                return 0
            fi
        done
        echo "unknown"
    }

    for base in "${HOME}/.claude" "${HOME}/.openclaw" "${HOME}/.opencode" /opt; do
        if [[ -d "${base}" ]]; then
            local agent_name=$(get_agent_name_from_dir "${base}")
            local agent_id=$(get_agent_id "${agent_name}" 2>/dev/null || echo "A000")

            # Shell scripts
            while IFS= read -r file; do
                [[ -z "${file}" ]] && continue
                [[ "${first}" == "true" ]] && first=false || scripts_json+=","
                scripts_json+="{\"path\":\"$(json_escape "${file}")\",\"type\":\"shell\",\"risk\":\"high\",\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\"}"
                ((count++))
            done < <(find "${base}" -type f -name "*.sh" 2>/dev/null | head -500)

            # Python scripts
            while IFS= read -r file; do
                [[ -z "${file}" ]] && continue
                [[ "${first}" == "true" ]] && first=false || scripts_json+=","
                scripts_json+="{\"path\":\"$(json_escape "${file}")\",\"type\":\"python\",\"risk\":\"medium\",\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\"}"
                ((count++))
            done < <(find "${base}" -type f -name "*.py" 2>/dev/null | head -500)

            # JavaScript files
            while IFS= read -r file; do
                [[ -z "${file}" ]] && continue
                [[ "${first}" == "true" ]] && first=false || scripts_json+=","
                scripts_json+="{\"path\":\"$(json_escape "${file}")\",\"type\":\"javascript\",\"risk\":\"medium\",\"agent_id\":\"${agent_id}\",\"agent_name\":\"${agent_name}\"}"
                ((count++))
            done < <(find "${base}" -type f -name "*.js" 2>/dev/null | head -500)
        fi
    done

    scripts_json+="]"
    echo "${scripts_json}" > "${SCRIPTS_FILE}"
    log "INFO" "发现 ${count} 个脚本文件"
}

# ============================================================================
# 生成 SBOM (Software Bill of Materials) - 增强版：关联 Agent
# ============================================================================
generate_sbom() {
    log "INFO" "生成 SBOM..."

    local components=""
    local first=true
    local count=0

    # 获取所有 agent_id 列表 (兼容 bash 3.2)
    local all_agent_ids=""
    for entry in "${AGENT_ID_LIST[@]}"; do
        all_agent_ids+="\"${entry#*:}\","
    done
    all_agent_ids="${all_agent_ids%,}"  # 移除末尾逗号
    [[ -z "${all_agent_ids}" ]] && all_agent_ids="\"SYSTEM\""

    # NPM 全局包 - 关联到所有 Agent
    if command -v npm &>/dev/null; then
        local npm_list=$(npm list -g --depth=0 2>/dev/null | tail -n +2 || true)
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            # 解析 npm list 输出
            local pkg_info=$(echo "${line}" | sed 's/.*-- //')
            local pkg_name=$(echo "${pkg_info}" | cut -d'@' -f1)
            local pkg_version=$(echo "${pkg_info}" | perl -nle 'print $1 if /@([0-9.]+)/' 2>/dev/null || echo "unknown")

            [[ -z "${pkg_name}" ]] && continue
            [[ "${first}" == "true" ]] && first=false || components+=","
            components+="{\"name\":\"${pkg_name}\",\"version\":\"${pkg_version}\",\"packageManager\":\"npm\",\"scope\":\"global\",\"agent_ids\":[${all_agent_ids}]}"
            ((count++))
        done <<< "${npm_list}"
    fi

    # Python 包 - 关联到所有 Agent
    if command -v pip3 &>/dev/null; then
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            local pkg_name=$(echo "${line}" | awk '{print $1}')
            local pkg_version=$(echo "${line}" | awk '{print $2}')

            [[ -z "${pkg_name}" ]] && continue
            [[ "${first}" == "true" ]] && first=false || components+=","
            components+="{\"name\":\"${pkg_name}\",\"version\":\"${pkg_version}\",\"packageManager\":\"pip\",\"scope\":\"global\",\"agent_ids\":[${all_agent_ids}]}"
            ((count++))
        done < <(pip3 list 2>/dev/null | tail -n +3)
    fi

    # 系统包 (dpkg) - 标记为 SYSTEM
    if command -v dpkg-query &>/dev/null; then
        while IFS='|' read -r pkg_name pkg_version; do
            [[ -z "${pkg_name}" ]] && continue
            [[ "${first}" == "true" ]] && first=false || components+=","
            components+="{\"name\":\"${pkg_name}\",\"version\":\"${pkg_version}\",\"packageManager\":\"dpkg\",\"scope\":\"system\",\"agent_ids\":[\"SYSTEM\"]}"
            ((count++))
        done < <(dpkg-query -W -f='${Package}|${Version}\n' 2>/dev/null | head -200)
    fi

    # 输出 SBOM JSON
    cat > "${SBOM_FILE}" << EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "metadata": {
    "component": {
      "name": "ai-agent-system",
      "type": "application"
    }
  },
  "components": [${components}]
}
EOF

    log "INFO" "SBOM 包含 ${count} 个组件"
}

# ============================================================================
# CVE 漏洞分析 (纯 Bash 实现)
# ============================================================================
analyze_cve() {
    log "INFO" "===== 开始 CVE 漏洞分析 ====="

    # 已知漏洞数据库 (使用普通数组存储，兼容 bash 3.2)
    # 格式：组件名|CVE|严重性|CVSS|描述|CWE
    local vuln_db=(
        # ===================== Python 包漏洞 =====================
        # Pillow (图像处理)
        "pillow|CVE-2023-50447|CRITICAL|9.8|Pillow 远程代码执行|CWE-94"
        "pillow|CVE-2024-3968|HIGH|7.5|Pillow 拒绝服务漏洞|CWE-400"
        "pillow|CVE-2023-44271|HIGH|7.5|Pillow DoS 漏洞|CWE-400"

        # urllib3 (HTTP 客户端)
        "urllib3|CVE-2023-45803|MEDIUM|4.2|urllib3 请求泄露|CWE-200"
        "urllib3|CVE-2023-43804|HIGH|8.1|urllib3 Cookie 泄露|CWE-614"
        "urllib3|CVE-2023-41105|MEDIUM|6.1|urllib3 代理验证绕过|CWE-287"
        "urllib3|CVE-2024-37890|HIGH|7.5|urllib3 代理基本认证泄露|CWE-522"

        # Requests (HTTP 库)
        "requests|CVE-2023-32681|MEDIUM|6.1|Requests 代理认证泄露|CWE-522"
        "requests|CVE-2024-35195|MEDIUM|6.5|Requests SSL 验证绕过|CWE-295"

        # Jinja2 (模板引擎)
        "jinja2|CVE-2024-22195|HIGH|7.5|Jinja2 XSS 漏洞|CWE-79"
        "jinja2|CVE-2024-34069|HIGH|7.5|Jinja2 沙盒逃逸|CWE-502"

        # Flask (Web 框架)
        "flask|CVE-2023-30861|HIGH|7.5|Flask 会话泄露|CWE-614"
        "flask|CVE-2024-34069|MEDIUM|5.3|Flask 请求伪造|CWE-352"

        # Django (Web 框架)
        "django|CVE-2024-24680|HIGH|7.8|Django DoS 漏洞|CWE-400"
        "django|CVE-2024-35195|HIGH|7.5|Django SQL 注入|CWE-89"
        "django|CVE-2023-46695|HIGH|7.5|Django 路径遍历|CWE-22"
        "django|CVE-2024-35200|MEDIUM|5.3|Django XSS 漏洞|CWE-79"

        # Werkzeug (WSGI 库)
        "werkzeug|CVE-2023-46136|HIGH|7.5|Werkzeug 路径遍历|CWE-22"
        "werkzeug|CVE-2023-25577|HIGH|7.5|Werkzeug DoS 漏洞|CWE-400"

        # NumPy (数值计算)
        "numpy|CVE-2021-41496|MEDIUM|5.5|NumPy 缓冲区溢出|CWE-120"
        "numpy|CVE-2021-34141|MEDIUM|7.5|NumPy 空指针解引用|CWE-476"

        # lxml (XML 处理)
        "lxml|CVE-2024-34575|HIGH|8.1|lxml XXE 漏洞|CWE-611"

        # PyYAML (YAML 解析)
        "pyyaml|CVE-2020-14343|CRITICAL|9.8|PyYAML 代码执行|CWE-94"

        # cryptography (加密库)
        "cryptography|CVE-2023-49083|CRITICAL|9.8|cryptography 空指针解引用|CWE-476"
        "cryptography|CVE-2023-38325|HIGH|7.5|cryptography 拒绝服务|CWE-400"

        # ===================== Node.js/npm 包漏洞 =====================
        # Lodash (工具库)
        "lodash|CVE-2021-23337|HIGH|7.2|Lodash 命令注入漏洞|CWE-77"
        "lodash|CVE-2020-8203|HIGH|7.4|Lodash 原型污染|CWE-1321"
        "lodash|CVE-2021-32804|HIGH|7.5|Lodash 原型污染|CWE-1321"

        # Express (Web 框架)
        "express|CVE-2024-29041|HIGH|7.5|Express 路径遍历漏洞|CWE-22"
        "express|CVE-2024-33883|MEDIUM|5.3|Express 重定向漏洞|CWE-601"

        # Axios (HTTP 客户端)
        "axios|CVE-2023-45857|MEDIUM|6.5|Axios CSRF 漏洞|CWE-352"
        "axios|CVE-2024-39338|MEDIUM|6.5|Axios 请求伪造|CWE-918"

        # Node.js (运行时)
        "node|CVE-2024-27980|HIGH|8.8|Node.js Windows 提权|CWE-269"
        "node|CVE-2024-27983|HIGH|7.5|Node.js 路径遍历|CWE-22"
        "node|CVE-2024-21891|HIGH|7.8|Node.js 原型污染|CWE-1321"
        "node|CVE-2023-39332|HIGH|7.8|Node.js DNS 重绑定|CWE-491"

        # minimist (参数解析)
        "minimist|CVE-2021-44906|CRITICAL|9.8|minimist 原型污染|CWE-1321"

        # jsonwebtoken (JWT 库)
        "jsonwebtoken|CVE-2022-23539|CRITICAL|9.8|jsonwebtoken 代码执行|CWE-94"
        "jsonwebtoken|CVE-2022-23552|HIGH|7.5|jsonwebtoken 签名绕过|CWE-347"

        # axios (HTTP)
        "follow-redirects|CVE-2022-0155|HIGH|6.5|follow-redirects 敏感信息泄露|CWE-200"
        "follow-redirects|CVE-2022-0536|MEDIUM|5.9|follow-redirects 头部泄露|CWE-200"

        # ===================== 系统组件漏洞 =====================
        # Git
        "git|CVE-2024-32002|CRITICAL|9.1|Git 代码注入|CWE-94"
        "git|CVE-2024-32004|HIGH|8.1|Git 路径遍历|CWE-22"

        # OpenSSH
        "openssh|CVE-2024-6387|CRITICAL|8.1|OpenSSH regreSSHion RCE|CWE-416"

        # OpenSSL
        "openssl|CVE-2024-0727|HIGH|7.5|OpenSSL 拒绝服务|CWE-400"
        "openssl|CVE-2023-5678|HIGH|7.5|OpenSSL 内存溢出|CWE-787"

        # Sudo
        "sudo|CVE-2023-22809|CRITICAL|8.4|Sudo 提权漏洞|CWE-269"

        # Polkit
        "polkit|CVE-2021-4034|CRITICAL|7.8|PwnKit 提权|CWE-269"

        # curl
        "curl|CVE-2024-23791|HIGH|7.5|curl HSTS 绕过|CWE-295"
        "curl|CVE-2024-22804|MEDIUM|5.7|curl 敏感信息泄露|CWE-200"

        # ===================== AI Agent 相关漏洞 =====================
        # OpenClaw (模拟)
        "openclaw|CVE-2024-SIM-001|INFO|0|API 密钥配置检查|CWE-522"
        "openclaw|CVE-2024-SIM-003|MEDIUM|5.3|配置文件未加密存储|CWE-311"

        # OpenCode (模拟)
        "opencode|CVE-2024-SIM-002|INFO|0|配置安全检查|CWE-522"
        "opencode|CVE-2024-SIM-004|MEDIUM|5.5|MCP 服务器认证绕过|CWE-287"

        # Claude Code (模拟)
        "claude-code|CVE-2024-SIM-005|INFO|0|会话令牌安全检查|CWE-614"

        # Ollama (模拟)
        "ollama|CVE-2024-SIM-006|MEDIUM|6.5|本地 API 未授权访问|CWE-284"

        # ===================== 其他常见组件 =====================
        # GitPython
        "gitpython|CVE-2023-40590|HIGH|7.5|GitPython 代码注入|CWE-94"
        "gitpython|CVE-2023-41491|HIGH|7.5|GitPython 路径遍历|CWE-22"

        # Certifi
        "certifi|CVE-2023-37920|CRITICAL|9.1|certifi 证书验证绕过|CWE-295"

        # setuptools
        "setuptools|CVE-2024-6345|HIGH|7.5|setuptools 远程代码执行|CWE-94"

        # pip
        "pip|CVE-2024-6345|HIGH|7.0|pip 远程代码执行|CWE-94"
    )

    # RCE 相关 CWE
    local rce_cwe="CWE-77 CWE-78 CWE-94 CWE-502 CWE-269 CWE-22 CWE-434 CWE-416 CWE-1321"

    # Shell 注入相关 CWE
    local shell_injection_cwe="CWE-78 CWE-77 CWE-94"

    # 提权相关 CWE
    local priv_esc_cwe="CWE-269 CWE-250 CWE-252 CWE-253 CWE-284"

    # 读取 SBOM 组件并匹配漏洞
    local vulnerabilities=""
    local first=true
    local total=0
    local critical=0
    local high=0
    local medium=0

    # 从 SBOM 提取组件名（处理单行 JSON 格式）
    local components=$(cat "${SBOM_FILE}" 2>/dev/null | tr ',' '\n' | perl -nle 'print $1 if /"name"\s*:\s*"([^"]+)"/' | sort -u)

    for comp in ${components}; do
        local comp_lower=$(echo "${comp}" | tr '[:upper:]' '[:lower:]')
        # 从 SBOM 获取组件版本（处理单行 JSON 格式）
        local comp_version=$(cat "${SBOM_FILE}" 2>/dev/null | tr ',' '\n' | grep -A1 "\"name\": *\"${comp}\"" | perl -nle 'print $1 if /"version"\s*:\s*"([^"]+)"/' 2>/dev/null | head -1 || echo "unknown")

        # 从 SBOM 获取组件的 agent_ids（处理单行 JSON 格式）
        local agent_ids="[]"
        local agent_line=$(cat "${SBOM_FILE}" 2>/dev/null | tr ',' '\n' | grep -A3 "\"name\": *\"${comp}\"" | perl -nle 'print $1 if /"agent_ids"\s*:\s*\[([^\]]*)\]/' 2>/dev/null | head -1)
        if [[ -n "${agent_line}" ]]; then
            agent_ids="[${agent_line}]"
        fi

        # 匹配已知漏洞
        for vuln_entry in "${vuln_db[@]}"; do
            IFS='|' read -r vuln_comp cve_id severity cvss description cwe <<< "${vuln_entry}"

            if [[ "${comp_lower}" == *"${vuln_comp}"* ]]; then
                # 检查风险类型
                local risk_flags=""
                local is_critical="false"

                # RCE 检查
                if [[ "${rce_cwe}" == *"${cwe}"* ]]; then
                    risk_flags="\"RCE\""
                fi

                # Shell 注入检查
                if [[ "${shell_injection_cwe}" == *"${cwe}"* ]]; then
                    [[ -n "${risk_flags}" ]] && risk_flags+=","
                    risk_flags+="\"SHELL_INJECTION\""
                fi

                # 提权检查
                if [[ "${priv_esc_cwe}" == *"${cwe}"* ]]; then
                    [[ -n "${risk_flags}" ]] && risk_flags+=","
                    risk_flags+="\"PRIVILEGE_ESCALATION\""
                fi

                # 严重性检查
                if [[ "${cwe}" == "CWE-94" || "${cwe}" == "CWE-416" || "${cwe}" == "CWE-269" ]]; then
                    is_critical="true"
                    ((critical++))
                elif [[ "${severity}" == "CRITICAL" ]]; then
                    is_critical="true"
                    ((critical++))
                elif [[ "${severity}" == "HIGH" ]]; then
                    ((high++))
                elif [[ "${severity}" == "MEDIUM" ]]; then
                    ((medium++))
                fi

                [[ "${first}" == "true" ]] && first=false || vulnerabilities+=","
                vulnerabilities+="{\"component\":\"${comp}\",\"version\":\"${comp_version}\",\"cve_id\":\"${cve_id}\",\"severity\":\"${severity}\",\"cvss\":${cvss},\"description\":\"${description}\",\"cwe\":\"${cwe}\",\"risk_flags\":[${risk_flags}],\"is_critical\":${is_critical},\"affected_agents\":${agent_ids}}"
                ((total++))
            fi
        done
    done

    # 输出漏洞 JSON
    cat > "${VULN_FILE}" << EOF
{
  "scan_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_vulnerabilities": ${total},
  "critical_count": ${critical},
  "high_count": ${high},
  "medium_count": ${medium},
  "vulnerabilities": [${vulnerabilities}]
}
EOF

    log "INFO" "发现 ${total} 个漏洞 (严重：${critical}, 高危：${high}, 中危：${medium})"
}

# ============================================================================
# 生成 HTML 报告 (纯 Bash)
# ============================================================================
generate_html_report() {
    log "INFO" "生成 HTML 报告..."

    # 读取 Skills 数据
    local skills_file="${OUTPUT_DIR}/skills.json"
    local total_skills=$(perl -nle 'print $1 if /"total_skills"\s*:\s*([0-9]+)/' "${skills_file}" 2>/dev/null || echo "0")

    # 读取 API 配置数据
    local api_configs_file="${OUTPUT_DIR}/api_configs.json"
    local total_api_configs=$(perl -nle 'print $1 if /"total_configs"\s*:\s*([0-9]+)/' "${api_configs_file}" 2>/dev/null || echo "0")

    # 生成 API 配置表格行
    local api_config_rows=""
    if [[ -f "${api_configs_file}" ]]; then
        while IFS= read -r line; do
            local agent_id=$(echo "${line}" | json_extract_value "agent_id")
            local agent_name=$(echo "${line}" | json_extract_value "agent_name")
            local provider=$(echo "${line}" | json_extract_value "provider")
            local api_key=$(echo "${line}" | json_extract_value "api_key")
            local base_url=$(echo "${line}" | json_extract_value "base_url")
            local model=$(echo "${line}" | json_extract_value "model")
            local config_file=$(echo "${line}" | json_extract_value "config_file")
            [[ -z "${agent_id}" ]] && continue
            api_config_rows+="<tr><td>${agent_id}</td><td>${agent_name}</td><td>${provider}</td><td>${api_key}</td><td>${base_url}</td><td>${model}</td><td>${config_file}</td></tr>"
        done < <(grep -o '{[^{}]*"agent_id"[^{}]*}' "${api_configs_file}" 2>/dev/null)
    fi

    # 生成 Skills 表格行
    local skills_rows=""
    if [[ -f "${skills_file}" ]]; then
        while IFS= read -r line; do
            local skill_name=$(echo "${line}" | json_extract_value "skill_name")
            local path=$(echo "${line}" | json_extract_value "path")
            local agent_id=$(echo "${line}" | json_extract_value "agent_id")
            local agent_name=$(echo "${line}" | json_extract_value "agent_name")
            [[ -z "${skill_name}" ]] && continue
            skills_rows+="<tr><td>${agent_id}</td><td>${agent_name}</td><td>${skill_name}</td><td>${path}</td></tr>"
        done < <(grep -o '{[^{}]*"skill_name"[^{}]*}' "${skills_file}" 2>/dev/null)
    fi

    # 读取漏洞数据
    local total_vulns=$(perl -nle 'print $1 if /"total_vulnerabilities"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local critical_count=$(perl -nle 'print $1 if /"critical_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local high_count=$(perl -nle 'print $1 if /"high_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local agent_count=$(grep -o '"name"' "${AGENTS_FILE}" 2>/dev/null | wc -l)
    local component_count=$(grep -o '"name"' "${SBOM_FILE}" 2>/dev/null | wc -l)
    local mcp_server_count=$(perl -nle 'print $1 if /"total_servers"\s*:\s*([0-9]+)/' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null || echo "0")

    # 生成 Agent 表格行（包含 agent_id）
    local agent_rows=""
    while IFS= read -r line; do
        local agent_id=$(echo "${line}" | json_extract_value "agent_id")
        local name=$(echo "${line}" | json_extract_value "name")
        local type=$(echo "${line}" | json_extract_value "type")
        local path=$(echo "${line}" | json_extract_value "path")
        local hostname=$(echo "${line}" | json_extract_value "hostname")
        [[ -n "${name}" ]] && agent_rows+="<tr><td>${agent_id}</td><td>${name}</td><td>${type}</td><td>${path}</td><td>${hostname:-${HOST_NAME}}</td></tr>"
    done < <(grep -o '{[^{}]*"agent_id"[^{}]*}' "${AGENTS_FILE}" 2>/dev/null)

    # 生成漏洞表格行（包含 affected_agents）
    local vuln_rows=""
    while IFS= read -r line; do
        local cve=$(echo "${line}" | json_extract_value "cve_id")
        local comp=$(echo "${line}" | json_extract_value "component")
        local ver=$(echo "${line}" | json_extract_value "version")
        local sev=$(echo "${line}" | json_extract_value "severity")
        local cvss=$(echo "${line}" | perl_extract '"cvss"\s*:\s*([0-9.]+)')
        local desc=$(echo "${line}" | json_extract_value "description")
        local flags=$(echo "${line}" | perl_extract '"risk_flags"\s*:\s*\[([^\]]*)\]')
        local affected=$(echo "${line}" | perl_extract '"affected_agents"\s*:\s*\[([^\]]*)\]')

        [[ -z "${cve}" ]] && continue

        local badge_class="badge-info"
        case "${sev}" in
            "CRITICAL") badge_class="badge-critical" ;;
            "HIGH") badge_class="badge-high" ;;
            "MEDIUM") badge_class="badge-medium" ;;
            "LOW") badge_class="badge-low" ;;
        esac

        local risk_span=""
        if [[ "${flags}" == *"RCE"* ]]; then
            risk_span="<span class=\"risk-flag risk-rce\">RCE</span>"
        fi

        # 格式化 affected_agents 显示
        local affected_display=""
        if [[ -n "${affected}" ]]; then
            local agent_count=$(echo "${affected}" | tr ',' '\n' | wc -l)
            affected_display="<span title=\"${affected}\">影响${agent_count}个 Agent</span>"
        fi

        if [[ "${sev}" == "CRITICAL" || "${sev}" == "HIGH" ]]; then
            vuln_rows+="<tr><td><strong>${cve}</strong></td><td>${comp} (${ver})</td><td><span class=\"badge ${badge_class}\">${sev}</span></td><td>${cvss}</td><td>${desc}</td><td>${risk_span}</td><td>${affected_display}</td></tr>"
        fi
    done < <(grep -o '{[^{}]*"cve_id"[^{}]*}' "${VULN_FILE}" 2>/dev/null)

    # 生成 HTML
    cat > "${REPORT_FILE}" << HTMLEOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Agent 安全审计报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 36px; font-weight: bold; }
        .section { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { color: #1a1a2e; margin-bottom: 15px; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #1a1a2e; }
        .badge-low { background: #28a745; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        .risk-flag { display: inline-block; padding: 2px 6px; margin: 2px; border-radius: 3px; font-size: 11px; font-weight: 600; color: white; }
        .risk-rce { background: #dc3545; }
        .risk-shell { background: #fd7e14; }
        .risk-priv { background: #6f42c1; }
        .agent-item { padding: 15px; background: #f8f9fa; border-radius: 8px; margin: 10px 0; border-left: 3px solid #1a1a2e; }
        .timestamp { text-align: right; color: #999; font-size: 13px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AI Agent 安全审计报告</h1>
            <p>生成时间：$(date '+%Y-%m-%d %H:%M:%S')</p>
        </div>

        <div class="stats">
            <div class="stat-card" style="border-left:4px solid #2196f3">
                <div class="stat-number" style="color:#2196f3">${HOST_NAME}</div>
                <div>主机名 (${HOST_IP})</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #dc3545">
                <div class="stat-number" style="color:#dc3545">${critical_count}</div>
                <div>严重漏洞</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #fd7e14">
                <div class="stat-number" style="color:#fd7e14">${high_count}</div>
                <div>高危漏洞</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #28a745">
                <div class="stat-number" style="color:#28a745">${agent_count}</div>
                <div>发现 Agent</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #17a2b8">
                <div class="stat-number" style="color:#17a2b8">${component_count}</div>
                <div>组件</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #6f42c1">
                <div class="stat-number" style="color:#6f42c1">${mcp_server_count}</div>
                <div>MCP 服务器</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #e91e63">
                <div class="stat-number" style="color:#e91e63">${total_skills}</div>
                <div>Skills/Plugins</div>
            </div>
            <div class="stat-card" style="border-left:4px solid #ff5722">
                <div class="stat-number" style="color:#ff5722">${total_api_configs}</div>
                <div>API 配置</div>
            </div>
        </div>

        <div class="section">
            <h2>发现的 AI Agent</h2>
            <table>
                <thead>
                    <tr><th>Agent ID</th><th>名称</th><th>类型</th><th>路径</th><th>主机名</th></tr>
                </thead>
                <tbody>
                    ${agent_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>高危漏洞详情</h2>
HTMLEOF

    if [[ -n "${vuln_rows}" ]]; then
        cat >> "${REPORT_FILE}" << HTMLEOF
            <table>
                <thead>
                    <tr><th>CVE</th><th>组件</th><th>严重性</th><th>CVSS</th><th>描述</th><th>风险</th><th>影响 Agent</th></tr>
                </thead>
                <tbody>
                    ${vuln_rows}
                </tbody>
            </table>
HTMLEOF
    else
        cat >> "${REPORT_FILE}" << HTMLEOF
            <p style="text-align:center;color:#28a745;padding:40px;">未发现高危漏洞</p>
HTMLEOF
    fi

    cat >> "${REPORT_FILE}" << HTMLEOF
        </div>

        <div class="section">
            <h2>MCP 服务器配置</h2>
            <p>共发现 <strong>${mcp_server_count}</strong> 个 MCP 服务器，详见 <a href="mcp_servers.json">mcp_servers.json</a></p>
HTMLEOF

    # 生成 MCP 服务器表格
    local mcp_rows=""
    if [[ -f "${OUTPUT_DIR}/mcp_servers.json" ]]; then
        while IFS= read -r line; do
            local name=$(echo "${line}" | json_extract_value "name")
            local type=$(echo "${line}" | json_extract_value "type")
            local url=$(echo "${line}" | json_extract_value "url")
            local cmd=$(echo "${line}" | json_extract_value "command")
            local source=$(echo "${line}" | json_extract_value "source")
            [[ -z "${name}" ]] && continue

            local conn_info="${url:-${cmd:-N/A}}"
            mcp_rows+="<tr><td>${name}</td><td>${type}</td><td>${conn_info}</td><td>${source}</td></tr>"
        done < <(grep -o '{[^{}]*"name"[^{}]*}' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null)
    fi

    if [[ -n "${mcp_rows}" ]]; then
        cat >> "${REPORT_FILE}" << HTMLEOF
            <table>
                <thead>
                    <tr><th>服务器名称</th><th>类型</th><th>连接信息</th><th>配置来源</th></tr>
                </thead>
                <tbody>
                    ${mcp_rows}
                </tbody>
            </table>
HTMLEOF
    else
        cat >> "${REPORT_FILE}" << HTMLEOF
            <p style="text-align:center;color:#999;padding:20px;">未发现 MCP 服务器配置</p>
HTMLEOF
    fi

    cat >> "${REPORT_FILE}" << HTMLEOF
        </div>

        <div class="section">
            <h2>SBOM 组件清单</h2>
            <p>共 ${component_count} 个组件，详见 <a href="sbom.json">sbom.json</a></p>
        </div>

        <div class="section">
            <h2>可执行脚本</h2>
            <p>已扫描 <strong>$(grep -o '"path"' "${SCRIPTS_FILE}" 2>/dev/null | wc -l)</strong> 个脚本文件，详见 <a href="scripts.json">scripts.json</a></p>
        </div>

        <div class="section">
            <h2>Skills/Plugins 清单</h2>
            <p>共发现 <strong>${total_skills}</strong> 个 Skills/Plugins，详见 <a href="skills.json">skills.json</a></p>
HTMLEOF

    if [[ -n "${skills_rows}" ]]; then
        cat >> "${REPORT_FILE}" << HTMLEOF
            <table>
                <thead>
                    <tr><th>Agent ID</th><th>Agent 名称</th><th>Skill/Plugin 名称</th><th>路径</th></tr>
                </thead>
                <tbody>
                    ${skills_rows}
                </tbody>
            </table>
HTMLEOF
    else
        cat >> "${REPORT_FILE}" << HTMLEOF
            <p style="text-align:center;color:#999;padding:20px;">未发现 Skills/Plugins</p>
HTMLEOF
    fi

    cat >> "${REPORT_FILE}" << HTMLEOF
        </div>

        <div class="section">
            <h2>API 配置详情</h2>
            <p>共发现 <strong>${total_api_configs}</strong> 个 API 配置，详见 <a href="api_configs.json">api_configs.json</a></p>
HTMLEOF

    if [[ -n "${api_config_rows}" ]]; then
        cat >> "${REPORT_FILE}" << HTMLEOF
            <table>
                <thead>
                    <tr><th>Agent ID</th><th>Agent 名称</th><th>Provider</th><th>API Key (脱敏)</th><th>Base URL</th><th>Model</th><th>配置文件</th></tr>
                </thead>
                <tbody>
                    ${api_config_rows}
                </tbody>
            </table>
HTMLEOF
    else
        cat >> "${REPORT_FILE}" << HTMLEOF
            <p style="text-align:center;color:#999;padding:20px;">未发现 API 配置</p>
HTMLEOF
    fi

    cat >> "${REPORT_FILE}" << HTMLEOF
        </div>

        <div class="timestamp">报告生成时间：$(date '+%Y-%m-%d %H:%M:%S')</div>
    </div>
</body>
</html>
HTMLEOF

    log "INFO" "HTML 报告已生成：${REPORT_FILE}"
}

# ============================================================================
# 生成 Excel 报告 (CSV 格式，纯 Bash)
# ============================================================================
generate_excel_report() {
    log "INFO" "生成 Excel 报告 (CSV 格式)..."

    local excel_dir="${OUTPUT_DIR}/excel_reports"
    mkdir -p "${excel_dir}"

    # 1. 漏洞详情表
    local vuln_csv="${excel_dir}/01_vulnerabilities.csv"
    echo "CVE ID，组件，版本，严重性，CVSS，描述，CWE，风险标识，影响 Agent，是否严重" > "${vuln_csv}"

    while IFS= read -r line; do
        local cve=$(echo "${line}" | json_extract_value "cve_id")
        local comp=$(echo "${line}" | json_extract_value "component")
        local ver=$(echo "${line}" | json_extract_value "version")
        local sev=$(echo "${line}" | json_extract_value "severity")
        local cvss=$(echo "${line}" | perl_extract '"cvss"\s*:\s*([0-9.]+)')
        local desc=$(echo "${line}" | json_extract_value "description")
        local cwe=$(echo "${line}" | json_extract_value "cwe")
        local flags=$(echo "${line}" | perl_extract '"risk_flags"\s*:\s*\[([^\]]*)\]' | tr -d '"' | tr ',' ';')
        local affected=$(echo "${line}" | perl_extract '"affected_agents"\s*:\s*\[([^\]]*)\]' | tr -d '"' | tr ',' ';')
        local is_crit=$(echo "${line}" | json_extract_bool "is_critical")

        [[ -z "${cve}" ]] && continue
        # CSV 转义：双引号包裹含逗号的字段
        echo "\"${cve}\",\"${comp}\",\"${ver}\",\"${sev}\",${cvss},\"${desc}\",\"${cwe}\",\"${flags}\",\"${affected}\",${is_crit}" >> "${vuln_csv}"
    done < <(grep -o '{[^{}]*"cve_id"[^{}]*}' "${VULN_FILE}" 2>/dev/null)

    # 2. AI Agent 列表（包含 agent_id）
    local agents_csv="${excel_dir}/02_agents.csv"
    echo "Agent ID，名称，类型，路径，主机名" > "${agents_csv}"

    while IFS= read -r line; do
        local agent_id=$(echo "${line}" | json_extract_value "agent_id")
        local name=$(echo "${line}" | json_extract_value "name")
        local type=$(echo "${line}" | json_extract_value "type")
        local path=$(echo "${line}" | json_extract_value "path")
        local hostname=$(echo "${line}" | json_extract_value "hostname")
        [[ -z "${name}" ]] && continue
        echo "\"${agent_id}\",\"${name}\",\"${type}\",\"${path}\",\"${hostname:-${HOST_NAME}}\"" >> "${agents_csv}"
    done < <(grep -o '{[^{}]*"agent_id"[^{}]*}' "${AGENTS_FILE}" 2>/dev/null)

    # 3. MCP 服务器列表
    local mcp_csv="${excel_dir}/03_mcp_servers.csv"
    echo "服务器名称，类型，URL,命令，参数，OAuth，配置来源，影响 Agent" > "${mcp_csv}"

    if [[ -f "${OUTPUT_DIR}/mcp_servers.json" ]]; then
        while IFS= read -r line; do
            local name=$(echo "${line}" | json_extract_value "name")
            local type=$(echo "${line}" | json_extract_value "type")
            local url=$(echo "${line}" | json_extract_value "url")
            local cmd=$(echo "${line}" | json_extract_value "command")
            local args=$(echo "${line}" | json_extract_value "args")
            local oauth=$(echo "${line}" | json_extract_value "oauth")
            local source=$(echo "${line}" | json_extract_value "source")
            local affected=$(echo "${line}" | perl_extract '"affected_agents"\s*:\s*\[([^\]]*)\]' | tr -d '"' | tr ',' ';')
            [[ -z "${name}" ]] && continue
            echo "\"${name}\",\"${type}\",\"${url}\",\"${cmd}\",\"${args}\",\"${oauth}\",\"${source}\",\"${affected}\"" >> "${mcp_csv}"
        done < <(grep -o '{[^{}]*"name"[^{}]*}' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null)
    fi

    # 4. 可执行脚本列表（包含 agent_id, agent_name）
    local scripts_csv="${excel_dir}/04_scripts.csv"
    echo "路径，类型，风险等级，Agent ID,Agent 名称" > "${scripts_csv}"

    if [[ -f "${SCRIPTS_FILE}" ]]; then
        while IFS= read -r line; do
            local path=$(echo "${line}" | json_extract_value "path")
            local type=$(echo "${line}" | json_extract_value "type")
            local risk=$(echo "${line}" | json_extract_value "risk")
            local agent_id=$(echo "${line}" | json_extract_value "agent_id")
            local agent_name=$(echo "${line}" | json_extract_value "agent_name")
            [[ -z "${path}" ]] && continue
            echo "\"${path}\",\"${type}\",\"${risk}\",\"${agent_id}\",\"${agent_name}\"" >> "${scripts_csv}"
        done < <(grep -o '{[^{}]*"path"[^{}]*}' "${SCRIPTS_FILE}" 2>/dev/null)
    fi

    # 5. SBOM 组件清单（包含 agent_ids）
    local sbom_csv="${excel_dir}/05_sbom_components.csv"
    echo "组件名称，版本，包管理器，范围，Agent IDs" > "${sbom_csv}"

    if [[ -f "${SBOM_FILE}" ]]; then
        while IFS= read -r line; do
            local name=$(echo "${line}" | json_extract_value "name")
            local ver=$(echo "${line}" | json_extract_value "version")
            local pm=$(echo "${line}" | json_extract_value "packageManager")
            local scope=$(echo "${line}" | json_extract_value "scope")
            local agent_ids=$(echo "${line}" | perl_extract '"agent_ids"\s*:\s*\[([^\]]*)\]')
            [[ -z "${name}" ]] && continue
            echo "\"${name}\",\"${ver}\",\"${pm}\",\"${scope}\",\"${agent_ids}\"" >> "${sbom_csv}"
        done < <(grep -o '{[^{}]*"name"[^{}]*}' "${SBOM_FILE}" 2>/dev/null)
    fi

    # 6. Skills/Plugins 清单
    local skills_csv="${excel_dir}/06_skills.csv"
    echo "Agent ID,Agent 名称，Skill/Plugin 名称，路径" > "${skills_csv}"

    local skills_file="${OUTPUT_DIR}/skills.json"
    if [[ -f "${skills_file}" ]]; then
        while IFS= read -r line; do
            local skill_name=$(echo "${line}" | json_extract_value "skill_name")
            local path=$(echo "${line}" | json_extract_value "path")
            local agent_id=$(echo "${line}" | json_extract_value "agent_id")
            local agent_name=$(echo "${line}" | json_extract_value "agent_name")
            [[ -z "${skill_name}" ]] && continue
            echo "\"${agent_id}\",\"${agent_name}\",\"${skill_name}\",\"${path}\"" >> "${skills_csv}"
        done < <(grep -o '{[^{}]*"skill_name"[^{}]*}' "${skills_file}" 2>/dev/null)
    fi

    # 7. API 配置清单
    local api_configs_csv="${excel_dir}/07_api_configs.csv"
    echo "Agent ID,Agent 名称，Provider,API Key (脱敏),Base URL,Model，配置文件" > "${api_configs_csv}"

    local api_configs_file="${OUTPUT_DIR}/api_configs.json"
    if [[ -f "${api_configs_file}" ]]; then
        while IFS= read -r line; do
            local agent_id=$(echo "${line}" | json_extract_value "agent_id")
            local agent_name=$(echo "${line}" | json_extract_value "agent_name")
            local provider=$(echo "${line}" | json_extract_value "provider")
            local api_key=$(echo "${line}" | json_extract_value "api_key")
            local base_url=$(echo "${line}" | json_extract_value "base_url")
            local model=$(echo "${line}" | json_extract_value "model")
            local config_file=$(echo "${line}" | json_extract_value "config_file")
            [[ -z "${agent_id}" ]] && continue
            echo "\"${agent_id}\",\"${agent_name}\",\"${provider}\",\"${api_key}\",\"${base_url}\",\"${model}\",\"${config_file}\"" >> "${api_configs_csv}"
        done < <(grep -o '{[^{}]*"agent_id"[^{}]*}' "${api_configs_file}" 2>/dev/null)
    fi

    # 8. 审计摘要
    local summary_csv="${excel_dir}/00_summary.csv"
    local total_vulns=$(perl -nle 'print $1 if /"total_vulnerabilities"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local critical_count=$(perl -nle 'print $1 if /"critical_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local high_count=$(perl -nle 'print $1 if /"high_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local medium_count=$(perl -nle 'print $1 if /"medium_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
    local agent_count=$(grep -o '"name"' "${AGENTS_FILE}" 2>/dev/null | wc -l)
    local component_count=$(grep -o '"name"' "${SBOM_FILE}" 2>/dev/null | wc -l)
    local mcp_count=$(perl -nle 'print $1 if /"total_servers"\s*:\s*([0-9]+)/' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null || echo "0")
    local script_count=$(grep -o '"path"' "${SCRIPTS_FILE}" 2>/dev/null | wc -l)
    local skills_file="${OUTPUT_DIR}/skills.json"
    local skills_count=$(perl -nle 'print $1 if /"total_skills"\s*:\s*([0-9]+)/' "${skills_file}" 2>/dev/null || echo "0")
    local api_configs_count=$(perl -nle 'print $1 if /"total_configs"\s*:\s*([0-9]+)/' "${api_configs_file}" 2>/dev/null || echo "0")

    cat > "${summary_csv}" << EOF
指标，数值
审计时间,$(date '+%Y-%m-%d %H:%M:%S')
发现 Agent 数量，${agent_count}
MCP 服务器数量，${mcp_count}
组件数量，${component_count}
脚本数量，${script_count}
Skills/Plugins数量，${skills_count}
API 配置数量，${api_configs_count}
漏洞总数，${total_vulns}
严重漏洞，${critical_count}
高危漏洞，${high_count}
中危漏洞，${medium_count}
EOF

    log "INFO" "Excel 报告已生成：${excel_dir}/ (共 8 个 CSV 文件)"
}

# ============================================================================
# 生成知识图谱 (纯 Bash)
# ============================================================================
generate_knowledge_graph() {
    log "INFO" "生成知识图谱..."

    # 生成节点数据
    local nodes=""
    local agent_count=0
    local vuln_count=0
    local mcp_count=0

    # 主机节点（根节点）
    nodes+="{id:\"host\",name:\"${HOST_NAME}\\n${HOST_IP}\",category:3,symbolSize:50},"

    # Agent 节点
    while IFS= read -r line; do
        local agent_id=$(echo "${line}" | json_extract_value "agent_id")
        local name=$(echo "${line}" | json_extract_value "name")
        [[ -n "${name}" ]] && nodes+="{id:\"${agent_id}\",name:\"${name}\",category:0,symbolSize:30},"
        ((agent_count++))
    done < <(grep -o '{[^{}]*"agent_id"[^{}]*}' "${AGENTS_FILE}" 2>/dev/null)

    # MCP 服务器节点（去重）
    if [[ -f "${OUTPUT_DIR}/mcp_servers.json" ]]; then
        local processed_mcps=""
        while IFS= read -r line; do
            local mcp_name=$(echo "${line}" | json_extract_value "name")
            [[ -z "${mcp_name}" ]] && continue

            # 跳过已处理的 MCP 名称（使用字符串检查代替关联数组）
            if [[ "${processed_mcps}" == *"|${mcp_name}|"* ]]; then
                continue
            fi
            processed_mcps+="|${mcp_name}|"

            local mcp_id="mcp_${mcp_name//[^a-zA-Z0-9]/_}"
            nodes+="{id:\"${mcp_id}\",name:\"${mcp_name}\",category:4,symbolSize:20},"
            ((mcp_count++))
        done < <(grep -o '{[^{}]*"name"[^{}]*}' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null)
    fi

    # 漏洞节点（去重）
    local processed_cves=""
    while IFS= read -r line; do
        local cve=$(echo "${line}" | json_extract_value "cve_id")
        local sev=$(echo "${line}" | json_extract_value "severity")
        [[ -z "${cve}" ]] && continue

        # 跳过已处理的 CVE（使用字符串检查）
        if [[ "${processed_cves}" == *"|${cve}|"* ]]; then
            continue
        fi
        processed_cves+="|${cve}|"

        local category=2
        [[ "${sev}" == "CRITICAL" || "${sev}" == "HIGH" ]] && category=1
        nodes+="{id:\"${cve}\",name:\"${cve}\",category:${category},symbolSize:15},"
        ((vuln_count++))
    done < <(grep -o '{[^{}]*"cve_id"[^{}]*}' "${VULN_FILE}" 2>/dev/null)

    # 生成链接关系
    local links=""

    # 主机 -> Agent 链接
    while IFS= read -r line; do
        local agent_id=$(echo "${line}" | json_extract_value "agent_id")
        [[ -n "${agent_id}" ]] && links+="{source:\"host\",target:\"${agent_id}\"},"
    done < <(grep -o '{[^{}]*"agent_id"[^{}]*}' "${AGENTS_FILE}" 2>/dev/null)

    # Agent -> MCP 链接（根据配置文件路径关联，去重）
    if [[ -f "${OUTPUT_DIR}/mcp_servers.json" ]]; then
        local processed_mcp_links=""
        while IFS= read -r line; do
            local mcp_name=$(echo "${line}" | json_extract_value "name")
            local source=$(echo "${line}" | json_extract_value "source")
            [[ -z "${mcp_name}" ]] && continue

            # 跳过已处理的 MCP 链接
            if [[ "${processed_mcp_links}" == *"|${mcp_name}|"* ]]; then
                continue
            fi
            processed_mcp_links+="|${mcp_name}|"

            local mcp_id="mcp_${mcp_name//[^a-zA-Z0-9]/_}"
            local target_agent=""

            # 根据 source 路径判断属于哪个 Agent
            if [[ "${source}" == *".claude"* ]]; then
                target_agent="${AGENT_ID_MAP[claude]:-}"
            elif [[ "${source}" == *".cursor"* ]]; then
                target_agent="${AGENT_ID_MAP[cursor]:-}"
            elif [[ "${source}" == *".openclaw"* ]]; then
                # OpenClaw 有多个 agent，取第一个
                for key in "${!AGENT_ID_MAP[@]}"; do
                    if [[ "${key}" == "openclaw"* ]]; then
                        target_agent="${AGENT_ID_MAP[${key}]}"
                        break
                    fi
                done
            elif [[ "${source}" == *".nanobot"* ]]; then
                target_agent="${AGENT_ID_MAP[nanobot]:-}"
            fi

            if [[ -n "${target_agent}" ]]; then
                links+="{source:\"${target_agent}\",target:\"${mcp_id}\"},"
            else
                # 没有明确 Agent 的 MCP，连接到主机
                links+="{source:\"host\",target:\"${mcp_id}\"},"
            fi
        done < <(grep -o '{[^{}]*"name"[^{}]*}' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null)
    fi

    # Agent -> 漏洞链接（去重）
    local processed_cve_links=""
    while IFS= read -r line; do
        local cve=$(echo "${line}" | json_extract_value "cve_id")
        [[ -z "${cve}" ]] && continue

        # 跳过已处理的 CVE 链接
        if [[ "${processed_cve_links}" == *"|${cve}|"* ]]; then
            continue
        fi
        processed_cve_links+="|${cve}|"

        # 连接到第一个 Agent
        local first_agent=$(perl -nle 'print $1 if /"agent_id"\s*:\s*"([^"]+)"/' "${AGENTS_FILE}" 2>/dev/null | head -1)
        if [[ -n "${first_agent}" ]]; then
            links+="{source:\"${first_agent}\",target:\"${cve}\"},"
        fi
    done < <(grep -o '{[^{}]*"cve_id"[^{}]*}' "${VULN_FILE}" 2>/dev/null)

    # 生成 HTML
    cat > "${GRAPH_FILE}" << HTMLEOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Agent 安全知识图谱 - ${HOST_NAME}</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #1a1a2e; }
        #chart { width: 100vw; height: 100vh; }
        .legend { position: absolute; top: 20px; left: 20px; background: rgba(255,255,255,0.9); padding: 20px; border-radius: 10px; z-index: 1000; }
        .legend h3 { color: #1a1a2e; margin-bottom: 10px; }
        .legend-item { display: flex; align-items: center; margin: 8px 0; }
        .legend-color { width: 16px; height: 16px; border-radius: 3px; margin-right: 10px; }
        .host-info { position: absolute; top: 20px; right: 20px; background: rgba(255,255,255,0.9); padding: 15px; border-radius: 10px; z-index: 1000; }
        .host-info h3 { color: #1a1a2e; margin-bottom: 8px; font-size: 14px; }
        .host-info p { color: #333; margin: 4px 0; font-size: 12px; }
    </style>
</head>
<body>
    <div id="chart"></div>
    <div class="legend">
        <h3>图例</h3>
        <div class="legend-item"><div class="legend-color" style="background:#2196f3"></div>主机 (${HOST_NAME})</div>
        <div class="legend-item"><div class="legend-color" style="background:#ffffff"></div>AI Agent (${agent_count})</div>
        <div class="legend-item"><div class="legend-color" style="background:#9c27b0"></div>MCP 服务器 (${mcp_count})</div>
        <div class="legend-item"><div class="legend-color" style="background:#dc3545"></div>严重/高危漏洞</div>
        <div class="legend-item"><div class="legend-color" style="background:#ffc107"></div>其他漏洞</div>
    </div>
    <div class="host-info">
        <h3>主机信息</h3>
        <p><strong>主机名:</strong> ${HOST_NAME}</p>
        <p><strong>IP:</strong> ${HOST_IP}</p>
        <p><strong>Agent:</strong> ${agent_count}</p>
        <p><strong>MCP:</strong> ${mcp_count}</p>
        <p><strong>漏洞:</strong> ${vuln_count}</p>
    </div>
    <script>
        const chart = echarts.init(document.getElementById('chart'));

        const nodes = [${nodes}];
        const links = [${links}];

        const option = {
            series: [{
                type: 'graph',
                layout: 'force',
                data: nodes,
                links: links,
                categories: [
                    {name:'AI Agent',itemStyle:{color:'#ffffff'}},
                    {name:'高危漏洞',itemStyle:{color:'#dc3545'}},
                    {name:'其他漏洞',itemStyle:{color:'#ffc107'}},
                    {name:'主机',itemStyle:{color:'#2196f3'}},
                    {name:'MCP 服务器',itemStyle:{color:'#9c27b0'}}
                ],
                roam: true,
                label: {
                    show: true,
                    position: 'right',
                    formatter: '{b}'
                },
                force: {
                    repulsion: 400,
                    edgeLength: 80,
                    gravity: 0.15
                },
                lineStyle: {
                    color: 'source',
                    curveness: 0.3,
                    opacity: 0.7
                },
                emphasis: {
                    focus: 'adjacency'
                }
            }]
        };

        chart.setOption(option);

        window.addEventListener('resize', function() {
            chart.resize();
        });

        // 点击事件
        chart.on('click', function(params) {
            if (params.data) {
                console.log('点击：', params.data.name, params.data);
            }
        });
    </script>
</body>
</html>
HTMLEOF

    log "INFO" "知识图谱已生成：${GRAPH_FILE}"
}

# ============================================================================
# 主函数
# ============================================================================
main() {
    echo ""
    echo "=============================================="
    echo "    AI Agent Security Auditor v2.4.0"
    echo "    (Pure Bash Implementation)"
    echo "=============================================="
    echo ""

    # 创建输出目录
    create_output_dir

    # 步骤 0: 采集主机信息
    collect_host_info

    # 步骤 1: 发现 Agent
    discover_ai_agents

    # 步骤 2: 提取 MCP 配置
    extract_mcp_config

    # 步骤 3: 提取 Skills
    extract_skills

    # 步骤 4: 提取 API 配置
    extract_api_configs

    # 步骤 5: 扫描脚本
    scan_scripts

    # 步骤 6: 生成 SBOM
    generate_sbom

    # 步骤 7: CVE 分析
    analyze_cve

    # 步骤 8: 生成报告
    generate_html_report
    generate_excel_report
    generate_knowledge_graph

    # 输出摘要
    echo ""
    echo "=============================================="
    echo "              审计完成"
    echo "=============================================="
    echo ""
    echo "主机信息:"
    echo "  - 主机名：${HOST_NAME}"
    echo "  - IP 地址：${HOST_IP}"
    echo ""
    echo "输出目录：${OUTPUT_DIR}"
    echo ""
    echo "生成文件:"
    echo "  - 安全报告 (HTML): ${REPORT_FILE}"
    echo "  - Excel 报告 (CSV): ${OUTPUT_DIR}/excel_reports/"
    echo "  - 知识图谱：${GRAPH_FILE}"
    echo "  - SBOM 清单：${SBOM_FILE}"
    echo "  - 漏洞数据：${VULN_FILE}"
    echo "  - Agent 列表：${AGENTS_FILE}"
    echo "  - 脚本列表：${SCRIPTS_FILE}"
    echo "  - MCP 服务器：${OUTPUT_DIR}/mcp_servers.json"
    echo "  - MCP 配置文件：${OUTPUT_DIR}/mcp_files.json"
    echo "  - MCP 进程：${OUTPUT_DIR}/mcp_processes.json"
    echo "  - Skills: ${OUTPUT_DIR}/skills.json"
    echo "  - API 配置：${OUTPUT_DIR}/api_configs.json"
    echo "  - 审计日志：${LOG_FILE}"
    echo ""

    # 显示 MCP 服务器摘要
    if [[ -f "${OUTPUT_DIR}/mcp_servers.json" ]]; then
        echo "MCP 服务器统计:"
        local mcp_total=$(perl -nle 'print $1 if /"total_servers"\s*:\s*([0-9]+)/' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null || echo "0")
        local mcp_files=$(perl -nle 'print $1 if /"config_files"\s*:\s*([0-9]+)/' "${OUTPUT_DIR}/mcp_servers.json" 2>/dev/null || echo "0")
        echo "  - MCP 服务器：${mcp_total}"
        echo "  - 配置文件：${mcp_files}"
        echo ""
    fi

    # 显示漏洞摘要
    if [[ -f "${VULN_FILE}" ]]; then
        echo "漏洞统计:"
        local total=$(perl -nle 'print $1 if /"total_vulnerabilities"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
        local critical=$(perl -nle 'print $1 if /"critical_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
        local high=$(perl -nle 'print $1 if /"high_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
        local medium=$(perl -nle 'print $1 if /"medium_count"\s*:\s*([0-9]+)/' "${VULN_FILE}" 2>/dev/null || echo "0")
        echo "  - 严重：${critical}"
        echo "  - 高危：${high}"
        echo "  - 中危：${medium}"
        echo "  - 总计：${total}"
    fi

    echo ""
    echo "=============================================="
    log "INFO" "审计完成!"
}

# 运行主函数
main "$@"
