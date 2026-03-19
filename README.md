# AI Agent Security Auditor

AI Agent 安全审计工具 - 纯 Bash 实现，用于扫描本地 AI Agent 程序、分析配置、检测漏洞并生成审计报告。

## 功能特性

- AI Agent 程序发现（支持 openclaw, opencode, claude, claude-code, nanobot 等）
- MCP 服务器配置提取
- Skills/Plugins 列表扫描
- **API Key 配置检测**（新增：扫描各 Agent 的 API Key、Base URL、Model 配置）
- 可执行脚本文件识别（.sh, .py, .js）
- SBOM (Software Bill of Materials) 生成
- CVE 漏洞分析（内置 60+ 漏洞数据库）
- HTML 可视化审计报告
- Excel CSV 格式报告（8 个报表文件）
- 知识图谱可视化

## 系统要求

- Linux 操作系统
- Bash 4.0+
- 标准 GNU 工具集（find, grep, sed, awk, curl）
- 可选：npm（扫描 NPM 包）
- 可选：pip3（扫描 Python 包）
- 可选：dpkg-query（扫描系统包）

## 快速开始

### 1. 克隆/下载脚本

```bash
cd /opt/aivul/aicheck
```

### 2. 赋予执行权限

```bash
linux：
chmod +x ai_agent_security_audit_linux.sh
macos：
chmod +x ai_agent_security_audit.sh
```

### 3. 运行审计

```bash
linux
./ai_agent_security_audit_linux.sh
macos
./ai_agent_security_audit.sh
```

### 4. 查看结果

审计完成后，输出目录将包含所有报告文件：

```bash
# 在浏览器中打开 HTML 报告
firefox audit_output_*/security_report.html

# 查看知识图谱
firefox audit_output_*/knowledge_graph.html
```

## 输出文件

| 文件 | 说明 |
|------|------|
| `security_report.html` | HTML 可视化审计报告 |
| `knowledge_graph.html` | 知识图谱（ECharts 可视化） |
| `excel_reports/00_summary.csv` | 审计摘要汇总 |
| `excel_reports/01_vulnerabilities.csv` | 漏洞详情表 |
| `excel_reports/02_agents.csv` | AI Agent 列表 |
| `excel_reports/03_mcp_servers.csv` | MCP 服务器配置 |
| `excel_reports/04_scripts.csv` | 可执行脚本清单 |
| `excel_reports/05_sbom_components.csv` | SBOM 组件清单 |
| `excel_reports/06_skills.csv` | Skills/Plugins 清单 |
| `excel_reports/07_api_configs.csv` | API 配置清单（新增） |
| `sbom.json` | SBOM 组件清单（CycloneDX 格式） |
| `vulnerabilities.json` | 漏洞详情数据 |
| `agents.json` | 发现的 AI Agent 列表 |
| `scripts.json` | 可执行脚本列表 |
| `mcp_servers.json` | MCP 服务器配置 |
| `mcp_files.json` | MCP 配置文件列表 |
| `mcp_processes.json` | 运行中的 MCP 进程 |
| `skills.json` | Skills/Plugins 列表 |
| `api_configs.json` | API 配置列表（新增） |
| `audit.log` | 审计日志 |

## 审计指标示例

```
==============================================
              审计完成
==============================================

输出目录：/opt/aivul/aicheck/audit_output_20260314_072228

MCP 服务器统计:
  - MCP 服务器：6
  - 配置文件：15

漏洞统计:
  - 严重：2
  - 高危：2
  - 中危：2
  - 总计：6
```

## 支持的 AI Agent

| 名称 | 检测方式 |
|------|----------|
| openclaw | 命令、目录、NPM 包 |
| opencode | 命令、目录、NPM 包 |
| claude | 命令、目录、NPM 包 |
| claude-code | 命令、NPM 包 |
| cline | 命令 |
| aider | 命令、Python 包 |
| ollama | 命令、Python 包 |
| llama | Python 包 |
| zed | 命令 |
| cursor | 命令 |
| nanobot | 命令、目录、NPM 包 |

## 支持的 MCP 配置

### MCP 配置文件搜索机制

脚本使用 **全系统扫描 + 去重** 机制发现 MCP 配置文件：

1. **标准路径搜索**: 预定义的 Claude、Cursor、VSCode、Windsurf 配置路径
2. **全系统扫描**: 使用 `find / | grep mcp` 扫描整个文件系统
3. **内容验证**: 检查文件是否包含 MCP 相关 JSON 字段
4. **智能去重**: 自动跳过重复文件和大文件 (>1MB)

### 支持的配置格式

| 类型 | 文件路径 |
|------|----------|
| Claude MCP | `~/.claude/mcp.json`, `~/.claude/mcp_config.json` |
| Cursor MCP | `~/.cursor/mcp.json`, `~/.cursor/mcp_config.json` |
| VSCode MCP | `~/.vscode/mcp.json` |
| Windsurf MCP | `~/.codeium/windsurf/mcp.json` |
| 插件 MCP | `**/.mcp.json` (全系统搜索) |
| Mcporter | `~/.mcporter/mcporter.json` |

## 内置漏洞检测

脚本内置 60+ 条目的漏洞数据库，涵盖以下组件：

### Python 包漏洞
| 组件 | 漏洞 | 严重性 | 风险标识 |
|------|------|--------|----------|
| Pillow | CVE-2023-50447 (RCE) | CRITICAL | RCE, SHELL_INJECTION |
| Pillow | CVE-2024-3968 | HIGH | - |
| urllib3 | CVE-2023-43804 | HIGH | - |
| urllib3 | CVE-2024-37890 | HIGH | - |
| requests | CVE-2023-32681 | MEDIUM | - |
| Jinja2 | CVE-2024-22195 | HIGH | - |
| Jinja2 | CVE-2024-34069 (沙盒逃逸) | HIGH | RCE |
| PyYAML | CVE-2020-14343 | CRITICAL | RCE, SHELL_INJECTION |
| django | CVE-2024-24680 | HIGH | - |
| cryptography | CVE-2023-49083 | CRITICAL | - |
| lxml | CVE-2024-34575 | HIGH | - |
| pip | CVE-2024-6345 | HIGH | RCE |

### Node.js 包漏洞
| 组件 | 漏洞 | 严重性 | 风险标识 |
|------|------|--------|----------|
| lodash | CVE-2021-23337 | HIGH | - |
| express | CVE-2024-29041 | HIGH | - |
| node | CVE-2024-27980 (Windows 提权) | HIGH | RCE |
| axios | CVE-2023-45857 | HIGH | - |

### 系统组件漏洞
| 组件 | 漏洞 | 严重性 | 风险标识 |
|------|------|--------|----------|
| git | CVE-2024-32002 | CRITICAL | RCE, SHELL_INJECTION |
| git | CVE-2024-32004 | HIGH | RCE |
| curl | CVE-2024-23791 | HIGH | - |
| openssh | CVE-2024-6387 (regreSSHion) | CRITICAL | RCE |
| sudo | CVE-2023-22809 | CRITICAL | RCE |
| openssl | CVE-2024-0727 | HIGH | - |

## 扩展漏洞库

编辑脚本中的 `analyze_cve()` 函数，添加更多漏洞条目：

```bash
local vuln_db=(
    "组件名|CVE-XXXX-XXXXX|严重性|CVSS|描述|CWE"
)
```

## 报告示例

### 统计卡片

- 严重漏洞（红色）
- 高危漏洞（橙色）
- 发现 Agent（绿色）
- 组件数量（青色）
- MCP 服务器（紫色）

### 漏洞详情

| CVE | 组件 | 严重性 | CVSS | 描述 | 风险标识 |
|-----|------|--------|------|------|----------|
| CVE-2023-50447 | pillow | CRITICAL | 9.8 | 远程代码执行 | RCE |
| CVE-2023-43804 | urllib3 | HIGH | 8.1 | Cookie 泄露 | - |

## 知识图谱

知识图谱使用 ECharts 力导向布局，支持：
- 拖拽节点
- 滚轮缩放
- 悬停高亮
- 点击查看详情

## Excel 报告

生成 6 个 CSV 格式报表文件，可用 Excel 直接打开：

1. **00_summary.csv** - 审计摘要汇总（漏洞统计、Agent 数量等）
2. **01_vulnerabilities.csv** - 完整漏洞详情表
3. **02_agents.csv** - AI Agent 列表及路径
4. **03_mcp_servers.csv** - MCP 服务器配置详情
5. **04_scripts.csv** - 可执行脚本清单
6. **05_sbom_components.csv** - SBOM 组件清单

## 自定义配置

### 添加新的 Agent 检测

编辑 `discover_ai_agents()` 函数：

```bash
for cmd in 新 Agent 名称; do
    if command -v "${cmd}" &>/dev/null; then
        # 检测逻辑
    fi
done
```

### 修改输出目录

```bash
OUTPUT_DIR="${SCRIPT_DIR}/自定义输出目录"
```

### 添加 CVE 检测

```bash
local vuln_db=(
    "新组件 |CVE-XXXX-XXXXX|SEVERITY|CVSS|描述|CWE"
)
```

## 安全说明

- 本工具仅用于本地安全审计
- 不会向外部发送任何数据
- 漏洞检测基于已知 CVE 数据库
- 建议定期更新漏洞库

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v2.4.1
- **修复知识图谱 ECharts 错误**: 修复浏览器控制台报错 "Cannot set properties of undefined (setting 'dataIndex')"
  - 修正节点 category 值与 categories 数组索引的匹配问题
  - 主机节点：category 4→3
  - MCP 服务器：category 5→4
  - 严重/高危漏洞：category 2→1
  - 其他漏洞：category 3→2

### v2.4.0
- **主机信息采集**: 新增 `collect_host_info()` 函数，采集主机名和 IP 地址
- **Agent 主机关联**: agents.json 和 02_agents.csv 添加 hostname 字段
- **知识图谱增强**: 以主机为根节点构建树状结构，主机→Agent→MCP/漏洞
- **HTML 报告增强**: 添加主机信息统计卡片，Agent 表格添加主机名列
- **图谱可视化**: 新增主机节点类别，显示主机信息和关联关系

### v2.3.1
- **修复 base_url 和 model 字段提取**: 添加 `ANTHROPIC_BASE_URL` 和 `ANTHROPIC_MODEL` 到 grep 匹配模式，修复 Claude 配置文件中 base_url 和 model 字段为空的问题

### v2.3.0
- **API Key 配置检测**: 新增 `extract_api_configs()` 函数，扫描所有 Agent 的 API 配置
- **API 配置输出**: 生成 `api_configs.json` 和 `excel_reports/07_api_configs.csv`
- **HTML 报告增强**: 添加 API 配置统计卡片和详情表格
- **支持多 Agent**: 支持 Claude、OpenClaw、Opencode、Nanobot、Hagent 等 Agent 的 API 配置扫描
- **敏感信息脱敏**: API Key 在日志输出中自动脱敏（如 `sk-sp-***`）

### v2.2.0
- **Agent 唯一标识**: 为每个发现的 Agent 添加自增 ID（如 A000, A001）
- **Skills 关联扫描**: 扫描每个 Agent 的 Skills/Plugins，建立 Agent 与 Skills 的关联关系
- **MCP 影响分析**: MCP 服务器输出添加 `affected_agents` 字段，说明哪些 Agent 使用该服务器
- **漏洞影响分析**: 漏洞输出添加 `affected_agents` 字段，说明哪些 Agent 依赖的组件存在漏洞
- **SBOM 归属**: SBOM 组件添加 `agent_ids` 字段，说明组件属于哪个 Agent 或全局环境
- **脚本归属**: 可执行脚本添加 `agent_id` 和 `agent_name` 字段
- **HTML 报告增强**: 添加 Agent ID 列、影响 Agent 列和 Skills/Plugins 清单表格
- **CSV 报告增强**: 添加 `06_skills.csv`，所有报表增加 Agent 关联字段

### v2.1.2
- 修复 MCP 解析问题：支持 `{"mcpServers": {...}}` 嵌套格式
- 修复 `parse_mcporter_file()` 函数：正确处理多行 JSON 块
- 修复 `parse_plugin_mcp_file()` 函数：自动检测并委托 mcpServers 格式
- 统一输出格式：根据是否有 command 字段区分 remote/http 和 stdio 类型

### v2.1.1
- 增强 MCP 发现机制：全系统扫描 (`find / | grep mcp`)
- 智能去重：避免重复处理配置文件
- 文件验证：跳过 >1MB 文件，检查 MCP 相关字段
- 支持更多配置格式：Mcporter、测试夹具配置

### v2.1.0
- 新增 Excel CSV 报告生成功能（6 个报表文件）
- 漏洞数据库扩展至 60+ 条目
- 增强风险标识检测（RCE、SHELL_INJECTION、PRIVILEGE_ESCALATION）
- 按组件类型组织漏洞库（Python、Node.js、系统组件）

### v2.0.0
- 新增 MCP 服务器配置提取功能
- 支持多种 MCP 配置格式
- 新增 MCP 进程检测
- 增强 HTML 报告 MCP 服务器展示
- 纯 Bash 实现，无 Python 依赖

### v1.0.0
- 初始版本发布
