#!/usr/bin/env python3
"""
lz-skill-vetter-plus v2.1.0 — 自动化审计器
三维度扫描：安全 / 性能 / 质量
输出：人类可读报告 + JSON（机器可消费）

用法：
  python3 audit.py <path-to-skill>                    # 文本报告
  python3 audit.py <path-to-skill> --format json      # JSON 报告
  python3 audit.py <path-to-skill> --severity high    # 仅高危及以上
  python3 audit.py <path-to-skill> --exit-code        # 退出码反映严重程度
  python3 audit.py <path-to-skill> --quiet            # 仅 JSON 到 stdout

退出码：
  0 = clean（无 critical/high 命中）
  1 = warning（有 medium 命中）
  2 = fail（有 critical/high 命中）

设计原则：
- 仅依赖 PyYAML（python3 -c "import yaml"）和 Python 标准库
- 所有严重度阈值可在 patterns/red_flags.yml 调整
- 扫描结果可被 CI 直接消费
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


# ─────────────────────────────────────────────────────────────
# 严重程度排序
# ─────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
SEVERITY_EXIT = {"critical": 2, "high": 2, "medium": 1, "low": 0, "info": 0}


# ─────────────────────────────────────────────────────────────
# 文件加载
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
PATTERNS_FILE = SCRIPT_DIR / "patterns" / "red_flags.yml"


def load_patterns() -> dict:
    """加载模式库（red_flags.yml）。"""
    if not PATTERNS_FILE.exists():
        sys.exit(f"❌ 模式库不存在: {PATTERNS_FILE}")
    try:
        with PATTERNS_FILE.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        sys.exit(f"❌ 模式库 YAML 解析失败:\n{e}")
    return data


# ─────────────────────────────────────────────────────────────
# 扫描器：安全 + 凭据 + 网络 + 系统
# ─────────────────────────────────────────────────────────────
def scan_security(skill_path: Path, patterns: dict) -> list:
    """扫描安全红线（24 条）。"""
    findings = []
    sec = patterns["security"]
    groups = sec["groups"]

    # 收集目标文件（跳过 patterns/ 目录避免自指）
    target_files = []
    for ext in ["*.sh", "*.py", "*.js", "*.ts", "*.mjs", "*.cjs", "*.md", "*.yaml", "*.yml"]:
        for f in skill_path.rglob(ext):
            # 跳过模式定义目录（避免审计器自指）
            if "scripts/patterns/" in str(f) or "/scripts/patterns/" in str(f):
                continue
            # 跳过审计器自身（自扫描时会产生大量自身代码命中）
            if f.name == "audit.py":
                continue
            target_files.append(f)

    for f in target_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            findings.append({
                "id": "SEC-IO-001",
                "severity": "low",
                "category": "io_error",
                "name": "文件读取失败",
                "file": str(f.relative_to(skill_path)),
                "line": 0,
                "match": str(e),
                "context": "",
            })
            continue

        # 检测代码块区域（markdown ``` / 代码内的示例不视为真实代码）
        in_code_block = False

        for line_no, line in enumerate(text.splitlines(), start=1):
            # 跟踪 markdown 代码块状态
            stripped = line.strip()
            if f.suffix == ".md" and stripped.startswith("```"):
                in_code_block = not in_code_block
                continue

            # 代码块内的行跳过（文档示例不是真实代码）
            if in_code_block:
                continue

            # 跳过纯注释行（仅代码文件，markdown 中 # 是标题）
            if f.suffix in (".py", ".sh", ".yaml", ".yml", ".js", ".ts", ".mjs", ".cjs"):
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

            # markdown 文件特殊处理
            if f.suffix == ".md":
                # 标题（# ## ###）是结构标记，不含代码
                if stripped.startswith("#"):
                    continue
                # 表格行（文档描述而非真实代码）
                if stripped.startswith("|") or stripped.endswith("|") or " | " in stripped:
                    continue
                # markdown 注释豁免 <!-- safe-pattern: ... -->
                if "<!-- safe-pattern" in line:
                    continue

            for group in groups:
                # 检查 file_glob 过滤
                file_globs = group.get("file_glob")
                if file_globs:
                    if not any(fnmatch.fnmatch(f.name, g) for g in file_globs):
                        continue

                # 编译正则
                try:
                    regex = re.compile(group["regex"])
                except re.error as e:
                    findings.append({
                        "id": group["id"] + "-REGEX",
                        "severity": "low",
                        "category": "config_error",
                        "name": f"模式 {group['id']} 正则错误",
                        "file": "<patterns/red_flags.yml>",
                        "line": 0,
                        "match": str(e),
                        "context": group.get("regex", "")[:80],
                    })
                    continue

                m = regex.search(line)
                if not m:
                    continue

                # 检查 exception_pattern 豁免
                exc_pat = group.get("exception_pattern")
                if exc_pat:
                    try:
                        if re.search(exc_pat, line):
                            continue
                    except re.error:
                        pass

                # 检查 safe-pattern: 注释豁免（同行出现即豁免）
                if "# safe-pattern:" in line or "// safe-pattern:" in line:
                    continue

                findings.append({
                    "id": group["id"],
                    "severity": group["severity"],
                    "category": group["category"],
                    "name": group["name"],
                    "file": str(f.relative_to(skill_path)),
                    "line": line_no,
                    "match": m.group(0)[:80],
                    "context": line.strip()[:120],
                    "description": group.get("description", ""),
                })

    return findings


# ─────────────────────────────────────────────────────────────
# 扫描器：性能
# ─────────────────────────────────────────────────────────────
def scan_performance(skill_path: Path, patterns: dict) -> list:
    """扫描性能指标（5 条）。"""
    findings = []
    metrics = patterns["performance"]["metrics"]
    skill_md = skill_path / "SKILL.md"

    for metric in metrics:
        target = metric.get("target", "SKILL.md")
        max_lines = metric.get("max_lines")
        max_chars = metric.get("max_chars")
        field = metric.get("field")
        pattern = metric.get("pattern")
        max_lines_per_file = metric.get("max_lines_per_file")

        if target == "SKILL.md" and not skill_md.exists():
            continue

        if target == "SKILL.md":
            if max_lines:
                line_count = sum(1 for _ in skill_md.open(encoding="utf-8", errors="replace"))
                if line_count > max_lines:
                    findings.append({
                        "id": metric["id"],
                        "severity": metric["severity"],
                        "category": "performance",
                        "name": metric["name"],
                        "file": "SKILL.md",
                        "line": 0,
                        "match": f"{line_count} lines",
                        "context": metric.get("suggestion", metric.get("description", "")),
                        "description": metric["description"],
                    })

            if field == "description":
                # 解析 frontmatter 拿 description 字符数
                try:
                    text = skill_md.read_text(encoding="utf-8")
                    fm = parse_frontmatter(text)
                    desc = fm.get("description", "") if fm else ""
                    if len(desc) > max_chars:
                        findings.append({
                            "id": metric["id"],
                            "severity": metric["severity"],
                            "category": "performance",
                            "name": metric["name"],
                            "file": "SKILL.md",
                            "line": 1,
                            "match": f"{len(desc)} chars",
                            "context": metric.get("suggestion", metric.get("description", "")),
                            "description": metric["description"],
                        })
                except Exception:
                    pass

            if field == "body":
                try:
                    text = skill_md.read_text(encoding="utf-8")
                    body = strip_frontmatter(text)
                    if len(body) > max_chars:
                        findings.append({
                            "id": metric["id"],
                            "severity": metric["severity"],
                            "category": "performance",
                            "name": metric["name"],
                            "file": "SKILL.md",
                            "line": 0,
                            "match": f"{len(body)} chars",
                            "context": metric.get("suggestion", metric.get("description", "")),
                            "description": metric["description"],
                        })
                except Exception:
                    pass

        elif target == "references/" and max_lines_per_file:
            ref_dir = skill_path / "references"
            if ref_dir.exists():
                for f in ref_dir.rglob("*"):
                    if f.is_file():
                        try:
                            lc = sum(1 for _ in f.open(encoding="utf-8", errors="replace"))
                            if lc > max_lines_per_file:
                                findings.append({
                                    "id": metric["id"],
                                    "severity": metric["severity"],
                                    "category": "performance",
                                    "name": metric["name"],
                                    "file": str(f.relative_to(skill_path)),
                                    "line": 0,
                                    "match": f"{lc} lines",
                                    "context": metric.get("description", ""),
                                    "description": metric["description"],
                                })
                        except Exception:
                            pass

        elif target == "scripts/" and pattern:
            scripts_dir = skill_path / "scripts"
            if scripts_dir.exists():
                try:
                    rx = re.compile(pattern)
                except re.error:
                    rx = None
                if rx:
                    for f in scripts_dir.rglob("*"):
                        if f.is_file() and f.suffix in (".sh", ".py", ".js"):
                            try:
                                first_line = f.open(encoding="utf-8", errors="replace").readline()
                                if rx.search(first_line):
                                    findings.append({
                                        "id": metric["id"],
                                        "severity": metric["severity"],
                                        "category": "performance",
                                        "name": metric["name"],
                                        "file": str(f.relative_to(skill_path)),
                                        "line": 1,
                                        "match": first_line[:80],
                                        "context": metric.get("suggestion", metric.get("description", "")),
                                        "description": metric["description"],
                                    })
                            except Exception:
                                pass

    return findings


# ─────────────────────────────────────────────────────────────
# 扫描器：质量
# ─────────────────────────────────────────────────────────────
def parse_frontmatter(text: str) -> dict | None:
    """解析 SKILL.md 的 YAML frontmatter。"""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end == -1:
        return None
    fm_raw = text[4:end]
    try:
        return yaml.safe_load(fm_raw)
    except yaml.YAMLError:
        return None


def strip_frontmatter(text: str) -> str:
    """去掉 frontmatter 返回 body。"""
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---", 4)
    if end == -1:
        return text
    return text[end + 4:]


def scan_quality(skill_path: Path, patterns: dict) -> list:
    """扫描质量（9 条）。"""
    findings = []
    checks = patterns["quality"]["checks"]
    skill_md = skill_path / "SKILL.md"

    if not skill_md.exists():
        findings.append({
            "id": "QUAL-STRUCT-000",
            "severity": "high",
            "category": "quality",
            "name": "缺少 SKILL.md",
            "file": "SKILL.md",
            "line": 0,
            "match": "",
            "context": "",
            "description": "技能目录必须包含 SKILL.md",
        })
        return findings

    text = skill_md.read_text(encoding="utf-8")
    fm = parse_frontmatter(text)

    for check in checks:
        cid = check["id"]
        csev = check["severity"]

        # QUAL-FM-001 必填字段
        if cid == "QUAL-FM-001":
            if fm is None:
                findings.append({
                    "id": cid, "severity": csev, "category": "quality",
                    "name": check["name"], "file": "SKILL.md", "line": 1,
                    "match": "no frontmatter", "context": "",
                    "description": check["description"],
                })
            else:
                missing = [f for f in check["required_fields"] if f not in fm]
                if missing:
                    findings.append({
                        "id": cid, "severity": csev, "category": "quality",
                        "name": check["name"], "file": "SKILL.md", "line": 1,
                        "match": f"missing: {missing}", "context": str(fm)[:120],
                        "description": check["description"],
                    })

        # QUAL-FM-002 YAML 解析失败
        elif cid == "QUAL-FM-002":
            if not text.startswith("---\n"):
                findings.append({
                    "id": cid, "severity": csev, "category": "quality",
                    "name": check["name"], "file": "SKILL.md", "line": 0,
                    "match": "no --- delimiter", "context": "",
                    "description": check["description"],
                })
            else:
                end = text.find("\n---", 4)
                if end == -1:
                    findings.append({
                        "id": cid, "severity": csev, "category": "quality",
                        "name": check["name"], "file": "SKILL.md", "line": 0,
                        "match": "unclosed ---", "context": "",
                        "description": check["description"],
                    })
                else:
                    try:
                        yaml.safe_load(text[4:end])
                    except yaml.YAMLError as e:
                        findings.append({
                            "id": cid, "severity": csev, "category": "quality",
                            "name": check["name"], "file": "SKILL.md", "line": 0,
                            "match": str(e)[:80], "context": "",
                            "description": check["description"],
                        })

        # QUAL-FM-003 name 格式
        elif cid == "QUAL-FM-003":
            if fm and "name" in fm:
                name = str(fm["name"])
                if not re.match(check["regex_for_name"], name):
                    findings.append({
                        "id": cid, "severity": csev, "category": "quality",
                        "name": check["name"], "file": "SKILL.md", "line": 1,
                        "match": name, "context": "",
                        "description": check["description"],
                    })

        # QUAL-STRUCT-001 禁用文件
        elif cid == "QUAL-STRUCT-001":
            for forbidden in check["forbid_files"]:
                if (skill_path / forbidden).exists():
                    findings.append({
                        "id": cid, "severity": check["severity"], "category": "quality",
                        "name": check["name"], "file": forbidden, "line": 0,
                        "match": forbidden, "context": check.get("suggestion", ""),
                        "description": check["description"],
                    })

        # QUAL-STRUCT-002 scripts 可执行权限
        elif cid == "QUAL-STRUCT-002":
            scripts_dir = skill_path / "scripts"
            if scripts_dir.exists():
                for f in scripts_dir.rglob("*"):
                    if f.is_file() and f.suffix in (".sh", ".py", ".js"):
                        if not os.access(f, os.X_OK):
                            findings.append({
                                "id": cid, "severity": check["severity"], "category": "quality",
                                "name": check["name"], "file": str(f.relative_to(skill_path)), "line": 0,
                                "match": "not executable", "context": "",
                                "description": check["description"],
                            })

        # QUAL-STRUCT-003 license
        elif cid == "QUAL-STRUCT-003":
            has_license_meta = (skill_path / "_meta.json").exists() and "license" in (skill_path / "_meta.json").read_text(encoding="utf-8", errors="replace").lower()
            has_license_md = "license" in text.lower()  # 全文件扫描，不限 2000 字符
            if not (has_license_meta or has_license_md):
                findings.append({
                    "id": cid, "severity": check["severity"], "category": "quality",
                    "name": check["name"], "file": "SKILL.md", "line": 0,
                    "match": "no license", "context": "",
                    "description": check["description"],
                })

        # QUAL-DOC-001 代码块
        elif cid == "QUAL-DOC-001":
            if "```" not in text:
                findings.append({
                    "id": cid, "severity": check["severity"], "category": "quality",
                    "name": check["name"], "file": "SKILL.md", "line": 0,
                    "match": "no code block", "context": "",
                    "description": check["description"],
                })

        # QUAL-DOC-002 章节
        elif cid == "QUAL-DOC-002":
            section_name = check["section_name"]
            if section_name.lower() not in text.lower():
                findings.append({
                    "id": cid, "severity": check["severity"], "category": "quality",
                    "name": check["name"], "file": "SKILL.md", "line": 0,
                    "match": f"missing section: {section_name}", "context": "",
                    "description": check["description"],
                })

        # QUAL-DOC-003 description 词数
        elif cid == "QUAL-DOC-003":
            if fm and "description" in fm:
                desc = str(fm["description"])
                # 中文字符 + 英文单词（粗略）
                chinese_chars = sum(1 for c in desc if '\u4e00' <= c <= '\u9fff')
                english_words = len(re.findall(r'\b[a-zA-Z]+\b', desc))
                if chinese_chars < 12 and english_words < check["min_words"]:
                    findings.append({
                        "id": cid, "severity": check["severity"], "category": "quality",
                        "name": check["name"], "file": "SKILL.md", "line": 1,
                        "match": f"cn={chinese_chars} en={english_words}", "context": desc[:80],
                        "description": check["description"],
                    })

    return findings


# ─────────────────────────────────────────────────────────────
# 报告聚合
# ─────────────────────────────────────────────────────────────
def apply_severity_cap(skill_path: Path, findings: list) -> tuple[str | None, int]:
    """
    检查 SKILL.md frontmatter 是否有 severity-cap / engine-class 字段。
    如果有，将所有超过 cap 的 finding 降级到 cap。

    返回 (cap_value, downgraded_count)。

    用法（SKILL.md）:
        ---
        name: my-skill
        severity-cap: medium  # critical/high → medium
        ---

    或:
        ---
        name: my-skill
        engine-class: true  # shorthand = severity-cap: high
        ---
    """
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        return None, 0

    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None, 0

    fm = parse_frontmatter(text)
    if not fm:
        return None, 0

    # engine-class: true 是 severity-cap: high 的简写
    cap = None
    if fm.get("engine-class") is True or fm.get("engine-class") == "true":
        cap = "high"
    if "severity-cap" in fm:
        cap_val = str(fm["severity-cap"]).lower()
        if cap_val in SEVERITY_ORDER:
            cap = cap_val

    if not cap:
        return None, 0

    # 应用降级
    cap_rank = SEVERITY_ORDER[cap]
    downgraded = 0
    for f in findings:
        if SEVERITY_ORDER[f["severity"]] > cap_rank:
            old_severity = f["severity"]
            f["severity"] = cap
            f["original_severity"] = f.get("original_severity", old_severity)
            downgraded += 1

    return cap, downgraded


def build_report(skill_path: Path, findings: list, patterns: dict) -> dict:
    """构建完整审计报告。"""
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    # 计算 verdict
    if by_severity["critical"] > 0:
        verdict = "❌ DO NOT INSTALL"
        emoji = "⛔"
    elif by_severity["high"] > 0:
        verdict = "⚠️ INSTALL WITH CAUTION"
        emoji = "🔴"
    elif by_severity["medium"] > 0:
        verdict = "⚠️ REVIEW MEDIUM ISSUES"
        emoji = "🟡"
    elif by_severity["low"] + by_severity["info"] > 0:
        verdict = "✅ SAFE TO INSTALL (minor notes)"
        emoji = "🟢"
    else:
        verdict = "✅ SAFE TO INSTALL"
        emoji = "🟢"

    # 统计文件
    files_scanned = set(f["file"] for f in findings if f["file"])
    total_lines = 0
    for ext in ["*.sh", "*.py", "*.js", "*.md", "*.yaml", "*.yml"]:
        for f in skill_path.rglob(ext):
            try:
                total_lines += sum(1 for _ in f.open(encoding="utf-8", errors="replace"))
            except Exception:
                pass

    return {
        "schema_version": "2.0",
        "scanner": "lz-skill-vetter-plus",
        "scanner_version": "2.1.0",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "skill_path": str(skill_path.resolve()),
        "skill_name": skill_path.name,
        "summary": {
            "files_scanned": len(files_scanned),
            "total_lines_scanned": total_lines,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_category": _count_by(findings, "category"),
        },
        "findings": findings,
        "verdict": f"{emoji} {verdict}",
        "verdict_code": "fail" if by_severity["critical"] > 0 else (
            "caution" if by_severity["high"] > 0 else (
                "review" if by_severity["medium"] > 0 else "ok"
            )
        ),
    }


def build_report_with_cap(skill_path: Path, findings: list, patterns: dict) -> dict:
    """构建报告，先应用 severity-cap 降级。"""
    cap, downgraded = apply_severity_cap(skill_path, findings)
    report = build_report(skill_path, findings, patterns)
    if cap:
        report["severity_cap_applied"] = cap
        report["severity_cap_downgraded_count"] = downgraded
    return report


def _count_by(items: list, key: str) -> dict:
    counts = {}
    for item in items:
        v = item.get(key, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts


# ─────────────────────────────────────────────────────────────
# 输出：文本报告
# ─────────────────────────────────────────────────────────────
def render_text(report: dict, severity_filter: str | None = None) -> str:
    lines = []
    lines.append("═" * 60)
    lines.append(f"  SKILL VETTING REPORT (v{report['scanner_version']})")
    lines.append("═" * 60)
    lines.append(f"Skill:       {report['skill_name']}")
    lines.append(f"Path:        {report['skill_path']}")
    lines.append(f"Scan time:   {report['scan_time']}")
    lines.append("─" * 60)
    s = report["summary"]
    lines.append(f"Files scanned:  {s['files_scanned']}")
    lines.append(f"Lines scanned:  {s['total_lines_scanned']}")
    lines.append(f"Total findings: {s['total_findings']}")
    lines.append("By severity:")
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = s["by_severity"].get(sev, 0)
        emoji = SEVERITY_EMOJI[sev]
        lines.append(f"  {emoji} {sev:10s} {cnt}")
    lines.append("By category:")
    for cat, cnt in sorted(s["by_category"].items(), key=lambda x: -x[1]):
        lines.append(f"  {cat:30s} {cnt}")
    lines.append("─" * 60)
    lines.append(f"VERDICT: {report['verdict']}")
    lines.append("─" * 60)

    findings = report["findings"]
    if severity_filter:
        threshold = SEVERITY_ORDER[severity_filter]
        findings = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= threshold]

    if findings:
        lines.append(f"\nFINDINGS ({len(findings)}):\n")
        # 按严重度排序
        findings_sorted = sorted(findings, key=lambda f: -SEVERITY_ORDER[f["severity"]])
        for f in findings_sorted:
            emoji = SEVERITY_EMOJI[f["severity"]]
            lines.append(f"{emoji} [{f['severity'].upper():8s}] {f['id']:18s} {f['name']}")
            lines.append(f"   File: {f['file']}:{f['line']}")
            if f.get("match"):
                lines.append(f"   Match: {f['match']}")
            if f.get("context"):
                lines.append(f"   Context: {f['context']}")
            if f.get("description"):
                lines.append(f"   Why: {f['description']}")
            lines.append("")

    lines.append("═" * 60)
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="lz-skill-vetter-plus v2.1.0 — OpenClaw 技能自动化审计器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python3 audit.py /path/to/skill
  python3 audit.py /path/to/skill --format json
  python3 audit.py /path/to/skill --severity high
  python3 audit.py /path/to/skill --exit-code   # CI 友好
        """,
    )
    parser.add_argument("skill_path", help="技能目录路径")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="输出格式（默认 text）")
    parser.add_argument("--severity", choices=list(SEVERITY_ORDER),
                        help="最低严重度过滤（如 high = critical + high）")
    parser.add_argument("--exit-code", action="store_true",
                        help="退出码反映严重程度（CI 用）")
    parser.add_argument("--quiet", action="store_true",
                        help="仅输出 JSON 到 stdout，无 banner")
    args = parser.parse_args()

    skill_path = Path(args.skill_path)
    if not skill_path.exists():
        sys.exit(f"❌ 路径不存在: {skill_path}")
    if not skill_path.is_dir():
        sys.exit(f"❌ 不是目录: {skill_path}")

    patterns = load_patterns()

    # 三维度扫描
    sec_findings = scan_security(skill_path, patterns)
    perf_findings = scan_performance(skill_path, patterns)
    qual_findings = scan_quality(skill_path, patterns)

    all_findings = sec_findings + perf_findings + qual_findings
    report = build_report_with_cap(skill_path, all_findings, patterns)

    # 输出
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_text(report, args.severity))

    # 退出码
    if args.exit_code:
        max_severity = "info"
        for sev, cnt in report["summary"]["by_severity"].items():
            if cnt > 0 and SEVERITY_ORDER[sev] > SEVERITY_ORDER[max_severity]:
                max_severity = sev
        sys.exit(SEVERITY_EXIT[max_severity])

    sys.exit(0)


if __name__ == "__main__":
    main()