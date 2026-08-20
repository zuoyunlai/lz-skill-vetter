## Description: <br>
OpenClaw 技能自动化审计器 Pro v2.1.3 — 三维度扫描（安全/性能/质量），38 条规则，JSON 报告 + 退出码支持 CI 集成。v2.1.3 防「severity-cap 洗白 critical」攻击：verdict 双路径计算（capped vs uncapped）+ 警告横幅。基于 spclaudehome skill-vetter v1.0.0 fork 深度升级，新增豁免机制、severity-cap 引擎适配。Install any skill from ClawHub, GitHub, or other sources — must run before install. <br>

This skill is ready for commercial/non-commercial use. <br>

## Publisher: <br>
[zuoyunlai](https://clawhub.ai/user/zuoyunlai) <br>
Forked from: [spclaudehome/skill-vetter](https://clawhub.ai/spclaudehome/skills/skill-vetter) v1.0.0 (MIT)

### License/Terms of Use: <br>
MIT License — Copyright (c) 2026 左运来 <br>

## Use Case: <br>
Developers and agents run this skill before installing or publishing any OpenClaw skill to automatically scan for security red flags (24 patterns), performance issues (5 thresholds), and quality problems (9 checks). Output is JSON for CI consumption or human-readable text. <br>

### Deployment Geography for Use: <br>
Global <br>

## Known Risks and Mitigations: <br>
Risk: False negatives — patterns may not catch novel attacks. <br>
Mitigation: Always combine with manual review (4-step protocol in references/audit_protocol.md) for high-risk skills. <br>
Risk: Custom patterns in red_flags.yml may have regex errors. <br>
Mitigation: audit.py reports regex compilation errors as findings (SEC-*-REGEX IDs). <br>
Risk: Markdown code blocks are exempted from security scanning. <br>
Mitigation: Code blocks are documentation only — they don't execute; manual review still required. <br>

## Reference(s): <br>
- [ClawHub skill page](https://clawhub.ai/zuoyunlai/skills/lz-skill-vetter-20260819) <br>
- [GitHub repo](https://github.com/zuoyunlai/lz-skill-vetter) <br>

## Skill Output: <br>
**Output Type(s):** [Markdown report, JSON, Shell commands, Exit codes] <br>
**Output Format:** [Text report with banner + JSON Schema v2.0] <br>
**Output Parameters:** [Severity filter, Format selector] <br>
**Other Properties Related to Output:** [CI-friendly with --exit-code; JSON machine-readable for pipelines] <br>

## Skill Version(s): <br>
2.1.2 (2026-08-20) — safe-pattern 双层校验（reason 白名单 + 文件级 manifest）+ 路径 `references/_*.md` 默认排除 + ClawHub scanner 91% finding 闭环（教训 #110）
2.1.1 (2026-08-19) — 关联 GitHub 源码仓库 zuoyunlai/lz-skill-vetter，source-repo 打通 <br>
2.1.0 (2026-08-19) — 独立审计修复 9 问题（original_severity bug / dot-key 词边界 / QUAL-STRUCT-002 实现 / 版本命名漂移清理） <!-- safe-pattern: version-history --> <br>
2.0.1 (2026-08-19) — Forked from spclaudehome v1.0.0; added 38-rule pattern library, JSON output, CI exit codes, 3-tier exemption, severity-cap engine adaptation, 3 false-positive fixes <br>
2.0.0 (2026-08-19) — Initial automated scanning (38 patterns), JSON output, CI exit codes <br>
1.0.0 (2026-08-03) — Original by spclaudehome: 4-step manual audit protocol <br>

## Ethical Considerations: <br>
Users should evaluate whether this skill is appropriate for their environment, review audit reports before relying on them, and apply their organization's safety, security, and compliance requirements before deployment. This skill scans files but does not modify them; all actions are read-only. <br>

## Changelog: <br>
### v2.1.3 (2026-08-20)
- **severity-cap 攻击面闭环**（ClawHub scanner 新 advisory 命中）：verdict 双路径计算（capped vs uncapped）+ 主 verdict 取严重者 + text 报告加 🚨 警告横幅
- 攻击回归：恶意 skill 设 `severity-cap: low` → 原 verdict = SAFE → 现 verdict = ❌ DO NOT INSTALL + 警告横幅显示 capped/uncapped 双值

### v2.1.2 (2026-08-20)
- ClawHub scanner 91% Prompt-Injection finding 闭环（A 移位 + B 收紧豁免 + C 文件级签名 · 教训 #110）
- safe-pattern reason 白名单强制（防御「按内容豁免」攻击面）

### v2.1.1 (2026-08-19)
- 关联 GitHub 源码仓库 zuoyunlai/lz-skill-vetter（source-repo 打通）
- 修正 GitHub 链接（去掉日期后缀）

### v2.1.0 (2026-08-19)
- 独立审计修复 9 问题，38 条规则名副其实

### v2.0.1 (2026-08-19)
- Renamed to lz-skill-vetter (final slug lz-skill-vetter-20260819, avoid slug conflict with spclaudehome)
- 3 false-positive fixes (1password op://, Chrome version number IP, updater curl)
- batch_audit.sh stderr separation fix
- severity-cap frontmatter mechanism (engine-class / severity-cap fields)

### v2.0.0 (2026-08-19)
- Forked from spclaudehome skill-vetter v1.0.0 (MIT)
- Added scripts/audit.py — Python automation with 38 patterns
- Added scripts/scan.sh — Bash wrapper with grep fallback
- Added references/{audit_protocol,patterns,output_format}.md
- Added assets/report_template.json
- Exemption mechanisms: `# safe-pattern:` comments, exception_pattern in YAML, markdown code block / table detection
- Preserved v1.0's 4-step manual audit protocol in references/ <br>

### v1.0.0 (2026-08-03)
- Original by spclaudehome: 4-step manual audit protocol with 15 red flags <br>