# LZ Skill Vetter Pro 🔒🦀

> OpenClaw 技能自动化审计器 —— 安装任何第三方技能前必跑的安全/性能/质量三维度扫描器。

**38 条规则** · 三维度扫描 · JSON 报告 · CI 退出码 · 豁免机制 · 引擎类适配

[![ClawHub](https://img.shields.io/badge/ClawHub-lz--skill--vetter--20260819-orange)](https://clawhub.ai/zuoyunlai/skills/lz-skill-vetter-20260819)
[![License](https://img.shields.io/badge/License-MIT--0-green)](./LICENSE)

---

## 这是什么

`skill-vetter` 是一个安全审计器，用于在安装任何 ClawHub / GitHub / 第三方 OpenClaw 技能**之前**，自动扫描其中的安全红线、性能问题和质量缺陷。

基于 [spclaudehome/skill-vetter](https://clawhub.ai/spclaudehome/skills/skill-vetter) v1.0.0（4 步人工审计协议）深度升级，MIT 协议 fork。

## 特性

### 🔒 安全扫描（24 条规则）

- **代码执行**：`eval()` / `exec()` / `os.system` / `new Function()`
- **网络外发**：`curl`/`wget` / `requests` / 硬编码 IP / URL 短链
- **凭据泄露**：硬编码 API key / 密码 / AWS Key ID / 私钥头 / 敏感路径
- **混淆**：base64 解码 / 压缩编码 / 超长 hex
- **系统权限**：`sudo` / `rm -rf` / `chmod 777` / `dd` 覆写
- **持久化**：修改 rc/crontab/systemd / 系统包安装

### ⚡ 性能审计（5 条阈值）

- SKILL.md body 行数 > 500
- frontmatter description > 500 字符
- body 字符数 > 30K（~5000 tokens）
- references/ 单文件 > 800 行
- scripts/ 缺少 shebang

### ✨ 质量审计（9 条检查）

- frontmatter 必填字段 / YAML 解析 / name 格式
- 禁用文件 / license 声明 / scripts 可执行权限
- 使用示例 / "When to Use" 段 / description 触发词

### 🛡️ 豁免机制（3 层）

1. `# safe-pattern:` 注释 —— 单行豁免
2. `exception_pattern` —— 模式库正则豁免
3. `severity-cap` / `engine-class` —— 引擎类技能自动降级

## 快速开始

```bash
# 文本报告（人类可读）
python3 scripts/audit.py /path/to/skill

# JSON 报告（机器可消费 + CI）
python3 scripts/audit.py /path/to/skill --format json

# 仅看严重问题
python3 scripts/audit.py /path/to/skill --severity high

# CI 退出码模式（0=pass, 1=warning, 2=fail）
python3 scripts/audit.py /path/to/skill --exit-code
```

### 批量审计所有已装技能

```bash
scripts/batch_audit.sh
```

### CI 集成（GitHub Actions）

```yaml
name: Skill Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.12'}
      - run: pip install pyyaml
      - name: Audit
        run: python3 skill-vetter/scripts/audit.py . --exit-code
```

## 目录结构

```
skill-vetter/
├── SKILL.md                    # 技能定义（OpenClaw 加载入口）
├── skill-card.md               # ClawHub 发布卡片
├── _meta.json                  # 元数据（slug/version/license/fork 来源）
├── scripts/
│   ├── audit.py                # 核心扫描器（Python）
│   ├── scan.sh                 # Bash 包装（grep fallback）
│   ├── batch_audit.sh          # 批量审计
│   └── patterns/
│       └── red_flags.yml       # 38 条规则模式库（可扩展）
├── references/
│   ├── audit_protocol.md       # 4 步人工审计协议（v1.0 保留）
│   ├── patterns.md             # 模式库索引
│   └── output_format.md        # JSON Schema + CI 示例
└── assets/
    └── report_template.json    # JSON 报告模板
```

## 风险分级

| 命中 | verdict |
|---|---|
| ≥1 critical | ⛔ ❌ DO NOT INSTALL |
| ≥1 high | 🔴 ⚠️ INSTALL WITH CAUTION |
| ≥1 medium | 🟡 ⚠️ REVIEW MEDIUM ISSUES |
| ≥1 low/info | 🟢 ✅ SAFE TO INSTALL (minor notes) |
| 无命中 | 🟢 ✅ SAFE TO INSTALL |

## 版本历史

- **v2.1.0** (2026-08-19) — 独立审计修复 9 问题（original_severity bug / `.key` 词边界 / QUAL-STRUCT-002 实现 / 版本命名漂移清理）
- **v2.0.1** (2026-08-19) — 3 误判修复 + severity-cap 机制
- **v2.0.0** (2026-08-19) — 从 v1.0 人工协议升级为 38 条自动化规则
- **v1.0.0** (2026-08-03) — 原始版（spclaudehome）：4 步人工审计协议 + 15 红线

## 发布渠道

- **ClawHub**: [lz-skill-vetter-20260819](https://clawhub.ai/zuoyunlai/skills/lz-skill-vetter-20260819)
- **GitHub**: 本仓库（源码真源）
- **Fork 来源**: [spclaudehome/skill-vetter](https://clawhub.ai/spclaudehome/skills/skill-vetter) v1.0.0 (MIT)

## License

MIT-0 —— 自由使用、修改、再分发，无需署名。

---

*Paranoia is a feature.* 🔒🦀
