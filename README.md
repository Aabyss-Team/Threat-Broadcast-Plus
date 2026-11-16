# 渊龙Sec安全团队 - 威胁情报播报Plus升级版

**在线播报地址：[https://threat.aabyss.cn/](https://threat.aabyss.cn/)**

------

## 1# 项目介绍

**基于原项目[threat-broadcast](https://github.com/Aabyss-Team/threat-broadcast)的魔改和升级，感谢DeepSeek Cyber网络安全模型的帮助~**

自动从多个公开威胁情报源抓取最新漏洞信息，去重归档后生成静态播报页面，并通过 GitHub Actions 定时更新、提交回仓库。

**如果你觉得本项目有用，欢迎点个 Star，感谢各位师傅的关注和支持~**

### 当前启用的情报源

| 来源 | 地址 | 说明 |
| --- | --- | --- |
| 阿里云漏洞库 | https://avd.aliyun.com/ | 中文漏洞通告，服务端渲染，稳定 |
| 斗象漏洞情报中心 | https://vip.tophant.com/intellList | 中文漏洞情报，含风险等级，支持 CVE 搜索 |
| 微步在线情报中心 | https://x.threatbook.com/v5/vulIntelligence | 中文漏洞公告，含风险等级、CVE/CNNVD 编号 |
| 长亭漏洞库 | https://stack.chaitin.com/vuldb/index | 中文漏洞库，含危害等级、CVE/CNVD/CNNVD 编号 |
| NVD | https://nvd.nist.gov/ | 官方 2.0 recent JSON 源，失败时回退 REST API |
| Tenable (Nessus) | https://www.tenable.com/cve/feeds?sort=newest | RSS 源，含严重等级与英文描述 |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 已被在野利用的漏洞目录 |

> 微步的漏洞详情页需要登录，列表接口本身是公开的；未登录时点击详情会跳转到登录页。

### 已停用的来源

以下来源因站点改版、接口失效、反爬升级或停止 CVE 分析而停用，代码保留在 `src/crawler/` 中，确认恢复后可重新启用：

- **360 CERT**：站点 TLS 证书已过期，接口内容停留在 2024 年
- **奇安信 / 红后 / 绿盟**：站点改版或接口失效
- **CNVD / CNNVD**：反爬机制不断升级，尊重平台
- **安全客**：已停止 CVE 分析

> 旧版斗象爬虫 `vas.py` 已由新的斗象漏洞情报中心接口替代。

> 这些爬虫仍引用旧依赖（如 CNVD 需要 `PyExecJS`），重新启用前请按需安装对应依赖。

> 本程序只收录国内外安全厂商已收录并分析的 CVE，并不收录所有 CVE。需要全量 CVE 可前往：
> [cve.mitre.org](https://cve.mitre.org/) / [CVEProject/cvelist](https://github.com/CVEProject/cvelist) / [cve.circl.lu](https://cve.circl.lu/)

------

## 2# 本次优化内容

针对旧版本中「跑不起来、抓不到数据、页面难看」的问题，做了以下修复：

### 依赖与兼容性

- 移除已停止维护、且与 Python 3.12 / PyYAML 6 不兼容的依赖：
  `pypdm-db`、`pyyaml-erb`、`py-color-log`、`GitPython`、`python-graphql-client`、`PyExecJS`
- 数据库改用 Python 标准库 `sqlite3`，日志改用标准库 `logging`
- 配置解析改为「先解析 YAML，再替换环境变量」，密码里含 `:`、`#`、引号也不会破坏配置
- GitHub Actions 升级到 `actions/checkout@v4`、`actions/setup-python@v5`、Python 3.12

### 抓取与数据质量

- **NVD**：旧 RSS 源已下线，改为官方 2.0 recent JSON 源（约 8 天数据），失败时自动回退 REST API 2.0
- **Tenable**：修复时间字段是 `datetime` 导致页面报错的问题，正确解析严重等级与描述
- **阿里云漏洞库**：新增来源，替代失效的 360 / 奇安信
- **斗象漏洞情报中心**：新增来源，调用公开 JSON 接口按披露时间倒序取最新 CVE
- **微步在线情报中心**：新增来源，读取公开漏洞公告接口，按披露时间保留最近一年
- **长亭漏洞库**：新增来源，读取公开列表接口（单页 15 条，自动翻页）
- **CISA KEV**：新增来源，标记「在野利用」漏洞
- 统一会话、超时与重试；单个来源失败不会影响其它来源
- 时间统一为 UTC+8 的 `YYYY-MM-DD HH:MM:SS`，页面按时间倒序
- 去重键改为「来源 + 编号 + 链接」，来源改写标题时不会重复播报
- 所有写入页面的字段做 HTML 转义，链接只允许 `http/https`
- 数据库自动去重、按来源裁剪归档、必要时 `VACUUM`，避免 50MB+ 的 `cves.db` 每次提交

### 页面美化

- 全新响应式布局：桌面表格 / 移动端卡片式堆叠
- 顶部数据概览（总条数、近两天新增、来源数、每源上限）
- 支持关键词搜索（CVE 编号、标题、来源），快捷键 `/` 聚焦
- 支持深色 / 浅色主题，跟随系统并记住选择
- 严重等级徽章（严重 / 高危 / 中危 / 低危 / 在野利用）与 `NEW` 标记
- 移除无用的 MD5 列，增加来源导航、回到顶部、无障碍标签
- 严格 CSP：`script-src 'self'`、`style-src 'self'`，无内联脚本

### 通知

- 邮件改为直接 SMTP 发送（465 SSL / 587 STARTTLS），失败只告警
- 新增微信推送：企业微信群机器人 / Server酱 / PushPlus，配置任意一种即可
- 邮件与微信内容均做转义与长度控制

------

## 3# 快速开始

### 本地运行

```bash
# 建议 Python 3.8+，GitHub Actions 使用 3.12
python -m pip install -r requirements.txt

# 生成页面 + 写数据库（不发送通知）
python main.py -g AabyssTeam6666 -t 60 --no-mail --no-wechat
```

生成的页面位于 `docs/index.html`。本地预览建议在项目根目录启动一个静态服务器（页面使用了严格 CSP，直接双击打开可能无法运行搜索 / 主题脚本）：

```bash
python -m http.server 8000
# 浏览器访问 http://127.0.0.1:8000/docs/
```

### GitHub Actions

工作流：`.github/workflows/autorun.yml`，默认每 3 小时运行一次，也可以手动 `workflow_dispatch`。

需要在仓库 `Settings -> Secrets and variables -> Actions` 中配置：

| Secret | 必填 | 说明 |
| --- | --- | --- |
| `CRAWL_PWD` | 是 | 启动密码；工作流会同时注入同名环境变量，本地运行时需与 `main.py` 默认值一致 |
| `GTK` | 否 | GitHub Token，用于从 Issue 收集订阅邮箱 |
| `MAIL_PASS` | 否 | 发件邮箱的 SMTP 授权码；不配置则跳过邮件 |
| `MAIL_USER` | 否 | 发件邮箱账号；不配置则使用 `settings.yml` 中的默认值 |
| `MAIL_SMTP` | 否 | SMTP 服务器；不配置则使用 `settings.yml` 中的默认值 |
| `NVD_API_KEY` | 否 | NVD API Key，仅在回退 REST API 时使用 |
| `WECHAT_WEBHOOK` | 否 | 企业微信群机器人 Webhook |
| `SERVERCHAN_KEY` | 否 | Server酱 SendKey |
| `PUSHPLUS_TOKEN` | 否 | PushPlus Token |

> 启动密码用于避免仓库被 Fork 后直接运行、对目标站点造成压力。直接运行时未配置密码，程序会静默退出；GitHub Actions 工作流额外增加了必填检查，`CRAWL_PWD` Secret 缺失时会直接失败并给出提示，避免出现“任务成功但没有抓取”的情况。

> GitHub Pages 的 Source 需要设置为 `Deploy from a branch`，选择默认分支、目录 `/docs`；自定义域名通过仓库根目录的 `CNAME` 生效。

### 配置文件

`config/settings.yml` 主要配置项：

```yaml
database:
  dbpath: './data/cves.db'
  retain_days: 365          # 归档保留天数，0 表示不按时间清理
  max_rows_per_src: 3000    # 每个来源最多保留条数，0 表示不限制

crawler:
  top: 60                   # 每个来源抓取 / 展示前 N 条
  timeout: 45               # 单次 HTTP 超时（秒）

notify:
  mail_smtp: 'smtp.qq.com'
  mail_port: 465            # 465 = SSL，587 = STARTTLS
  mail_user: 'threatbroadcast@qq.com'
  mail_pass: "<%= ENV['MAIL_PASS'] %>"
  wechat_webhook: "<%= ENV['WECHAT_WEBHOOK'] %>"
  serverchan_key: "<%= ENV['SERVERCHAN_KEY'] %>"
  pushplus_token: "<%= ENV['PUSHPLUS_TOKEN'] %>"
```

------

## 4# 目录结构

```
threat-broadcast
├── README.md ............................... [项目说明]
├── main.py ................................. [程序运行入口]
├── config/settings.yml ..................... [运行配置]
├── cache ................................... [各来源 MD5 去重缓存]
├── data/cves.db ............................ [sqlite: 威胁情报归档]
├── docs .................................... [GitHub Page 威胁情报总览]
│   ├── index.html .......................... [自动生成的播报页面]
│   ├── CNAME ............................... [GitHub Pages 自定义域名]
│   ├── css/page.css ........................ [页面样式]
│   └── js/app.js ........................... [搜索 / 主题切换]
├── src
│   ├── crawler ............................. [各情报源爬虫]
│   ├── bean / dao .......................... [数据模型与 sqlite 访问]
│   ├── notice .............................. [页面 / 邮件 / 微信播报]
│   └── utils ............................... [Git 与 GitHub GraphQL]
├── script .................................. [数据库脚本]
├── tpl ..................................... [页面模板]
├── imgs .................................... [项目图片]
└── logs .................................... [项目日志]
```

------

## 5# 数据与归档

- 所有抓取到的情报（去重后）都会写入 `data/cves.db`
- 页面只展示每个来源最新 `top` 条（默认 60 条），来源超过 45 天没有更新会自动隐藏
- 默认保留最近 365 天、每个来源最多 3000 条，超出的记录会在每次运行时清理并整理数据库
- `cache/*.dat` 只保存 MD5，用于跨次运行去重，可安全删除（删除后数据库唯一索引仍会防重复）

> 当前工作流会把 `data/cves.db` 和 `docs/index.html` 提交回仓库，数据库约 4MB。长期每 3 小时提交一次会让仓库体积持续增长；如果介意，建议改为「Actions cache 保存数据库 + Pages artifact 部署页面」，不再提交生成物。

------

## 6# 页面特性

- 响应式：桌面表格、移动端卡片
- 搜索：编号 / 标题 / 来源，`/` 聚焦，`Esc` 清空
- 深色 / 浅色主题：跟随系统，可手动切换并记住
- 等级徽章：严重、高危、中危、低危、在野利用
- `NEW`：最近两天披露
- 纯静态、无外部 JS 依赖，严格 CSP
- 可直接部署到 GitHub Pages、Cloudflare Pages、Nginx 等任意静态托管

------

## 7# 版权声明

[![Copyright (C) EXP,2016](https://img.shields.io/badge/Copyright%20(C)-EXP%202016-blue.svg)](http://exp-blog.com)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

本项目 Fork 并参考了 [Mr-xn/threat-broadcast](https://github.com/Mr-xn/threat-broadcast) 和 [EXP-Tools/threat-broadcast](https://github.com/EXP-Tools/threat-broadcast)，由衷感谢这两个项目~

## 8# 感谢各位师傅🙏

## Forkers

[![Forkers repo roster for @Aabyss-Team/threat-broadcast](http://reporoster.com/forks/Aabyss-Team/Threat-Broadcast-Plus/network/members)](https://github.com/Aabyss-Team/Threat-Broadcast-Plus/network/members)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Aabyss-Team/Threat-Broadcast-Plus&type=Date)](https://star-history.com/#Aabyss-Team/Threat-Broadcast-Plus&Date)
