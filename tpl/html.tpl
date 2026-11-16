<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; base-uri 'none'; form-action 'none'">
    <meta name="robots" content="noarchive">
    <meta name="author" content="Aabyss-Team">
    <meta name="description" content="渊龙Sec安全团队威胁情报自动播报：聚合 NVD、Tenable、阿里云高危漏洞库、斗象、微步、长亭、CISA KEV 等公开来源的最新漏洞情报。">
    <meta property="og:title" content="威胁情报播报 · 渊龙Sec安全团队">
    <meta property="og:description" content="自动聚合公开漏洞情报源，每 3 小时更新，聚焦最新披露与在野利用漏洞。">
    <meta property="og:type" content="website">
    <title>威胁情报播报 · 渊龙Sec安全团队</title>
    <link rel="icon" href="https://www.aabyss.cn/favicon.ico">
    <link rel="stylesheet" href="./css/page.css">
</head>
<body id="top">
<a class="skip-link" href="#main">跳到主要内容</a>

<header class="hero">
    <div class="wrap hero-inner">
        <div class="hero-copy">
            <p class="eyebrow">THREAT INTELLIGENCE · AUTO BROADCAST</p>
            <h1>威胁情报播报</h1>
            <p class="lede">自动聚合公开漏洞情报源，每 3 小时更新一次，聚焦最新披露与已被在野利用的高危漏洞。</p>
            <div class="hero-meta">
                <span class="meta-item"><span class="meta-dot" aria-hidden="true"></span>最后更新 <time datetime="$datetime_iso">$datetime</time></span>
                <span class="meta-item">$src_count 个情报源</span>
                <span class="meta-item">$total 条记录</span>
            </div>
        </div>
        <div class="hero-actions">
            <a class="btn btn-ghost" href="https://github.com/Aabyss-Team/Threat-Broadcast-Plus" target="_blank" rel="noopener">GitHub 项目</a>
            <a class="btn btn-primary" href="https://www.aabyss.cn" target="_blank" rel="noopener">团队主页</a>
        </div>
    </div>
</header>

<main id="main">
    <section class="wrap stats" aria-label="数据概览">
        <div class="stat">
            <span class="stat-value">$total</span>
            <span class="stat-label">当前展示情报</span>
        </div>
        <div class="stat stat-accent">
            <span class="stat-value">$new_count</span>
            <span class="stat-label">近两天新增</span>
        </div>
        <div class="stat">
            <span class="stat-value">$src_count</span>
            <span class="stat-label">活跃情报源</span>
        </div>
        <div class="stat">
            <span class="stat-value">$top</span>
            <span class="stat-label">每源展示上限</span>
        </div>
    </section>

    <div class="wrap toolbar">
        <div class="search">
            <span class="search-icon" aria-hidden="true">⌕</span>
            <label class="sr-only" for="search">搜索 CVE 编号、关键词或来源</label>
            <input id="search" type="search" placeholder="搜索 CVE 编号、关键词或来源…" autocomplete="off" spellcheck="false">
            <kbd>/</kbd>
        </div>

        <div class="filters">
            <div class="filter">
                <label for="filter-level">等级</label>
                <select id="filter-level">
                    <option value="all">全部等级</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                    <option value="kev">在野利用</option>
                    <option value="none">未知</option>
                </select>
            </div>
            <div class="filter">
                <label for="filter-time">时间</label>
                <select id="filter-time">
                    <option value="all">全部时间</option>
                    <option value="1">近 24 小时</option>
                    <option value="7">近 7 天</option>
                    <option value="30">近 30 天</option>
                    <option value="90">近 90 天</option>
                    <option value="365">近一年</option>
                </select>
            </div>
        </div>

        <button id="toggle-all" class="btn btn-icon" type="button" aria-label="展开或收起全部来源">展开全部</button>
        <button id="theme-toggle" class="btn btn-icon" type="button" aria-label="切换深色 / 浅色主题">
            <span id="theme-label">深色</span>
        </button>
    </div>

    <nav class="wrap source-nav" aria-label="情报来源">
$nav
    </nav>

    <div class="wrap">
        <p id="no-results" class="no-results" hidden>没有匹配的情报，调整关键词或筛选条件试试。</p>
$tables
    </div>
</main>

<footer class="site-footer">
    <div class="wrap footer-inner">
        <div class="footer-brand">
            <strong>渊龙Sec安全团队</strong>
            <p>持续跟踪公开漏洞情报，为安全从业者提供轻量、可检索、可归档的每日威胁简报。</p>
            <p class="footer-note">数据来源：$source_names。情报仅供参考，请以官方通告为准。</p>
        </div>
        <div class="footer-links">
            <a href="https://threat.aabyss.cn/" target="_blank" rel="noopener">在线播报页</a>
            <a href="https://github.com/Aabyss-Team/Threat-Broadcast-Plus" target="_blank" rel="noopener">开源项目</a>
            <a href="https://www.aabyss.cn" target="_blank" rel="noopener">团队主页</a>
            <a href="https://github.com/Aabyss-Team/Threat-Broadcast-Plus/issues" target="_blank" rel="noopener">问题反馈</a>
        </div>
        <div class="footer-qr">
            <img src="imgs/wechat.png" alt="渊龙Sec安全团队公众号二维码" width="96" height="96" loading="lazy">
            <span>扫码关注公众号</span>
        </div>
    </div>
    <div class="wrap copyright">
        <p>© $year 渊龙Sec安全团队 · 页面由 GitHub Actions 自动生成 · 最近一次构建 $datetime</p>
    </div>
</footer>

<a class="back-top" href="#top" aria-label="回到顶部">↑</a>
<script src="./js/app.js" defer></script>
</body>
</html>
