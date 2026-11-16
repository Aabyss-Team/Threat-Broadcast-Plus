#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 9:37
# @File   : page.py
# -----------------------------------------------
# 从数据库读取最新 CVE 生成 GitHub 播报页面
# -----------------------------------------------

import html
import os
from datetime import datetime, timedelta
from string import Template

import src.config as config
from src.bean.cve_info import CST, LEVEL_CN
from src.dao.t_cves import TCvesDao
from src.logger import log

HTML_PATH = '%s/docs/index.html' % config.PRJ_DIR
HTML_TPL_PATH = '%s/tpl/html.tpl' % config.PRJ_DIR
TABLE_TPL_PATH = '%s/tpl/table.tpl' % config.PRJ_DIR
ROW_TPL_PATH = '%s/tpl/row.tpl' % config.PRJ_DIR

# 只展示最近 N 天内更新过的来源，避免已停用的来源长期占据页面
SOURCE_RECENT_DAYS = 45
# 最近 N 天内披露的情报标记为 NEW
NEW_RECENT_DAYS = 2
# 标题在列表中的最大展示长度
TITLE_LIMIT = 120

_LEVEL_CLASS = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'KEV': 'kev',
}


def to_page(conn, top=60, sources=None, active=None):
    """生成 docs/index.html。

    :param conn: 数据库连接
    :param top: 每个来源展示的最大条数
    :param sources: 爬虫实例列表（用于来源名称、主页与排序）
    :param active: 本次成功抓到数据的来源名称集合
    """
    sources = sources or []
    active = set(active or [])
    now = datetime.now(CST)
    new_cutoff = (now - timedelta(days=NEW_RECENT_DAYS)).strftime('%Y-%m-%d')
    stale_cutoff = (now - timedelta(days=SOURCE_RECENT_DAYS)).strftime('%Y-%m-%d %H:%M:%S')

    html_tpl, table_tpl, row_tpl = load_tpl()

    latest_by_src = {}
    for row in conn.execute('SELECT s_src, MAX(s_time) AS latest FROM t_cves GROUP BY s_src'):
        latest_by_src[row['s_src']] = row['latest'] or ''

    blocks = []
    nav_items = []
    included_names = []
    total = 0
    new_count = 0
    latest_time = ''

    dao = TCvesDao()
    index = 0
    for src in sources:
        name = src.NAME_CH()
        if name not in latest_by_src:
            continue

        latest = latest_by_src.get(name) or ''
        if name not in active and latest < stale_cutoff:
            log.debug('页面跳过过期来源 [%s]（最后更新 %s）' % (name, latest or '未知'))
            continue

        rows = conn.execute(
            TCvesDao.SQL_SELECT + ' AND s_src = ? ORDER BY s_time DESC LIMIT ?',
            (name, int(top))
        ).fetchall()
        cves = [dao._to_bean(row) for row in rows if row is not None]
        if not cves:
            continue

        rendered_rows = []
        for cve in cves:
            rendered_rows.append(_render_row(row_tpl, cve, new_cutoff))
            if cve.time and cve.time[:10] >= new_cutoff:
                new_count += 1

        total += len(cves)
        if latest > latest_time:
            latest_time = latest

        index += 1
        anchor = 'src-%d' % index
        included_names.append(name)
        blocks.append(_render_table(table_tpl, src, anchor, cves, rendered_rows, latest))
        nav_items.append(
            '<a class="chip" href="#%s"><span>%s</span><b>%d</b></a>'
            % (anchor, html.escape(name), len(cves))
        )

    if not blocks:
        blocks.append(
            '<div class="empty-state">'
            '<h2>暂时没有可展示的情报</h2>'
            '<p>首次运行或所有来源均不可用时会出现此提示。</p>'
            '</div>'
        )

    page = Template(html_tpl).safe_substitute({
        'datetime': now.strftime('%Y-%m-%d %H:%M:%S'),
        'datetime_iso': now.strftime('%Y-%m-%dT%H:%M:%S+08:00'),
        'year': now.strftime('%Y'),
        'total': total,
        'new_count': new_count,
        'src_count': index,
        'latest': latest_time or '—',
        'top': int(top),
        'source_names': html.escape(' · '.join(included_names) or '公开威胁情报源'),
        'nav': '\n'.join(nav_items),
        'tables': '\n'.join(blocks),
    })

    create_html(page)
    log.info('播报页面已生成：%s（%d 个来源 / %d 条情报 / %d 条为近 %d 天新增）'
             % (HTML_PATH, index, total, new_count, NEW_RECENT_DAYS))
    return total


def load_tpl():
    with open(HTML_TPL_PATH, 'r', encoding=config.CHARSET) as file:
        html_tpl = file.read()

    with open(TABLE_TPL_PATH, 'r', encoding=config.CHARSET) as file:
        table_tpl = file.read()

    with open(ROW_TPL_PATH, 'r', encoding=config.CHARSET) as file:
        row_tpl = file.read()

    return html_tpl, table_tpl, row_tpl


def create_html(content):
    directory = os.path.dirname(HTML_PATH)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(HTML_PATH, 'w', encoding=config.CHARSET) as file:
        file.write(content)


def _render_table(table_tpl, src, anchor, cves, rendered_rows, latest):
    return Template(table_tpl).safe_substitute({
        'anchor': anchor,
        'src': html.escape(src.NAME_CH()),
        'src_raw': html.escape(src.NAME_CH(), quote=True),
        'home': html.escape(src.HOME_PAGE(), quote=True),
        'count': len(cves),
        'latest': html.escape(_display_time(latest)),
        'rows': '\n'.join(rendered_rows),
    })


def _render_row(row_tpl, cve, new_cutoff):
    title = cve.title or '(无标题)'
    short_title = _shorten(title, TITLE_LIMIT)
    url = cve.url or '#'
    is_new = bool(cve.time and cve.time[:10] >= new_cutoff)
    display_time = _display_time(cve.time)

    search_text = ' '.join(filter(None, [
        cve.cves or '', title, cve.src or '', cve.level or '',
        LEVEL_CN.get((cve.level or '').upper(), ''),
    ])).lower()

    return Template(row_tpl).safe_substitute({
        'url': html.escape(url, quote=True),
        'id': html.escape(cve.cves or '—'),
        'title': html.escape(short_title),
        'title_full': html.escape(title, quote=True),
        'time': html.escape(display_time),
        'time_iso': html.escape((cve.time or '').replace(' ', 'T'), quote=True),
        'timestamp': _epoch(cve.time),
        'level_code': (cve.level or 'none').lower(),
        'level_html': _level_badge(cve.level),
        'new_html': '<span class="badge-new">NEW</span>' if is_new else '',
        'search': html.escape(search_text, quote=True),
        'md5': html.escape(cve.md5 or ''),
    })


def _epoch(value):
    """把 UTC+8 的时间字符串转成 Unix 时间戳，供前端时间筛选使用。"""
    try:
        moment = datetime.strptime(value, '%Y-%m-%d %H:%M:%S').replace(tzinfo=CST)
        return int(moment.timestamp())
    except (TypeError, ValueError):
        return 0


def _shorten(text, limit):
    """按词边界截断长描述，避免出现半截单词。"""
    if len(text) <= limit:
        return text
    cut = text[:limit].rstrip()
    space = cut.rfind(' ')
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip('，,。.;；:：') + '…'


def _display_time(value):
    """纯日期来源（AVD / CISA）不显示无意义的 00:00:00。"""
    if value and value.endswith(' 00:00:00'):
        return value[:10]
    return value or '—'


def _level_badge(level):
    code = (level or '').upper()
    if code in LEVEL_CN:
        return '<span class="badge badge-%s">%s</span>' % (
            _LEVEL_CLASS.get(code, 'none'), html.escape(LEVEL_CN[code])
        )
    return '<span class="badge badge-none">—</span>'
