#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : cve_info.py
# -----------------------------------------------

import hashlib
import html
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

# 中国标准时间（无夏令时，固定 UTC+8）
CST = timezone(timedelta(hours=8))
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

_TAG_PATTERN = re.compile(r'<[^>]+>')
_SPACE_PATTERN = re.compile(r'[\s\u3000]+')
_CONTROL_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

LEVEL_CN = {
    'CRITICAL': '严重',
    'HIGH': '高危',
    'MEDIUM': '中危',
    'LOW': '低危',
    'KEV': '在野利用',
}

_LEVEL_ALIASES = {
    'CRITICAL': 'CRITICAL',
    '严重': 'CRITICAL',
    'HIGH': 'HIGH',
    '高危': 'HIGH',
    'MEDIUM': 'MEDIUM',
    '中危': 'MEDIUM',
    'MODERATE': 'MEDIUM',
    'LOW': 'LOW',
    '低危': 'LOW',
    'KEV': 'KEV',
    '在野利用': 'KEV',
    'UNKNOWN': '',
    '未知': '',
}


def clean_text(value, limit=0):
    """去掉 HTML 标签、反转义实体、压缩空白，并按需截断。"""
    if value is None:
        return ''
    text = html.unescape(str(value))
    text = _TAG_PATTERN.sub(' ', text)
    text = _CONTROL_PATTERN.sub(' ', text)
    text = _SPACE_PATTERN.sub(' ', text).strip()
    if limit and len(text) > limit:
        text = text[:limit].rstrip() + '…'
    return text


def normalize_time(value):
    """把各种来源的时间统一成 UTC+8 的 YYYY-MM-DD HH:MM:SS。"""
    if value is None or value == '':
        return ''

    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        try:
            seconds = float(value)
            if seconds > 1e12:          # 毫秒时间戳
                seconds = seconds / 1000.0
            moment = datetime.fromtimestamp(seconds, CST)
        except (ValueError, OverflowError, OSError):
            return ''
    else:
        text = str(value).strip()
        if not text:
            return ''

        # 纯日期
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', text):
            return text + ' 00:00:00'

        # 已经是本地时间格式（不带 T / 时区），保持原样
        if re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', text):
            return text

        moment = None
        try:
            moment = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            try:
                moment = parsedate_to_datetime(text)
            except (TypeError, ValueError):
                return ''

        if moment is None:
            return ''

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    try:
        return moment.astimezone(CST).strftime(TIME_FORMAT)
    except (ValueError, OverflowError):
        return ''


def safe_url(value):
    """只允许 http/https，防止模板里出现 javascript: 等危险链接。"""
    url = (value or '').strip()
    if not url:
        return ''
    try:
        scheme = urlparse(url).scheme.lower()
    except ValueError:
        return ''
    return url if scheme in ('http', 'https') else ''


def cve_md5(src, cve_id, url, title=''):
    """稳定的去重键：优先使用「来源 + 编号 + 链接」。

    不使用标题参与计算，否则来源修改描述后会被误判为一条新情报，产生重复记录。
    仅当来源确实没有编号（如部分通告）时，才退回使用标题。
    """
    key = '%s|%s|%s' % (src or '', cve_id or '', url or '')
    if not cve_id:
        key = '%s|%s' % (key, title or '')
    return hashlib.md5(key.encode(encoding='UTF-8')).hexdigest()


class CVEInfo(object):

    def __init__(self):
        self.id = ''
        self.src = ''
        self.url = ''
        self.time = ''
        self.title = ''
        self.info = ''
        self.level = ''
        self.md5 = ''

    def set_time(self, value):
        self.time = normalize_time(value)
        return self.time

    def set_level(self, value):
        text = clean_text(value, 32).upper()
        self.level = _LEVEL_ALIASES.get(text, '')
        return self.level

    def normalize(self):
        """统一清洗字段；在写库和生成页面前调用。"""
        self.id = clean_text(self.id, 128)
        self.title = clean_text(self.title, 300)
        self.info = clean_text(self.info, 1200)
        self.src = clean_text(self.src, 64)
        self.url = safe_url(self.url)
        self.time = normalize_time(self.time)
        self.level = _LEVEL_ALIASES.get(clean_text(self.level, 32).upper(), '')

        if not self.title and self.info:
            self.title = self.info[:300]

        # 编号缺失时从标题里兜底提取
        if not self.id:
            found = _CVE_PATTERN.search(self.title)
            if found:
                self.id = found.group(0).upper()
        else:
            self.id = self.id.upper()

        self.md5 = ''
        return self

    def is_valid(self):
        return bool(self.title and self.src)

    # 兼容旧拼写
    is_vaild = is_valid

    def MD5(self):
        if not self.md5:
            self.md5 = cve_md5(self.src, self.id, self.url, self.title)
        return self.md5

    @property
    def level_cn(self):
        return LEVEL_CN.get(self.level, '')

    def to_html(self):
        """邮件正文里的单条情报（已做 HTML 转义）。"""
        title = html.escape(self.title or '(无标题)')
        url = html.escape(self.url or '#')
        source = html.escape(self.src)
        cve_id = html.escape(self.id or '—')
        moment = html.escape(self.time or '—')
        badge = ''
        if self.level_cn:
            badge = ' <span style="display:inline-block;padding:1px 8px;border-radius:10px;' \
                    'background:#fee2e2;color:#b91c1c;font-size:12px;">%s</span>' % html.escape(self.level_cn)

        return (
            '<div style="margin:0 0 16px;padding:14px 16px;border:1px solid #e5e7eb;'
            'border-left:4px solid #dc2626;border-radius:8px;background:#ffffff;">'
            '<div style="font-size:12px;color:#6b7280;margin-bottom:6px;">%s · %s · %s%s</div>'
            '<div style="font-size:15px;line-height:1.6;color:#111827;font-weight:600;">%s</div>'
            '<div style="margin-top:8px;"><a href="%s" style="color:#2563eb;font-size:13px;">查看详情 →</a></div>'
            '</div>'
        ) % (source, cve_id, moment, badge, title, url)

    def to_text(self):
        """纯文本摘要，用于 IM / 微信推送。"""
        rows = [
            '【%s】%s' % (self.level_cn or '情报', self.title or '(无标题)'),
        ]
        if self.id:
            rows.append('编号：%s' % self.id)
        if self.time:
            rows.append('时间：%s' % self.time)
        if self.url:
            rows.append('链接：%s' % self.url)
        return '\n'.join(rows)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return '\n'.join([
            "\n==============================================",
            "[ TITLE ] %s" % self.title,
            "[ TIME  ] %s" % self.time,
            "[ CVE   ] %s" % self.id,
            "[ LEVEL ] %s" % self.level,
            "[ SRC   ] %s" % self.src,
            "[ URL   ] %s" % self.url,
            "[ INFO  ] %s" % self.info,
        ])
