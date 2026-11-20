#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# Sploitus：https://sploitus.com/
# 漏洞利用（Exploit / PoC）聚合搜索引擎，收录 Exploit-DB、PacketStorm、GitHub 等来源。
# 公开检索接口：POST /search（JSON），每页固定 10 条、offset 翻页，空查询不返回结果，
# 这里以「CVE」为查询词、按收录时间倒序拉取最新的漏洞利用。
# -----------------------------------------------

import re

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

API_URL = 'https://sploitus.com/search'
EXPLOIT_URL = 'https://sploitus.com/exploit?id='
PAGE_SIZE = 10              # 接口固定每页 10 条，limit 参数无效
MAX_PAGES = 10              # 翻页上限，避免接口异常时死循环
_CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


class Sploitus(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'Sploitus'
        self.name_en = 'Sploitus'
        self.home_page = 'https://sploitus.com/'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=60):
        cves = []
        seen = set()
        pages = min(MAX_PAGES, (limit + PAGE_SIZE - 1) // PAGE_SIZE)
        for page in range(pages):
            entries = self._search(page * PAGE_SIZE)
            if not entries:
                break
            for entry in entries:
                identifier = entry.get('id') or ''
                if identifier and identifier in seen:
                    continue
                seen.add(identifier)
                cve = self.to_cve(entry)
                if cve.is_valid():
                    cves.append(cve)
                if len(cves) >= limit:
                    return cves
        return cves

    def _search(self, offset):
        payload = {
            'type': 'exploits',
            'sort': 'date',
            'query': 'CVE',
            'title': False,
            'offset': offset,
        }
        try:
            response = self.post(API_URL, json=payload, timeout=max(self.timeout, 60))
        except Exception as error:
            log.warning('获取 [%s] 情报失败：%s' % (self.NAME_CH(), error))
            return []

        if response.status_code != 200:
            log.warning('获取 [%s] 情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        try:
            return (response.json() or {}).get('exploits') or []
        except ValueError as error:
            log.warning('解析 [%s] 返回失败：%s' % (self.NAME_CH(), error))
            return []

    def to_cve(self, entry):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.title = (entry.get('title') or '').strip()
        cve.id = ', '.join(dict.fromkeys(
            value.upper() for value in _CVE_PATTERN.findall(cve.title)))
        cve.time = (entry.get('published') or '').strip()
        # href 是原始来源链接（如 GitHub 仓库），比 Sploitus 中转页更有用
        cve.url = (entry.get('href') or '').strip()
        if not cve.url and entry.get('id'):
            cve.url = EXPLOIT_URL + entry['id']
        cve.info = 'Sploitus 收录的公开漏洞利用；原始来源：%s；相关度评分：%s；时间为收录时间。' % (
            (entry.get('type') or '').strip() or '未知', entry.get('score') or '未知')
        return cve
