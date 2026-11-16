#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : chaitin.py
# -----------------------------------------------
# 长亭漏洞库：https://stack.chaitin.com/vuldb/index
#
# 公开列表接口（无需登录）：
#   GET https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=0
#
# 接口单页最多返回 15 条，按披露时间倒序；详情页：
#   https://stack.chaitin.com/vuldb/detail?id={id}
# -----------------------------------------------

import math
import re

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

API_URL = 'https://stack.chaitin.com/api/v2/vuln/list/'
DETAIL_URL = 'https://stack.chaitin.com/vuldb/detail?id='
HOME_PAGE = 'https://stack.chaitin.com/vuldb/index'

PAGE_SIZE = 15
MAX_PAGES = 20

SEVERITY_MAP = {
    'critical': 'CRITICAL',
    'high': 'HIGH',
    'medium': 'MEDIUM',
    'low': 'LOW',
}

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
# 标题末尾的「（CVE-...）」「(CVE-.../CVE-...)」
CVE_SUFFIX = re.compile(r'\s*[（(]\s*CVE-[^）)]*[)）]\s*$', re.IGNORECASE)


class Chaitin(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '长亭漏洞库'
        self.name_en = 'Chaitin'
        self.home_page = HOME_PAGE
        self.url = API_URL

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def headers(self):
        headers = BaseCrawler.headers(self)
        headers['Accept'] = 'application/json, text/plain, */*'
        headers['Referer'] = HOME_PAGE
        return headers

    def get_cves(self, limit=60):
        pages = max(1, min(int(math.ceil(float(limit) / PAGE_SIZE)), MAX_PAGES))

        records = []
        seen = set()
        for page in range(pages):
            params = {'limit': PAGE_SIZE, 'offset': page * PAGE_SIZE}
            response = self.get(self.url, params=params)
            if response.status_code != 200:
                log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
                break

            try:
                payload = response.json()
            except ValueError as error:
                log.warning('解析 [%s] 返回的 JSON 失败：%s' % (self.NAME_CH(), error))
                break

            data = payload.get('data') or {}
            batch = data.get('list') or []
            if not batch:
                break

            for item in batch:
                key = str(item.get('id') or item.get('ct_id') or '')
                if key in seen:
                    continue
                seen.add(key)
                records.append(item)

            if len(records) >= limit or len(batch) < PAGE_SIZE:
                break

        records.sort(key=lambda item: item.get('disclosure_date') or '', reverse=True)

        cves = []
        for item in records:
            if len(cves) >= limit:
                break
            cve = self.to_cve(item)
            if cve.is_valid():
                cves.append(cve)

        return cves

    def to_cve(self, record):
        cve = CVEInfo()
        cve.src = self.NAME_CH()

        identifier = str(record.get('id') or '').strip()
        cve.url = DETAIL_URL + identifier if identifier else ''

        cve.id = self._identifier(record)
        cve.title = self._title(record)
        cve.info = record.get('summary') or ''
        cve.time = record.get('disclosure_date') or record.get('created_at') or ''
        cve.level = SEVERITY_MAP.get((record.get('severity') or '').lower(), '')

        return cve

    def _identifier(self, record):
        for key in ('cve_id', 'cnnvd_id', 'cnvd_id', 'ct_id'):
            value = (record.get(key) or '').strip()
            if value:
                return value.upper() if value.upper().startswith('CVE-') else value
        return ''

    def _title(self, record):
        title = (record.get('title') or '').strip()
        cleaned = CVE_SUFFIX.sub('', title).strip()
        if cleaned:
            return cleaned
        # 标题本身可能就是「CVE-2026-129492」这类纯编号
        found = CVE_PATTERN.search(title)
        return found.group(0).upper() if found else title
