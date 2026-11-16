#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : tophant.py
# -----------------------------------------------
# 斗象漏洞情报中心：https://vip.tophant.com/intellList
#
# 页面是 Nuxt SSR，列表数据来自公开 JSON 接口：
#   POST https://vip.tophant.com/api/data/vuln_list
#   参数：{"page":1,"pageSize":60,"keyword":"CVE-","publishTimeSort":0}
#
# keyword 传 "CVE-" 可以覆盖所有年份的 CVE，避免写死 "CVE-2026" 后跨年失效。
# -----------------------------------------------

import re

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

API_URL = 'https://vip.tophant.com/api/data/vuln_list'
DETAIL_URL = 'https://vip.tophant.com/detail/'
HOME_PAGE = 'https://vip.tophant.com/intellList'

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
CVE_PREFIX = re.compile(r'^\s*[（(]\s*CVE-\d{4}-\d{4,}\s*[)）]\s*', re.IGNORECASE)
CVE_SUFFIX = re.compile(r'\s*[（(]\s*CVE-\d{4}-\d{4,}\s*[)）]\s*$', re.IGNORECASE)

LEVEL_MAP = {
    'serious': 'CRITICAL',
    'critical': 'CRITICAL',
    'high_risk': 'HIGH',
    'medium_risk': 'MEDIUM',
    'low_risk': 'LOW',
}


class Tophant(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '斗象漏洞情报中心'
        self.name_en = 'Tophant'
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
        headers['Content-Type'] = 'application/json; charset=UTF-8'
        headers['Origin'] = 'https://vip.tophant.com'
        headers['Referer'] = HOME_PAGE
        return headers

    def get_cves(self, limit=60):
        page_size = max(1, min(int(limit), 100))
        payload = {
            'page': 1,
            'pageSize': page_size,
            'keyword': 'CVE-',
            'publishTimeSort': 0,       # 0 = 按披露时间倒序
        }

        response = self.post(self.url, json=payload, timeout=max(self.timeout, 60))
        if response.status_code != 200:
            log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        try:
            data = response.json()
        except ValueError as error:
            log.warning('解析 [%s] 返回的 JSON 失败：%s' % (self.NAME_CH(), error))
            return []

        if str(data.get('errorCode')) not in ('00000', '0'):
            log.warning('获取 [%s] 威胁情报失败：%s' % (self.NAME_CH(), data.get('errorMessage')))
            return []

        records = (data.get('data') or {}).get('records') or []
        cves = []
        for record in records:
            if len(cves) >= limit:
                break

            cve = self.to_cve(record)
            if cve.is_valid():
                cves.append(cve)

        return cves

    def to_cve(self, record):
        cve = CVEInfo()
        cve.src = self.NAME_CH()

        identifier = str(record.get('id') or '')
        cve.url = DETAIL_URL + identifier if identifier else ''

        name = (record.get('vulnName') or '').strip()
        cve.id = (record.get('vulnCveCode') or '').strip().upper()
        if not cve.id:
            found = CVE_PATTERN.search(name)
            if found:
                cve.id = found.group(0).upper()

        title = CVE_PREFIX.sub('', name)
        title = CVE_SUFFIX.sub('', title).strip()
        if not title or title.upper() == cve.id:
            title = name or cve.id
        cve.title = title
        cve.info = name

        cve.time = record.get('publishTime') or record.get('collectTime') or ''
        cve.level = LEVEL_MAP.get((record.get('riskLevel') or '').lower(), '')

        return cve
