#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : threatbook.py
# -----------------------------------------------
# 微步在线 X 情报中心：https://x.threatbook.com/v5/vulIntelligence
#
# 公开的漏洞公告列表接口（无需登录，每页最多 10 条）：
#   GET https://x.threatbook.com/v5/node/vul_module/notice/next
#       ?page=1&pageSize=10
#
# 漏洞详情页需要登录，但列表接口本身是公开的，详情链接仍然指向官方页面。
# -----------------------------------------------

from datetime import datetime, timedelta

from src.bean.cve_info import CST, CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

API_URL = 'https://x.threatbook.com/v5/node/vul_module/notice/next'
DETAIL_URL = 'https://x.threatbook.com/v5/vul?id='
HOME_PAGE = 'https://x.threatbook.com/v5/vulIntelligence'

PAGE_SIZE = 10
MAX_PAGES = 12
# 只保留最近一年披露的公告，避免把多年前的旧漏洞当作最新情报展示
RECENT_DAYS = 365

RISK_MAP = {
    '严重': 'CRITICAL',
    '严重风险': 'CRITICAL',
    '高风险': 'HIGH',
    '中风险': 'MEDIUM',
    '低风险': 'LOW',
}


class ThreatBook(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '微步在线情报中心'
        self.name_en = 'ThreatBook'
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
        # 列表接口按「更新时间」排序，不是按「披露时间」。
        # 因此多取几页后按披露时间重排，保证页面展示的是真正最新的 N 条。
        items = []
        seen = set()
        for page in range(1, MAX_PAGES + 1):
            response = self.get(self.url, params={'page': page, 'pageSize': PAGE_SIZE})
            if response.status_code == 204:
                break
            if response.status_code != 200:
                log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
                break

            try:
                payload = response.json()
            except ValueError as error:
                log.warning('解析 [%s] 返回的 JSON 失败：%s' % (self.NAME_CH(), error))
                break

            data = payload.get('data') or {}
            batch = data.get('items') or []
            if not batch:
                break

            for item in batch:
                key = self._record_key(item)
                if key in seen:
                    continue
                seen.add(key)
                items.append(item)

            if len(batch) < PAGE_SIZE:
                break

        items.sort(key=self._publish_time, reverse=True)
        cutoff = (datetime.now(CST) - timedelta(days=RECENT_DAYS)).strftime('%Y-%m-%d %H:%M:%S')

        cves = []
        for item in items:
            if len(cves) >= limit:
                break
            cve = self.to_cve(item)
            if not cve.is_valid():
                continue
            # 公告接口里混有大量多年前、近期被重新维护的旧漏洞，按披露时间过滤
            if not cve.time or cve.time < cutoff:
                continue
            cves.append(cve)

        return cves

    def _record_key(self, item):
        identifiers = item.get('id') or []
        if isinstance(identifiers, str):
            identifiers = [identifiers]
        if identifiers:
            return '|'.join(str(identifier) for identifier in identifiers)
        return (item.get('xveId') or item.get('title') or '').strip()

    def to_cve(self, item):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.title = (item.get('title') or '').strip()
        cve.time = self._publish_time(item)
        cve.level = RISK_MAP.get((item.get('riskLevel') or '').strip(), '')

        identifiers = item.get('id') or []
        if isinstance(identifiers, str):
            identifiers = [identifiers]

        cve_id = ''
        for identifier in identifiers:
            if str(identifier).upper().startswith('CVE-'):
                cve_id = str(identifier).upper()
                break

        xve_id = (item.get('xveId') or '').strip()
        cve.id = cve_id or xve_id
        cve.url = DETAIL_URL + cve.id if cve.id else ''
        cve.info = cve.title
        return cve

    def _publish_time(self, item):
        timelines = item.get('timelines') or []

        # 优先取「漏洞公开」时间；找不到时退回时间线中最早的一条
        for entry in timelines:
            for description in entry.get('descriptions') or []:
                if description.get('field') == 'VULN_PUBLISH_TIME':
                    return entry.get('timeline') or ''

        if timelines:
            return timelines[-1].get('timeline') or ''
        return ''
