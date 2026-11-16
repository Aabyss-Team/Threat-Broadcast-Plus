#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : nvd.py
# -----------------------------------------------
# NVD：https://nvd.nist.gov/
#
# 旧版 RSS 源（nvd-rss-analyzed.xml）已于 2023 年下线。
# 现在优先读取官方 2.0 recent JSON 源（约 8 天数据，1~2MB，无频率限制）：
#   https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz
# 若该源不可用，再回退到 REST API 2.0：
#   https://services.nvd.nist.gov/rest/json/cves/2.0
# -----------------------------------------------

import gzip
import json
import os
from datetime import datetime, timedelta, timezone

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

FEED_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz'
API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
DETAIL_URL = 'https://nvd.nist.gov/vuln/detail/'
# API 回退时查询最近 N 天；单次最多返回 2000 条
WINDOW_DAYS = 2
MAX_RESULTS = 2000


class NVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '美国国家漏洞数据库（NVD）'
        self.name_en = 'NVD'
        self.home_page = 'https://nvd.nist.gov/'
        self.url = FEED_URL

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def headers(self):
        headers = BaseCrawler.headers(self)
        token = os.environ.get('NVD_API_KEY', '').strip()
        if token:
            headers['apiKey'] = token
        return headers

    def get_cves(self, limit=60):
        vulnerabilities = self._from_feed()
        if vulnerabilities is None:
            vulnerabilities = self._from_api()

        if not vulnerabilities:
            return []

        vulnerabilities.sort(
            key=lambda item: (item.get('cve') or {}).get('published') or '',
            reverse=True,
        )

        cves = []
        for item in vulnerabilities:
            if len(cves) >= limit:
                break

            cve_data = item.get('cve') or {}
            if (cve_data.get('vulnStatus') or '').lower() == 'rejected':
                continue

            cve = self.to_cve(cve_data)
            if cve.is_valid():
                cves.append(cve)

        return cves

    def _from_feed(self):
        try:
            response = self.get(self.url, timeout=max(self.timeout, 90))
        except Exception as error:
            log.warning('获取 [%s] JSON 源失败：%s' % (self.NAME_CH(), error))
            return None

        if response.status_code != 200:
            log.warning('获取 [%s] JSON 源失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return None

        try:
            raw = response.content
            try:
                payload = json.loads(raw.decode('utf-8'))
            except (UnicodeDecodeError, ValueError):
                # 官方源是 .json.gz；若中间层已自动解压则直接按 JSON 读取
                payload = json.loads(gzip.decompress(raw).decode('utf-8'))
            return payload.get('vulnerabilities') or []
        except (OSError, ValueError) as error:
            log.warning('解析 [%s] JSON 源失败：%s' % (self.NAME_CH(), error))
            return None

    def _from_api(self):
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=WINDOW_DAYS)
        params = {
            'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': MAX_RESULTS,
        }

        log.info('[%s] 正在回退到 REST API ...' % self.NAME_CH())
        try:
            response = self.get(API_URL, params=params, timeout=max(self.timeout, 90))
        except Exception as error:
            log.warning('获取 [%s] REST API 失败：%s' % (self.NAME_CH(), error))
            return []

        if response.status_code != 200:
            log.warning('获取 [%s] REST API 失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        try:
            return (response.json() or {}).get('vulnerabilities') or []
        except ValueError as error:
            log.warning('解析 [%s] REST API 失败：%s' % (self.NAME_CH(), error))
            return []

    def to_cve(self, cve_data):
        cve = CVEInfo()
        cve.id = cve_data.get('id') or ''
        cve.src = self.NAME_CH()
        cve.url = DETAIL_URL + cve.id
        cve.time = cve_data.get('published') or ''

        descriptions = cve_data.get('descriptions') or []
        description = ''
        for item in descriptions:
            if item.get('lang') == 'en':
                description = item.get('value') or ''
                break
        if not description and descriptions:
            description = descriptions[0].get('value') or ''

        cve.title = description
        cve.info = description
        cve.level = self._severity(cve_data)
        return cve

    def _severity(self, cve_data):
        metrics = cve_data.get('metrics') or {}
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            entries = metrics.get(key)
            if not entries:
                continue
            entry = entries[0] or {}
            cvss_data = entry.get('cvssData') or {}
            severity = cvss_data.get('baseSeverity') or entry.get('baseSeverity')
            if severity:
                return severity
        return ''
