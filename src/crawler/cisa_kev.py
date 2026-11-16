#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : cisa_kev.py
# -----------------------------------------------
# CISA 已知在野利用漏洞目录（Known Exploited Vulnerabilities）
# https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# 数据源：https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
NVD_DETAIL = 'https://nvd.nist.gov/vuln/detail/'


class CisaKev(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'CISA 在野利用漏洞'
        self.name_en = 'CISAKEV'
        self.home_page = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
        self.url = FEED_URL

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=60):
        response = self.get(self.url, timeout=max(self.timeout, 90))
        if response.status_code != 200:
            log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        try:
            payload = response.json()
        except ValueError as error:
            log.warning('解析 [%s] 返回的 JSON 失败：%s' % (self.NAME_CH(), error))
            return []

        vulnerabilities = payload.get('vulnerabilities') or []
        vulnerabilities.sort(key=lambda item: item.get('dateAdded') or '', reverse=True)

        cves = []
        for item in vulnerabilities:
            if len(cves) >= limit:
                break

            cve_id = (item.get('cveID') or '').strip()
            if not cve_id:
                continue

            vendor = (item.get('vendorProject') or '').strip()
            name = (item.get('vulnerabilityName') or '').strip()

            # 名称里通常已经包含厂商，避免出现「Microsoft：Microsoft ...」这类重复
            prefix = ''
            if vendor:
                first_word = vendor.split()[0].lower()
                if first_word not in name.lower():
                    prefix = vendor

            cve = CVEInfo()
            cve.id = cve_id
            cve.src = self.NAME_CH()
            cve.url = NVD_DETAIL + cve_id
            cve.time = item.get('dateAdded') or ''
            cve.title = ('%s：%s' % (prefix, name)) if prefix else name
            cve.info = item.get('shortDescription') or ''
            cve.level = 'KEV'

            if cve.is_valid():
                cves.append(cve)

        return cves
