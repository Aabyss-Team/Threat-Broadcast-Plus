#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : tenable.py
# -----------------------------------------------
# Tenable：https://www.tenable.com/cve/feeds?sort=newest
# -----------------------------------------------

import re

from lxml import etree

from src.bean.cve_info import CVEInfo, clean_text
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

FEED_URL = 'https://www.tenable.com/cve/feeds?sort=newest'

SEVERITY_PATTERN = re.compile(r'(Critical|High|Medium|Low)\s+Severity', re.IGNORECASE)
DESCRIPTION_PATTERN = re.compile(r'<h3>\s*Description\s*</h3>\s*<p>(.*?)</p>', re.IGNORECASE | re.DOTALL)


class Tenable(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'Tenable (Nessus)'
        self.name_en = 'Tenable'
        self.home_page = 'https://www.tenable.com/'
        self.url = FEED_URL

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=60):
        response = self.get(self.url, timeout=max(self.timeout, 60))
        if response.status_code != 200:
            log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        try:
            root = etree.fromstring(response.content)
        except etree.XMLSyntaxError as error:
            log.warning('解析 [%s] RSS 失败：%s' % (self.NAME_CH(), error))
            return []

        cves = []
        for item in root.xpath('//item'):
            if len(cves) >= limit:
                break
            cve = self.to_cve(item)
            if cve.is_valid():
                cves.append(cve)

        return cves

    def to_cve(self, item):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.id = (item.findtext('title') or '').strip()
        cve.url = (item.findtext('link') or '').strip()
        cve.time = (item.findtext('pubDate') or '').strip()

        description = item.findtext('description') or ''
        severity = SEVERITY_PATTERN.search(description)
        if severity:
            cve.set_level(severity.group(1))

        match = DESCRIPTION_PATTERN.search(description)
        if match:
            text = clean_text(match.group(1))
        else:
            text = clean_text(description)

        cve.title = text
        cve.info = text
        return cve
