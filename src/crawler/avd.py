#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : avd.py
# -----------------------------------------------
# 阿里云漏洞库：https://avd.aliyun.com/
# 说明：页面为服务端渲染，稳定且更新及时，用于替代已停更/反爬的来源
# -----------------------------------------------

import re
from urllib.parse import urljoin

from lxml import etree

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


def _text(element):
    """兼容 lxml.etree._Element，提取节点内全部文本。"""
    return ''.join(element.itertext()).strip()


class AliyunAVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '阿里云漏洞库'
        self.name_en = 'AliyunAVD'
        self.home_page = 'https://avd.aliyun.com/'
        self.url = 'https://avd.aliyun.com/'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=60):
        response = self.get(self.url)
        if response.status_code != 200:
            log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        response.encoding = 'utf-8'
        try:
            doc = etree.HTML(response.text)
        except Exception as error:
            log.warning('解析 [%s] 页面失败：%s' % (self.NAME_CH(), error))
            return []

        cves = []
        rows = doc.xpath('//table//tr')
        for row in rows:
            links = row.xpath('.//a[contains(@href, "/detail?id=AVD-")]')
            if not links:
                continue

            anchor = links[0]
            avd_id = (anchor.text or '').strip()
            href = anchor.get('href') or ''
            cells = row.xpath('./td')
            if len(cells) < 4:
                continue

            title = _text(cells[1])
            published = _text(cells[3])
            if not title:
                continue

            cve = CVEInfo()
            cve.src = self.NAME_CH()
            cve.url = urljoin(self.home_page, href)
            cve.title = re.sub(r'[（(]\s*CVE-\d{4}-\d{4,}\s*[)）]', '', title, flags=re.IGNORECASE).strip()

            found = CVE_PATTERN.search(title)
            cve.id = found.group(0).upper() if found else avd_id
            cve.time = published
            cve.info = title

            if cve.is_valid():
                cves.append(cve)
                if len(cves) >= limit:
                    break

        return cves
