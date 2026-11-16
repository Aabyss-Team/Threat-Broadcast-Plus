#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File   : avd.py
# -----------------------------------------------
# 阿里云高危漏洞库：https://avd.aliyun.com/high-risk/list
#
# 说明：
#   - 该页面由阿里云 WAF 保护，直接 requests 可能只拿到 JS 挑战页；
#   - 此时回退到 r.jina.ai 的只读渲染结果，解析其中的 Markdown 表格；
#   - 列表每页 30 条，60 条需要 2 页。
# -----------------------------------------------

import math
import re
from urllib.parse import urljoin

from lxml import etree

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

HIGH_RISK_URL = 'https://avd.aliyun.com/high-risk/list'
JINA_URL = 'https://r.jina.ai/http://avd.aliyun.com/high-risk/list?page=%d'
PAGE_SIZE = 30
MAX_PAGES = 10

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
CVE_SUFFIX = re.compile(r'\s*[（(]\s*CVE-\d{4}-\d{4,}\s*[)）]\s*$', re.IGNORECASE)
DATE_PATTERN = re.compile(r'\d{4}-\d{2}-\d{2}')
AVD_LINK = re.compile(r'\[(AVD-[^\]]+)\]\((https?://[^)]+)\)')


def _text(element):
    """兼容 lxml.etree._Element，提取节点内全部文本。"""
    return ''.join(element.itertext()).strip()


class AliyunAVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '阿里云高危漏洞库'
        self.name_en = 'AliyunAVDHighRisk'
        self.home_page = HIGH_RISK_URL
        self.url = HIGH_RISK_URL

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=60):
        pages = min(max(1, int(math.ceil(float(limit) / PAGE_SIZE))), MAX_PAGES)
        records = []
        seen = set()
        use_jina = False

        for page in range(1, pages + 1):
            rows = None
            if not use_jina:
                rows = self._from_direct(page)
            if not rows:
                use_jina = True
                rows = self._from_jina(page)
            if not rows:
                break

            for row in rows:
                key = row.get('avd_id') or row.get('url') or row.get('title')
                if not key or key in seen:
                    continue
                seen.add(key)
                records.append(row)

            if len(records) >= limit:
                break

        records.sort(key=lambda item: item.get('date') or '', reverse=True)

        cves = []
        for record in records:
            if len(cves) >= limit:
                break
            cve = self.to_cve(record)
            if cve.is_valid():
                cves.append(cve)
        return cves

    def _from_direct(self, page):
        """优先直接解析服务端 HTML；遇到 WAF 挑战时返回空列表。"""
        try:
            response = self.get(self.url, params={'page': page})
        except Exception as error:
            log.debug('直连 [%s] 第 %d 页失败：%s' % (self.NAME_CH(), page, error))
            return []

        if response.status_code != 200:
            return []

        response.encoding = 'utf-8'
        try:
            doc = etree.HTML(response.text)
        except Exception:
            return []

        records = []
        for row in doc.xpath('//table//tr'):
            links = row.xpath('.//a[contains(@href, "/detail?id=AVD-")]')
            if not links:
                continue

            cells = row.xpath('./td')
            if len(cells) < 4:
                continue

            title = _text(cells[1])
            date = _text(cells[3])
            if not title:
                continue

            records.append({
                'avd_id': (links[0].text or '').strip(),
                'title': title,
                'date': date,
                'url': urljoin(self.home_page, links[0].get('href') or ''),
            })
        return records

    def _from_jina(self, page):
        """WAF 挑战页无法直接解析时，使用只读渲染服务取 Markdown 表格。"""
        try:
            response = self.get(
                JINA_URL % page,
                headers={'Accept': 'text/plain, text/markdown, */*'},
            )
        except Exception as error:
            log.warning('获取 [%s] 第 %d 页失败：%s' % (self.NAME_CH(), page, error))
            return []

        if response.status_code != 200:
            log.warning('获取 [%s] 第 %d 页失败：HTTP %s'
                        % (self.NAME_CH(), page, response.status_code))
            return []

        records = []
        for line in response.text.splitlines():
            if 'avd.aliyun.com/detail?id=' not in line:
                continue

            cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
            if len(cells) < 4:
                continue

            link = AVD_LINK.search(cells[0])
            if not link:
                continue

            title = cells[1]
            date = ''
            for cell in cells[2:]:
                found = DATE_PATTERN.search(cell)
                if found:
                    date = found.group(0)
                    break

            records.append({
                'avd_id': link.group(1).strip(),
                'title': title,
                'date': date,
                'url': link.group(2).strip(),
            })

        if not records:
            log.warning('解析 [%s] 第 %d 页失败：未找到漏洞行' % (self.NAME_CH(), page))
        return records

    def to_cve(self, record):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.url = record.get('url') or ''
        cve.time = record.get('date') or ''
        cve.level = 'HIGH'       # 高危漏洞库，全部按高危处理
        cve.info = record.get('title') or ''

        title = record.get('title') or ''
        cve.title = CVE_SUFFIX.sub('', title).strip() or title

        found = CVE_PATTERN.search(title)
        cve.id = found.group(0).upper() if found else (record.get('avd_id') or '')
        return cve
