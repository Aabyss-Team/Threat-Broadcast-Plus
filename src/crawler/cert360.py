#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : cert360.py
# -----------------------------------------------
# 360：https://cert.360.cn/warning
#
# 注意：cert.360.cn 对部分海外 IP / 云主机做了访问限制，
# 在 GitHub Actions（美国节点）上偶尔会握手失败。失败时只记录告警，不影响其它来源。
# -----------------------------------------------

import json
import re

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.logger import log

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


class Cert360(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '360 网络安全响应中心'
        self.name_en = 'cert360'
        self.home_page = 'https://cert.360.cn/warning'
        self.url_list = 'https://cert.360.cn/warning/searchbypage'
        self.url_cve = 'https://cert.360.cn/warning/detail?id='

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def headers(self):
        headers = BaseCrawler.headers(self)
        headers['Referer'] = self.home_page
        headers['X-Requested-With'] = 'XMLHttpRequest'
        return headers

    def get_cves(self, limit=60):
        params = {'length': limit, 'start': 0}

        response = self.get(self.url_list, params=params)
        if response.status_code != 200:
            log.warning('获取 [%s] 威胁情报失败：HTTP %s' % (self.NAME_CH(), response.status_code))
            return []

        try:
            payload = json.loads(response.text)
        except ValueError:
            log.warning('获取 [%s] 威胁情报失败：接口未返回 JSON（可能被风控或接口已变更）'
                        % self.NAME_CH())
            return []

        records = payload.get('data')
        if isinstance(records, dict):
            records = records.get('data') or records.get('list') or records.get('results')
        if not isinstance(records, list):
            log.warning('获取 [%s] 威胁情报失败：返回结构异常' % self.NAME_CH())
            return []

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

        identifier = record.get('id') or record.get('warning_id') or ''
        cve.url = self.url_cve + str(identifier)

        title = record.get('title') or ''
        cve.title = re.sub(r'^\s*CVE-\d{4}-\d{4,}\s*[:：]\s*', '', title, flags=re.IGNORECASE).strip()
        cve.info = (record.get('description') or '').strip()

        found = CVE_PATTERN.search(title)
        cve.id = found.group(0).upper() if found else ''

        # update_time / add_time 可能是时间戳、日期字符串或已格式化的本地时间
        timestamp = record.get('update_time') or record.get('add_time') or record.get('publish_time')
        cve.set_time(timestamp)

        level = record.get('level') or record.get('risk_level') or record.get('severity')
        if level:
            cve.set_level(level)

        return cve
