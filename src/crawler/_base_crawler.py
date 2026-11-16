#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : _base_crawler.py
# -----------------------------------------------

import os
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import src.config as config
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao
from src.dao import _db
from src.logger import log

# 缓存文件只保存 MD5，用于跨次运行去重
CACHE_MAX_LINES = 1000
CACHE_KEEP_LINES = 500


class BaseCrawler(object):
    """爬虫基类：统一网络会话、重试、缓存去重与入库。"""

    def __init__(self, timeout=None, charset=None):
        self.timeout = timeout or int(config.settings.get('crawler', 'timeout', 45) or 45)
        self.charset = charset or config.CHARSET
        self._session = None

    @property
    def session(self):
        # 延迟创建，确保子类先完成自身属性初始化（headers 可能依赖这些属性）
        if self._session is None:
            self._session = self._build_session()
        return self._session

    # ---------------- 子类需要实现的信息 ----------------

    def NAME_CH(self):
        return '未知来源'

    def NAME_EN(self):
        return 'unknown'

    def HOME_PAGE(self):
        return 'https://github.com/Aabyss-Team/threat-broadcast'

    def CACHE_PATH(self):
        name = self.NAME_EN().replace(' ', '_').replace('(', '').replace(')', '')
        return '%s/cache/%s.dat' % (config.PRJ_DIR, name)

    # ---------------- 网络请求 ----------------

    def headers(self):
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.7',
            'Connection': 'keep-alive',
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'),
        }

    def _build_session(self):
        session = requests.Session()
        session.headers.update(self.headers())
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(('GET', 'POST')),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def get(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        kwargs.setdefault('timeout', self.timeout)
        return self.session.post(url, **kwargs)

    def close(self):
        if self._session is None:
            return
        try:
            self._session.close()
        except Exception:
            pass
        self._session = None

    # ---------------- 主流程 ----------------

    def cves(self, conn=None, limit=None):
        """抓取 -> 过滤 -> 去重 -> 入库 -> 写缓存。"""
        limit = limit or int(config.settings.get('crawler', 'top', 60) or 60)
        own_conn = conn is None
        if own_conn:
            conn = _db.connect()

        started = time.time()
        log.info('------------------------------------------------------------')
        log.info('正在获取 [%s] 威胁情报（上限 %d 条）...' % (self.NAME_CH(), limit))

        old_md5 = self.load_cache()
        try:
            fetched = self.get_cves(limit) or []
        except Exception as error:
            log.error('获取 [%s] 威胁情报失败：%s' % (self.NAME_CH(), error))
            fetched = []

        fresh = []
        seen = set()
        for cve in fetched:
            try:
                cve.src = cve.src or self.NAME_CH()
                cve.normalize()
            except Exception as error:
                log.warning('忽略一条无法解析的 [%s] 情报：%s' % (self.NAME_CH(), error))
                continue

            if not cve.is_valid():
                continue

            md5 = cve.MD5()
            if md5 in old_md5 or md5 in seen:
                continue
            seen.add(md5)
            fresh.append(cve)

        if fresh:
            dao = TCvesDao()
            inserted = dao.insert_all(conn, [self._to_bean(cve) for cve in fresh])

            # 写库异常时不要写缓存，否则这批情报下次会被误判为「已播报」
            if inserted < 0:
                log.error('[%s] 写入数据库失败，本次不播报，下次运行会重试' % self.NAME_CH())
                fresh = []
            else:
                self.to_cache(fresh)
                log.info('得到 [%s] 最新威胁情报 %d 条（本次抓取 %d 条，写入数据库 %d 条）'
                         % (self.NAME_CH(), len(fresh), len(fetched), inserted))

                # 数据库里已存在（例如缓存被清空或去重键刚迁移）时，不再重复播报
                if inserted == 0:
                    log.info('[%s] 情报均已归档，跳过本次播报' % self.NAME_CH())
                    fresh = []
                else:
                    for cve in fresh:
                        log.debug(cve.to_text())
        else:
            log.info('得到 [%s] 最新威胁情报 0 条（本次抓取 %d 条，均已在缓存中）'
                     % (self.NAME_CH(), len(fetched)))

        log.info('[%s] 耗时 %.1f 秒' % (self.NAME_CH(), time.time() - started))

        if own_conn:
            _db.close(conn)
        return fresh

    def get_cves(self, limit=60):
        # 由子类实现
        return []

    def _to_bean(self, cve):
        bean = TCves()
        bean.md5 = cve.MD5()
        bean.src = cve.src
        bean.cves = cve.id
        bean.title = cve.title
        bean.time = cve.time
        bean.info = cve.info
        bean.url = cve.url
        bean.level = cve.level
        return bean

    # ---------------- 缓存 ----------------

    def load_cache(self):
        path = self.CACHE_PATH()
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)

        if not os.path.exists(path):
            open(path, 'a', encoding='utf-8').close()
            return set()

        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as file:
                lines = [line.strip() for line in file if line.strip()]
        except OSError as error:
            log.warning('读取缓存失败（%s）：%s' % (path, error))
            return set()

        # 缓存过大时只保留最近的一部分
        if len(lines) > CACHE_MAX_LINES:
            lines = lines[-CACHE_KEEP_LINES:]
            self._write_cache(lines)

        return set(lines)

    def to_cache(self, cves):
        path = self.CACHE_PATH()
        md5s = [cve.MD5() for cve in cves]
        if not md5s:
            return
        try:
            with open(path, 'a+', encoding='utf-8') as file:
                file.seek(0, os.SEEK_END)
                if file.tell() > 0:
                    file.seek(file.tell() - 1)
                    if file.read(1) != '\n':
                        file.write('\n')
                file.write('\n'.join(md5s) + '\n')
        except OSError as error:
            log.warning('写入缓存失败（%s）：%s' % (path, error))

    def _write_cache(self, lines):
        path = self.CACHE_PATH()
        temp = path + '.tmp'
        try:
            with open(temp, 'w', encoding='utf-8') as file:
                file.write('\n'.join(lines) + '\n')
            os.replace(temp, path)
        except OSError as error:
            log.warning('整理缓存失败（%s）：%s' % (path, error))
