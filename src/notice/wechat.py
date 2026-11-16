#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/5/2 14:53
# @File   : wechat.py
# -----------------------------------------------
# 通过微信 / 企业微信推送威胁情报
#
# 支持三种免公众号开发的推送方式（配置任意一种即可）：
#   1. 企业微信群机器人  notify.wechat_webhook  <- ENV['WECHAT_WEBHOOK']
#   2. Server酱          notify.serverchan_key  <- ENV['SERVERCHAN_KEY']
#   3. PushPlus          notify.pushplus_token  <- ENV['PUSHPLUS_TOKEN']
#
# 均未配置时静默跳过，不影响主流程。
# -----------------------------------------------

import requests

import src.config as config
from src.bean.cve_info import CST
from src.logger import log
from datetime import datetime

PAGE_URL = 'https://threat.aabyss.cn/'
MAX_CONTENT = 3500


def to_wechat(cves):
    if not cves:
        return False

    webhook = (config.settings.get('notify', 'wechat_webhook', '') or '').strip()
    serverchan = (config.settings.get('notify', 'serverchan_key', '') or '').strip()
    pushplus = (config.settings.get('notify', 'pushplus_token', '') or '').strip()

    if not any((webhook, serverchan, pushplus)):
        log.debug('[微信] 未配置推送渠道，跳过')
        return False

    title = '威胁情报播报 | 新增 %d 条' % _total(cves)
    content = build_markdown(cves)

    sent = False
    if webhook:
        sent = _send_wecom(webhook, content) or sent
    if serverchan:
        sent = _send_serverchan(serverchan, title, content) or sent
    if pushplus:
        sent = _send_pushplus(pushplus, title, content) or sent
    return sent


def _total(cves):
    return sum(len(items) for items in cves.values())


def build_markdown(cves):
    lines = [
        '## 威胁情报播报',
        '> 新增 **%d** 条 · %s' % (_total(cves), datetime.now(CST).strftime('%Y-%m-%d %H:%M')),
        '',
    ]

    for src, items in cves.items():
        lines.append('**%s**（%d 条）' % (src.NAME_CH(), len(items)))
        for cve in items[:5]:
            title = (cve.title or '').strip()
            if len(title) > 80:
                title = title[:80] + '…'
            identifier = cve.id or '详情'
            if cve.url:
                lines.append('- [%s](%s) %s' % (identifier, cve.url, title))
            else:
                lines.append('- %s %s' % (identifier, title))
        if len(items) > 5:
            lines.append('- 其余 %d 条请查看完整播报' % (len(items) - 5))
        lines.append('')

    lines.append('[查看完整播报](%s)' % PAGE_URL)
    text = '\n'.join(lines)
    return text[:MAX_CONTENT]


def _post(url, **kwargs):
    kwargs.setdefault('timeout', 20)
    response = requests.post(url, **kwargs)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return {}


def _send_wecom(webhook, content):
    # 企业微信 markdown 限制 4096 字节，中文按 UTF-8 计算会超过字符数
    content = _truncate_bytes(content, 3900)
    try:
        result = _post(webhook, json={
            'msgtype': 'markdown',
            'markdown': {'content': content},
        })
        if result.get('errcode') == 0:
            log.info('[微信] 企业微信机器人推送成功')
            return True
        log.warning('[微信] 企业微信机器人推送失败：%s' % result)
    except Exception as error:
        log.warning('[微信] 企业微信机器人推送异常：%s' % error)
    return False


def _truncate_bytes(text, max_bytes):
    data = text.encode('utf-8')
    if len(data) <= max_bytes:
        return text
    return data[:max_bytes].decode('utf-8', 'ignore').rstrip() + '\n…'


def _send_serverchan(key, title, content):
    try:
        result = _post('https://sctapi.ftqq.com/%s.send' % key, data={
            'title': title[:32],
            'desp': content,
        })
        if result.get('code') == 0:
            log.info('[微信] Server酱推送成功')
            return True
        log.warning('[微信] Server酱推送失败：%s' % result)
    except Exception as error:
        log.warning('[微信] Server酱推送异常：%s' % error)
    return False


def _send_pushplus(token, title, content):
    try:
        result = _post('https://www.pushplus.plus/send', json={
            'token': token,
            'title': title,
            'content': content,
            'template': 'markdown',
        })
        if result.get('code') == 200:
            log.info('[微信] PushPlus 推送成功')
            return True
        log.warning('[微信] PushPlus 推送失败：%s' % result)
    except Exception as error:
        log.warning('[微信] PushPlus 推送异常：%s' % error)
    return False
