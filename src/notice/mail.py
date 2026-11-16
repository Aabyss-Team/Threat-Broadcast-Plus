#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 23:29
# -----------------------------------------------
# 通过邮件发送威胁情报
# -----------------------------------------------

import html
import os
import re
import smtplib
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr

import src.config as config
from src.bean.cve_info import CST
from src.logger import log
from src.utils import _git

MAIL_RECV_DIR = '%s/recv' % config.PRJ_DIR
MAIL_CONTENT_CACHE = '%s/cache/mail_content.dat' % config.PRJ_DIR
MAIL_RECV_CACHE = '%s/cache/mail_recvs.dat' % config.PRJ_DIR

EMAIL_PATTERN = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def to_mail(gtk, cves, smtp, sender, password, port=465):
    """发送播报邮件；未配置密码时只写缓存，不报错。"""
    if not cves:
        return False

    content = format_content(cves)
    text = format_text(cves)

    receivers = set(load_local_receivers())
    if gtk:
        receivers.update(load_issue_receivers(gtk))
    receivers = sorted(receivers)

    if not password:
        if gtk:
            # 兼容旧版 GitHub Action：把收件人与正文写入 cache，供 action-send-mail 读取
            to_cache(','.join(receivers), MAIL_RECV_CACHE)
            to_cache(content, MAIL_CONTENT_CACHE)
            log.info('[邮件] 未配置 MAIL_PASS，已生成邮件缓存（收件人 %d 个）' % len(receivers))
        else:
            log.warning('[邮件] 未配置邮箱密码，跳过邮件推送')
        return False

    if not receivers:
        log.warning('[邮件] 没有可用收件人，跳过邮件推送')
        return False

    if not sender:
        log.warning('[邮件] 未配置发件邮箱，跳过邮件推送')
        return False

    subject = '威胁情报播报 | 新增 %d 条 | %s' % (
        _total(cves), datetime.now(CST).strftime('%Y-%m-%d')
    )

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = formataddr(('威胁情报播报', sender))
    message['To'] = ', '.join(receivers)
    message.set_content(text)
    message.add_alternative(content, subtype='html')

    log.info('[邮件] 正在向 %d 个收件人推送威胁情报...' % len(receivers))
    try:
        if int(port) == 465:
            server = smtplib.SMTP_SSL(smtp, int(port), timeout=45)
        else:
            server = smtplib.SMTP(smtp, int(port), timeout=45)
            server.starttls()
        try:
            server.login(sender, password)
            server.send_message(message)
        finally:
            try:
                server.quit()
            except Exception:
                pass
        log.info('[邮件] 推送威胁情报成功')
        return True
    except Exception as error:
        log.error('[邮件] 推送威胁情报失败：%s' % error)
        return False


def _total(cves):
    return sum(len(items) for items in cves.values())


def format_content(cves):
    total = _total(cves)
    source_rows = []
    detail_blocks = []

    for src, items in cves.items():
        source_rows.append(
            '<tr>'
            '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">'
            '<a href="%s" style="color:#2563eb;text-decoration:none;">%s</a></td>'
            '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:right;'
            'color:#dc2626;font-weight:700;">%d</td>'
            '</tr>' % (
                html.escape(src.HOME_PAGE(), quote=True),
                html.escape(src.NAME_CH()),
                len(items)
            )
        )
        cards = '\n'.join(cve.to_html() for cve in items)
        detail_blocks.append(
            '<h3 style="margin:28px 0 12px;font-size:16px;color:#111827;">%s '
            '<span style="color:#6b7280;font-weight:400;">(%d)</span></h3>%s'
            % (html.escape(src.NAME_CH()), len(items), cards)
        )

    return '''<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:'PingFang SC','Microsoft YaHei',Arial,sans-serif;color:#111827;">
<div style="max-width:760px;margin:0 auto;padding:24px 16px;">
  <div style="background:linear-gradient(135deg,#0b1220,#1e293b);border-radius:14px;padding:26px 24px;color:#f8fafc;">
    <div style="font-size:12px;letter-spacing:.16em;color:#fca5a5;font-weight:700;">THREAT INTELLIGENCE</div>
    <h1 style="margin:10px 0 6px;font-size:24px;">威胁情报播报</h1>
    <p style="margin:0;color:#cbd5e1;font-size:13px;">发现最新威胁情报 <b style="color:#fca5a5;">%(total)d</b> 条 · 共 %(src_count)d 个来源</p>
  </div>

  <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;margin-top:16px;padding:8px 4px;">
    <table role="presentation" width="100%%" style="border-collapse:collapse;">
      <thead>
        <tr>
          <th style="padding:10px 12px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb;">来源</th>
          <th style="padding:10px 12px;text-align:right;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb;">新增</th>
        </tr>
      </thead>
      <tbody>%(source_rows)s</tbody>
    </table>
  </div>

  <div style="margin-top:8px;">%(details)s</div>

  <div style="margin-top:28px;padding-top:16px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:12px;line-height:1.8;">
    <p style="margin:0;">本邮件由 GitHub Actions 自动生成，情报仅供参考，请以官方通告为准。</p>
    <p style="margin:4px 0 0;">在线播报：<a href="https://threat.aabyss.cn/" style="color:#2563eb;">https://threat.aabyss.cn/</a></p>
    <p style="margin:4px 0 0;">渊龙Sec安全团队 · <a href="https://www.aabyss.cn" style="color:#2563eb;">www.aabyss.cn</a></p>
  </div>
</div>
</body>
</html>''' % {
        'total': total,
        'src_count': len(cves),
        'source_rows': '\n'.join(source_rows),
        'details': '\n'.join(detail_blocks),
    }


def format_text(cves):
    lines = ['威胁情报播报', '=' * 40, '共 %d 个来源 / %d 条情报' % (len(cves), _total(cves)), '']
    for src, items in cves.items():
        lines.append('[%s] %d 条' % (src.NAME_CH(), len(items)))
        for cve in items:
            lines.append('  - %s %s' % (cve.id or '', cve.title or ''))
            if cve.url:
                lines.append('    %s' % cve.url)
        lines.append('')
    lines.append('在线播报：https://threat.aabyss.cn/')
    return '\n'.join(lines)


def load_local_receivers():
    receivers = set()
    if not os.path.isdir(MAIL_RECV_DIR):
        return []

    for fileName in os.listdir(MAIL_RECV_DIR):
        if not (fileName.startswith('mail') and fileName.endswith('.dat')):
            continue
        filePath = os.path.join(MAIL_RECV_DIR, fileName)
        try:
            with open(filePath, 'r', encoding=config.CHARSET) as file:
                for line in file:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    for email in EMAIL_PATTERN.findall(line):
                        receivers.add(email)
        except OSError as error:
            log.warning('[邮件] 读取收件人文件失败（%s）：%s' % (filePath, error))
    return sorted(receivers)


def load_issue_receivers(gtk):
    receivers = set()
    try:
        for issue in _git.query_issues(gtk):
            for email in EMAIL_PATTERN.findall(issue or ''):
                receivers.add(email)
    except Exception as error:
        log.warning('[邮件] 获取 Issue 收件人失败：%s' % error)
    return receivers


def to_cache(content, filepath):
    directory = os.path.dirname(filepath)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    try:
        with open(filepath, 'w', encoding=config.CHARSET) as file:
            file.write(content)
    except OSError as error:
        log.warning('[邮件] 写入缓存失败（%s）：%s' % (filepath, error))
