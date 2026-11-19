#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# 危害等级归一化：把各来源的等级描述 / CVSS 分值映射到统一词汇
# 统一词汇：CRITICAL / HIGH / MEDIUM / LOW（空串表示未知）
# -----------------------------------------------

LEVELS = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

_ALIASES = {
    'MODERATE': 'MEDIUM',
    'IMPORTANT': 'HIGH',
    '严重': 'CRITICAL',
    '高危': 'HIGH',
    '中危': 'MEDIUM',
    '低危': 'LOW',
}


def normalize(value):
    """把来源自带的等级描述归一化；无法识别（含 NONE / 未知）时返回空串。"""
    text = str(value or '').strip().upper()
    text = _ALIASES.get(text, text)
    return text if text in LEVELS else ''


def from_score(score, version='3'):
    """按 CVSS 分值推断等级；分值为 0 或非法时返回空串。"""
    try:
        number = float(score)
    except (TypeError, ValueError):
        return ''
    if not 0 < number <= 10:
        return ''
    if number >= 9 and not str(version).startswith('2'):
        return 'CRITICAL'
    if number >= 7:
        return 'HIGH'
    return 'MEDIUM' if number >= 4 else 'LOW'
