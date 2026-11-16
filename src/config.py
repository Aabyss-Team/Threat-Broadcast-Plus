#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 21:56
# -----------------------------------------------
# 配置加载：YAML + 环境变量占位符
#
# 占位符写法： <%= ENV['MAIL_PASS'] %>
# 解析顺序：先按 YAML 语法解析，再把字符串里的占位符替换成同名环境变量。
# 这样即使密码/Token 里包含引号、冒号、# 等特殊字符，也不会破坏 YAML 结构。
# -----------------------------------------------

import os
import re

import yaml

PRJ_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
CHARSET = 'utf-8'
SETTINGS_PATH = '%s/config/settings.yml' % PRJ_DIR

# <%= ENV['NAME'] %> / <%= ENV["NAME"] %>
_ENV_PATTERN = re.compile(r"<%=\s*ENV\[\s*['\"]([^'\"]+)['\"]\s*\]\s*%>")

DEFAULT_SETTINGS = {
    'database': {
        'dbtype': 'sqlite',
        'dbpath': './data/cves.db',
        'sqlpath': './script/cves-create.sql',
        'retain_days': 365,
        'max_rows_per_src': 3000,
    },
    'github': {
        'graphql': 'https://api.github.com/graphql',
        'repo': 'threat-broadcast',
        'owner': 'Aabyss-Team',
        'gtk': '',
        'auto_commit': False,
    },
    'crawler': {
        'top': 60,
        'timeout': 45,
    },
    'notify': {
        'mail_smtp': 'smtp.qq.com',
        'mail_port': 465,
        'mail_user': '',
        'mail_pass': '',
        'wechat_webhook': '',
        'serverchan_key': '',
        'pushplus_token': '',
    },
    'kimi': {
        'api_key': '',
        'api_url': 'https://api.kimi.com/coding/v1/chat/completions',
        'model': 'k3',
        'reasoning_effort': 'low',
        'days': 5,
        'max_items': 30,
        'max_tokens': 800,
    },
}


def _expand_env(value):
    """递归地把配置里的 <%= ENV['X'] %> 替换成环境变量。"""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ''), value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def _merge(base, override):
    """浅合并：只补全缺失的顶层配置段和键，不覆盖已有值。"""
    merged = {}
    for key, value in base.items():
        merged[key] = dict(value) if isinstance(value, dict) else value

    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


class Config(object):

    def __init__(self, settings_path, charset):
        self._charset = charset
        self._data = {}

        raw = {}
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r', encoding=charset) as file:
                    raw = yaml.safe_load(file.read()) or {}
            except Exception as error:      # 配置写错时给出明确提示，而不是静默失败
                raise RuntimeError('配置文件解析失败：%s（%s）' % (settings_path, error))

        if not isinstance(raw, dict):
            raw = {}

        self._data = _expand_env(_merge(DEFAULT_SETTINGS, raw))

    # 允许 settings.database / settings.notify 这样的点号访问
    def __getattr__(self, name):
        data = object.__getattribute__(self, '_data')
        if name in data:
            return data[name]
        raise AttributeError(name)

    def section(self, name):
        value = self._data.get(name)
        return value if isinstance(value, dict) else {}

    def get(self, section, key, default=None):
        value = self.section(section).get(key, default)
        return default if value is None else value

    def as_dict(self):
        return self._data


settings = Config(SETTINGS_PATH, CHARSET)
