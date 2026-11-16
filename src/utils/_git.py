#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/5/1 22:31
# @File   : _git.py
# -----------------------------------------------
# Git 自动提交与 GitHub GraphQL 查询
# -----------------------------------------------

import os
import subprocess
from datetime import datetime

import requests

import src.config as config
from src.bean.cve_info import CST
from src.logger import log

GRAPHQL_QUERY = """
query($owner: String!, $repo: String!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $repo) {
    issues(first: $first, after: $after, states: OPEN,
           orderBy: {field: UPDATED_AT, direction: DESC}) {
      edges {
        node {
          title
          url
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}
"""


def _run(args):
    return subprocess.run(
        args,
        cwd=config.PRJ_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='replace',
    )


def auto_commit(message=None):
    """把本次生成的文件提交并推送到当前分支。"""
    if not os.path.isdir(os.path.join(config.PRJ_DIR, '.git')):
        log.warning('[Git] 当前目录不是 Git 仓库，跳过自动提交')
        return False

    message = message or '[Threat-Broadcast] %s' % datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')

    try:
        added = _run(['git', 'add', '-A'])
        if added.returncode != 0:
            log.error('[Git] git add 失败：%s' % added.stderr.strip())
            return False

        diff = _run(['git', 'diff', '--cached', '--quiet'])
        if diff.returncode == 0:
            log.info('[Git] 没有需要提交的变更')
            return False

        committed = _run(['git', 'commit', '-m', message])
        if committed.returncode != 0:
            log.error('[Git] git commit 失败：%s' % committed.stderr.strip())
            return False

        pushed = _run(['git', 'push'])
        if pushed.returncode != 0:
            log.error('[Git] git push 失败：%s' % pushed.stderr.strip())
            return False

        log.info('[Git] 提交并推送成功：%s' % message)
        return True
    except OSError as error:
        log.error('[Git] 执行 git 命令失败：%s' % error)
        return False


def query_issues(github_token, owner=None, repo=None, page_size=100):
    """查询仓库中所有未关闭 Issue 的标题（用于收集订阅邮箱）。"""
    owner = owner or config.settings.get('github', 'owner', 'Aabyss-Team')
    repo = repo or config.settings.get('github', 'repo', 'threat-broadcast')
    endpoint = config.settings.get('github', 'graphql', 'https://api.github.com/graphql')
    headers = {
        'Authorization': 'Bearer %s' % github_token,
        'Content-Type': 'application/json',
        'User-Agent': 'threat-broadcast',
    }

    titles = []
    cursor = None
    for _ in range(20):        # 最多 20 页，避免异常情况下死循环
        try:
            response = requests.post(
                endpoint,
                json={
                    'query': GRAPHQL_QUERY,
                    'variables': {
                        'owner': owner,
                        'repo': repo,
                        'first': page_size,
                        'after': cursor,
                    },
                },
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as error:
            log.warning('[GitHub] GraphQL 请求失败：%s' % error)
            break

        if response.status_code != 200:
            log.warning('[GitHub] GraphQL 返回 HTTP %s' % response.status_code)
            break

        try:
            payload = response.json()
        except ValueError:
            log.warning('[GitHub] GraphQL 返回内容不是 JSON')
            break

        if payload.get('errors'):
            log.warning('[GitHub] GraphQL 返回错误：%s' % payload['errors'])
            break

        repository = (payload.get('data') or {}).get('repository') or {}
        issues = repository.get('issues') or {}
        for edge in issues.get('edges') or []:
            node = edge.get('node') or {}
            title = node.get('title') or ''
            if title:
                titles.append(title)

        page_info = issues.get('pageInfo') or {}
        if not page_info.get('hasNextPage'):
            break

        next_cursor = page_info.get('endCursor')
        if not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor

    return titles
