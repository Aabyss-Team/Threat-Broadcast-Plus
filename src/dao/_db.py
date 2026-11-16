#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# SQLite 连接、建表、迁移与归档清理
# -----------------------------------------------

import os
import sqlite3

import src.config as config
from src.bean.cve_info import cve_md5
from src.logger import log


def db_path():
    path = config.settings.get('database', 'dbpath', './data/cves.db')
    if not os.path.isabs(path):
        path = os.path.join(config.PRJ_DIR, path)
    return os.path.normpath(path)


def sql_path():
    path = config.settings.get('database', 'sqlpath', './script/cves-create.sql')
    if not os.path.isabs(path):
        path = os.path.join(config.PRJ_DIR, path)
    return os.path.normpath(path)


def connect():
    path = db_path()
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)

    conn = sqlite3.connect(path, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout = 60000')
    return conn


def _columns(conn, table):
    try:
        rows = conn.execute('PRAGMA table_info(%s)' % table).fetchall()
        return set(row['name'] for row in rows)
    except Exception:
        return set()


def init(conn):
    """建表 + 兼容旧库迁移 + 去重 + 索引。"""
    path = sql_path()
    if os.path.exists(path):
        with open(path, 'r', encoding=config.CHARSET) as file:
            conn.executescript(file.read())
    else:
        log.warning('建表脚本不存在：%s' % path)

    columns = _columns(conn, 't_cves')
    if columns and 's_level' not in columns:
        conn.execute("ALTER TABLE t_cves ADD COLUMN s_level TEXT DEFAULT ''")
        log.info('数据库迁移：已新增字段 s_level')

    # 旧版本会根据 标题/编号/链接 生成 MD5，但未建立唯一约束，可能产生重复行
    duplicated = conn.execute(
        'SELECT COUNT(1) FROM (SELECT s_md5 FROM t_cves GROUP BY s_md5 HAVING COUNT(1) > 1)'
    ).fetchone()[0]
    if duplicated:
        conn.execute(
            'DELETE FROM t_cves WHERE rowid NOT IN '
            '(SELECT MIN(rowid) FROM t_cves GROUP BY s_md5)'
        )
        log.info('数据库去重：清理重复记录 %d 条' % duplicated)

    conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS uq_t_cves_md5 ON t_cves(s_md5)')
    conn.commit()

    _migrate_md5(conn)


def _migrate_md5(conn):
    """把旧版「编号+标题+链接」的去重键迁移为稳定的「来源+编号+链接」。

    旧算法在情报来源修改标题后会生成新的 MD5，导致同一条 CVE 被重复播报。
    """
    version = conn.execute('PRAGMA user_version').fetchone()[0]
    if version >= 3:
        return

    rows = conn.execute(
        'SELECT rowid, s_md5, s_src, s_cves, s_url, s_title '
        'FROM t_cves ORDER BY s_time DESC, rowid DESC'
    ).fetchall()

    seen = set()
    updated = 0
    removed = 0
    for row in rows:
        key = cve_md5(row['s_src'], row['s_cves'], row['s_url'], row['s_title'])
        if key in seen:
            conn.execute('DELETE FROM t_cves WHERE rowid = ?', (row['rowid'],))
            removed += 1
            continue
        seen.add(key)

        if row['s_md5'] != key:
            cursor = conn.execute(
                'UPDATE OR IGNORE t_cves SET s_md5 = ? WHERE rowid = ?',
                (key, row['rowid'])
            )
            if cursor.rowcount == 0:
                conn.execute('DELETE FROM t_cves WHERE rowid = ?', (row['rowid'],))
                removed += 1
            else:
                updated += 1

    conn.execute('PRAGMA user_version = 3')
    conn.commit()
    if updated or removed:
        log.info('数据库迁移：重算去重键 %d 条，清理重复记录 %d 条' % (updated, removed))


def prune(conn):
    """限制归档体积，避免 data/cves.db 在每次 Actions 提交中无限膨胀。"""
    retain_days = int(config.settings.get('database', 'retain_days', 365) or 365)
    max_rows = int(config.settings.get('database', 'max_rows_per_src', 3000) or 3000)

    before = conn.execute('SELECT COUNT(1) FROM t_cves').fetchone()[0]
    deleted = 0

    # 清理历史上解析失败、时间字段非法的脏数据（例如 'yt'）
    cursor = conn.execute(
        "DELETE FROM t_cves WHERE s_time IS NULL OR s_time = '' "
        "OR s_time NOT GLOB '20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]*'"
    )
    deleted += cursor.rowcount or 0

    if retain_days > 0:
        cutoff = conn.execute(
            "SELECT strftime('%Y-%m-%d %H:%M:%S', 'now', '+8 hours', ?)",
            ('-%d days' % retain_days,)
        ).fetchone()[0]
        cursor = conn.execute('DELETE FROM t_cves WHERE s_time < ?', (cutoff,))
        deleted += cursor.rowcount or 0

    if max_rows > 0:
        srcs = [row[0] for row in conn.execute('SELECT DISTINCT s_src FROM t_cves')]
        for src in srcs:
            cursor = conn.execute(
                'DELETE FROM t_cves WHERE rowid IN ('
                'SELECT rowid FROM t_cves WHERE s_src = ? '
                'ORDER BY s_time DESC LIMIT -1 OFFSET ?)',
                (src, max_rows)
            )
            deleted += cursor.rowcount or 0

    conn.commit()

    after = conn.execute('SELECT COUNT(1) FROM t_cves').fetchone()[0]
    if deleted > 0:
        log.info('归档清理：删除 %d 条，保留 %d 条' % (deleted, after))

    # 只有大量删除才整理磁盘，避免每次 Actions 都重写整库
    if deleted > 500 or before == 0:
        try:
            conn.execute('VACUUM')
            conn.commit()
        except Exception as error:
            log.warning('数据库整理失败：%s' % error)

    try:
        conn.execute('PRAGMA optimize')
    except Exception:
        pass

    return deleted


def size():
    try:
        return os.path.getsize(db_path())
    except OSError:
        return 0


def close(conn):
    if conn is None:
        return
    try:
        conn.commit()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass
