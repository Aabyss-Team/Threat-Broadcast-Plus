#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/29 23:31
# @File   : _base.py
# -----------------------------------------------
# 数据访问对象：基类（基于 Python 标准库 sqlite3）
# -----------------------------------------------

from src.logger import log


class BaseDao(object):
    """Dao 基类，子类只需声明表名与 SQL。"""

    TABLE_NAME = ""
    SQL_COUNT = ""
    SQL_TRUNCATE = ""
    SQL_INSERT = ""
    SQL_DELETE = ""
    SQL_SELECT = ""
    CHARSET = "utf-8"

    def __init__(self):
        pass

    def count(self, conn):
        try:
            return conn.execute(self.SQL_COUNT).fetchone()[0]
        except Exception as error:
            log.error("统计表 [%s] 行数失败：%s" % (self.TABLE_NAME, error))
            return 0

    def truncate(self, conn):
        try:
            conn.execute(self.SQL_TRUNCATE)
            conn.commit()
            return True
        except Exception as error:
            log.error("清空表 [%s] 失败：%s" % (self.TABLE_NAME, error))
            return False

    def insert(self, conn, bean):
        try:
            conn.execute(self.SQL_INSERT, bean.params())
            conn.commit()
            return True
        except Exception as error:
            log.error("插入数据到表 [%s] 失败：%s" % (self.TABLE_NAME, error))
            return False

    def insert_all(self, conn, beans):
        """批量插入，一次提交；返回实际新增行数，发生异常时返回 -1。"""
        if not beans:
            return 0

        before = conn.total_changes
        try:
            conn.executemany(self.SQL_INSERT, [bean.params() for bean in beans])
            conn.commit()
        except Exception as error:
            log.error("批量插入数据到表 [%s] 失败：%s" % (self.TABLE_NAME, error))
            try:
                conn.rollback()
            except Exception:
                pass
            return -1
        return conn.total_changes - before

    def delete(self, conn, wheres=None):
        wheres = wheres or {}
        try:
            sql = self._append(self.SQL_DELETE, wheres.keys())
            conn.execute(sql, tuple(wheres.values()))
            conn.commit()
            return True
        except Exception as error:
            log.error("从表 [%s] 删除数据失败：%s" % (self.TABLE_NAME, error))
            return False

    def query_all(self, conn):
        return self.query_some(conn)

    def query_some(self, conn, wheres=None):
        wheres = wheres or {}
        beans = []
        try:
            sql = self._append(self.SQL_SELECT, wheres.keys())
            rows = conn.execute(sql, tuple(wheres.values())).fetchall()
            for row in rows:
                bean = self._to_bean(row)
                if bean is not None:
                    beans.append(bean)
        except Exception as error:
            log.error("从表 [%s] 查询数据失败：%s" % (self.TABLE_NAME, error))
        return beans

    def query_one(self, conn, wheres=None):
        wheres = wheres or {}
        try:
            sql = self._append(self.SQL_SELECT, wheres.keys())
            row = conn.execute(sql, tuple(wheres.values())).fetchone()
            return self._to_bean(row)
        except Exception as error:
            log.error("从表 [%s] 查询数据失败：%s" % (self.TABLE_NAME, error))
            return None

    def _append(self, sql, keys):
        """追加 where 条件，条件之间为 and 关系；值使用 ? 占位符防注入。"""
        text = sql
        for key in keys:
            text = "%s and %s ?" % (text, key)
        return text

    def _to_bean(self, row):
        # 需子类实现
        return row

    def _to_val(self, row, key):
        """按列名或列下标取值；不存在时返回 None。"""
        if row is None:
            return None
        try:
            return row[key]
        except (IndexError, KeyError, TypeError):
            return None
