#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------------------
# 统一日志：输出到 stdout，兼容 GitHub Actions 日志
# -----------------------------------------------

import logging
import os
import sys

_LEVELS = {
    'DEBUG': '36',      # cyan
    'INFO': '32',       # green
    'WARNING': '33',    # yellow
    'ERROR': '31',      # red
    'CRITICAL': '35',   # magenta
}

_RESET = '\033[0m'


class _Formatter(logging.Formatter):

    def __init__(self, color=False):
        logging.Formatter.__init__(self, '%(asctime)s | %(levelname)-7s | %(message)s', '%H:%M:%S')
        self.color = color

    def format(self, record):
        text = logging.Formatter.format(self, record)
        if self.color:
            color = _LEVELS.get(record.levelname)
            if color:
                text = '\033[%sm%s%s' % (color, text, _RESET)
        return text


class _Logger(object):
    """对 logging 的轻量封装，保留 info/error/warning/warn/debug/exception 接口。"""

    def __init__(self):
        self._logger = logging.getLogger('threat-broadcast')
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

    def setup(self, level='INFO'):
        for handler in list(self._logger.handlers):
            self._logger.removeHandler(handler)

        handler = logging.StreamHandler(sys.stdout)
        color = sys.stdout.isatty() and not os.environ.get('NO_COLOR')
        handler.setFormatter(_Formatter(color=color))
        self._logger.addHandler(handler)
        self._logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
        return self

    def _fmt(self, message, args):
        if args:
            try:
                return str(message) % args
            except Exception:
                return '%s %s' % (message, ' '.join(str(arg) for arg in args))
        return str(message)

    def debug(self, message, *args):
        self._logger.debug(self._fmt(message, args))

    def info(self, message, *args):
        self._logger.info(self._fmt(message, args))

    def warning(self, message, *args):
        self._logger.warning(self._fmt(message, args))

    # 兼容旧代码里的 log.warn
    def warn(self, message, *args):
        self._logger.warning(self._fmt(message, args))

    def error(self, message, *args):
        self._logger.error(self._fmt(message, args))

    def exception(self, message, *args):
        self._logger.exception(self._fmt(message, args))

    def critical(self, message, *args):
        self._logger.critical(self._fmt(message, args))


log = _Logger().setup(os.environ.get('LOG_LEVEL', 'INFO'))
