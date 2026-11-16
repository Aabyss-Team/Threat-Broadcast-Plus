/* ============================================================
   威胁情报播报 · 页面交互
   - 前端搜索过滤
   - 深色 / 浅色主题切换
   - 快捷键：/ 聚焦搜索，Esc 清空
   ============================================================ */

(function () {
    'use strict';

    var doc = document;
    var root = doc.documentElement;
    var THEME_KEY = 'threat-broadcast-theme';

    /* ----------------------------- 主题切换 ----------------------------- */

    var themeButton = doc.getElementById('theme-toggle');
    var themeLabel = doc.getElementById('theme-label');

    function applyTheme(theme) {
        root.setAttribute('data-theme', theme);
        if (themeLabel) {
            themeLabel.textContent = theme === 'dark' ? '浅色' : '深色';
        }
        if (themeButton) {
            themeButton.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
        }
    }

    if (themeButton) {
        var saved = null;
        try {
            saved = window.localStorage.getItem(THEME_KEY);
        } catch (error) {
            saved = null;
        }

        var prefersDark = window.matchMedia &&
            window.matchMedia('(prefers-color-scheme: dark)').matches;
        applyTheme(saved || (prefersDark ? 'dark' : 'light'));

        themeButton.addEventListener('click', function () {
            var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            applyTheme(next);
            try {
                window.localStorage.setItem(THEME_KEY, next);
            } catch (error) {
                /* 隐私模式下忽略 */
            }
        });
    }

    /* ------------------------------ 搜索过滤 ------------------------------ */

    var input = doc.getElementById('search');
    var rows = Array.prototype.slice.call(doc.querySelectorAll('tr[data-search]'));
    var cards = Array.prototype.slice.call(doc.querySelectorAll('.source-card'));
    var noResults = doc.getElementById('no-results');

    function updateCount(card, visible) {
        var counter = card.querySelector('.card-count');
        if (!counter) {
            return;
        }
        var total = counter.getAttribute('data-total') || '0';
        counter.textContent = visible + ' / ' + total + ' 条';
    }

    function filterRows() {
        if (!input) {
            return;
        }

        var keyword = (input.value || '').trim().toLowerCase();
        var visibleRows = 0;

        rows.forEach(function (row) {
            var text = row.getAttribute('data-search') || '';
            var matched = !keyword || text.indexOf(keyword) !== -1;
            row.hidden = !matched;
            if (matched) {
                visibleRows += 1;
            }
        });

        cards.forEach(function (card) {
            var visible = card.querySelectorAll('tr[data-search]:not([hidden])').length;
            card.hidden = visible === 0;
            updateCount(card, visible);
        });

        if (noResults) {
            noResults.hidden = visibleRows !== 0;
        }
    }

    if (input && rows.length) {
        input.addEventListener('input', filterRows);
    }

    /* ------------------------------- 快捷键 ------------------------------- */

    doc.addEventListener('keydown', function (event) {
        var tag = (event.target && event.target.tagName || '').toLowerCase();

        if (event.key === '/' && tag !== 'input' && tag !== 'textarea') {
            if (input) {
                event.preventDefault();
                input.focus();
                input.select();
            }
        } else if (event.key === 'Escape' && tag === 'input' && input) {
            input.value = '';
            filterRows();
            input.blur();
        }
    });
})();
