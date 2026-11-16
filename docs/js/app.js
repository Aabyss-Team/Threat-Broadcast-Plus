/* ============================================================
   威胁情报播报 · 页面交互
   - 来源卡片折叠 / 展开
   - 关键词、危害等级、时间范围筛选
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

    /* --------------------------- 来源卡片折叠 --------------------------- */

    var cards = Array.prototype.slice.call(doc.querySelectorAll('.source-card'));
    var toggleAllButton = doc.getElementById('toggle-all');

    function setExpanded(card, expanded) {
        var button = card.querySelector('.source-toggle');
        if (!button) {
            return;
        }
        button.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        card.classList.toggle('is-collapsed', !expanded);
    }

    function isExpanded(card) {
        return !card.classList.contains('is-collapsed');
    }

    function visibleRows(card) {
        return card.querySelectorAll('tr[data-search]:not([hidden])').length;
    }

    function allExpanded() {
        return cards.length > 0 && cards.every(isExpanded);
    }

    function updateToggleAll() {
        if (!toggleAllButton) {
            return;
        }
        var expanded = allExpanded();
        toggleAllButton.textContent = expanded ? '收起全部' : '展开全部';
        toggleAllButton.setAttribute('aria-pressed', expanded ? 'true' : 'false');
    }

    cards.forEach(function (card) {
        // 默认收起；没有 JS 时卡片仍然完整可见
        setExpanded(card, false);
        var button = card.querySelector('.source-toggle');
        if (button) {
            button.addEventListener('click', function () {
                setExpanded(card, !isExpanded(card));
                updateToggleAll();
            });
        }
    });

    if (toggleAllButton) {
        toggleAllButton.addEventListener('click', function () {
            var expand = !allExpanded();
            cards.forEach(function (card) {
                setExpanded(card, expand);
            });
            updateToggleAll();
        });
    }

    updateToggleAll();

    // 点击来源导航时同时展开对应卡片
    Array.prototype.slice.call(doc.querySelectorAll('.source-nav .chip')).forEach(function (chip) {
        chip.addEventListener('click', function () {
            var target = (chip.getAttribute('href') || '').replace('#', '');
            var card = target ? doc.getElementById(target) : null;
            if (card) {
                setExpanded(card, true);
                updateToggleAll();
            }
        });
    });

    /* ---------------------------- 搜索与筛选 ---------------------------- */

    var input = doc.getElementById('search');
    var levelSelect = doc.getElementById('filter-level');
    var timeSelect = doc.getElementById('filter-time');
    var noResults = doc.getElementById('no-results');
    var rows = Array.prototype.slice.call(doc.querySelectorAll('tr[data-search]'));
    var DAY_SECONDS = 24 * 60 * 60;

    function updateCount(card, visible) {
        var counter = card.querySelector('.card-count');
        if (!counter) {
            return;
        }
        var total = counter.getAttribute('data-total') || '0';
        counter.textContent = visible + ' / ' + total + ' 条';
    }

    function matches(row, keyword, level, days) {
        var text = row.getAttribute('data-search') || '';
        if (keyword && text.indexOf(keyword) === -1) {
            return false;
        }

        if (level && level !== 'all' && row.getAttribute('data-level') !== level) {
            return false;
        }

        if (days && days !== 'all') {
            var timestamp = Number(row.getAttribute('data-ts') || 0);
            if (!timestamp || timestamp < (Date.now() / 1000 - Number(days) * DAY_SECONDS)) {
                return false;
            }
        }

        return true;
    }

    function filterRows() {
        var keyword = input ? (input.value || '').trim().toLowerCase() : '';
        var level = levelSelect ? levelSelect.value : 'all';
        var days = timeSelect ? timeSelect.value : 'all';
        var hasFilter = !!keyword || level !== 'all' || days !== 'all';
        var matchedRows = 0;

        rows.forEach(function (row) {
            var matched = matches(row, keyword, level, days);
            row.hidden = !matched;
            if (matched) {
                matchedRows += 1;
            }
        });

        cards.forEach(function (card) {
            var visible = visibleRows(card);
            card.hidden = visible === 0;
            updateCount(card, visible);

            // 筛选时自动展开有结果的来源，避免结果藏在折叠面板里
            if (hasFilter && visible > 0) {
                setExpanded(card, true);
            }
        });

        if (noResults) {
            noResults.hidden = matchedRows !== 0;
        }
        updateToggleAll();
    }

    if (input) {
        input.addEventListener('input', filterRows);
    }
    if (levelSelect) {
        levelSelect.addEventListener('change', filterRows);
    }
    if (timeSelect) {
        timeSelect.addEventListener('change', filterRows);
    }

    /* ------------------------------- 快捷键 ------------------------------- */

    doc.addEventListener('keydown', function (event) {
        var tag = (event.target && event.target.tagName || '').toLowerCase();

        if (event.key === '/' && tag !== 'input' && tag !== 'textarea' && tag !== 'select') {
            if (input) {
                event.preventDefault();
                input.focus();
                input.select();
            }
        } else if (event.key === 'Escape' && tag === 'input' && input) {
            input.value = '';
            if (levelSelect) {
                levelSelect.value = 'all';
            }
            if (timeSelect) {
                timeSelect.value = 'all';
            }
            filterRows();
            input.blur();
        }
    });
})();
