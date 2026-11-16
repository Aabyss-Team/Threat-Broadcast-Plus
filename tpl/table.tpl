    <section class="source-card is-collapsed" id="$anchor" data-source="$src_raw">
        <header class="source-head">
            <button class="source-toggle" type="button" aria-expanded="false" aria-controls="${anchor}-body">
                <span class="toggle-icon" aria-hidden="true"></span>
                <span class="source-heading">
                    <span class="source-name" role="heading" aria-level="2">$src</span>
                    <span class="source-meta">最近更新 $latest · <span class="card-count" data-total="$count">$count 条</span></span>
                </span>
            </button>
            <a class="source-more" href="$home" target="_blank" rel="noopener">访问来源 <span aria-hidden="true">→</span></a>
        </header>
        <div class="source-body" id="${anchor}-body">
            <div class="table-wrap">
                <table>
                    <caption class="sr-only">$src 最新威胁情报</caption>
                    <thead>
                        <tr>
                            <th scope="col" class="col-id">编号</th>
                            <th scope="col" class="col-level">等级</th>
                            <th scope="col" class="col-time">披露时间</th>
                            <th scope="col" class="col-title">漏洞标题</th>
                            <th scope="col" class="col-link">详情</th>
                        </tr>
                    </thead>
                    <tbody>
$rows
                    </tbody>
                </table>
            </div>
        </div>
    </section>
