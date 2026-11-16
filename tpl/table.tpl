    <section class="source-card" id="$anchor" data-source="$src_raw">
        <header class="source-head">
            <div>
                <h2 class="source-name"><a href="$home" target="_blank" rel="noopener">$src</a></h2>
                <p class="source-meta">最近更新 $latest · <span class="card-count" data-total="$count">$count 条</span></p>
            </div>
            <a class="source-more" href="$home" target="_blank" rel="noopener">访问来源 <span aria-hidden="true">→</span></a>
        </header>
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
    </section>
