from typing import List, Tuple
from datetime import datetime
import html as htmllib

class MXTHTMLReporter:
    def __init__(self) -> None:
        pass

    def status_class(self, status: str) -> str:
        s = (status or '').lower()
        if s in ('failed', 'error'):
            return 'failed'
        if s == 'warning':
            return 'warning'
        if s == 'passed':
            return 'passed'
        if s == 'timeout':
            return 'timeout'
        return 'unknown'

    def _priority(self, status: str) -> int:
        s = (status or '').lower()
        if s in ('failed', 'error'):
            return 0
        if s == 'warning':
            return 1
        if s == 'passed':
            return 2
        if s == 'timeout':
            return 3
        return 4

    def build_domain_table(self, rows: List[List[str]]) -> str:
        # Сортировка по критичности: Failed -> Warning -> Passed -> Timeout -> остальные
        sorted_rows = sorted(rows, key=lambda r: (self._priority(r[0]), r[1])) if rows else []

        def row_html(r: List[str]) -> str:
            status, name, info, url = r
            css = self.status_class(status)
            info_html = htmllib.escape(info)
            name_html = htmllib.escape(name)
            more = f'<a href="{url}" target="_blank">More Info</a>' if url else ''
            return f'<tr class="{css}"><td class="status">{status}</td><td class="name">{name_html}</td><td class="info">{info_html} {more}</td></tr>'
        table_rows = '\n'.join(row_html(r) for r in sorted_rows) if sorted_rows else '<tr><td colspan="3">No items</td></tr>'
        return f"""
<table class=\"table\">
  <thead><tr><th>Status</th><th>Test</th><th>Info</th></tr></thead>
  <tbody>
    {table_rows}
  </tbody>
</table>
"""

    def build_plain_table(self, headers: List[str], rows: List[List[str]], raw_html_cols: List[int] | None = None) -> str:
        head_html = ''.join(f'<th>{htmllib.escape(h)}</th>' for h in headers)
        raw_set = set(raw_html_cols or [])
        def row_html(r: List[str]) -> str:
            tds = []
            for idx, c in enumerate(r):
                if idx in raw_set:
                    tds.append(f'<td>{str(c)}</td>')
                else:
                    tds.append(f'<td>{htmllib.escape(str(c))}</td>')
            cols = ''.join(tds)
            return f'<tr>{cols}</tr>'
        body = '\n'.join(row_html(r) for r in rows) if rows else '<tr><td colspan="{len(headers)}">No items</td></tr>'
        return f"""
<table class=\"table\">
  <thead><tr>{head_html}</tr></thead>
  <tbody>
    {body}
  </tbody>
</table>
"""

    def wrap_global(self, sections: List[Tuple[str, str]], title: str = "Report", footer: str = "") -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        items_html = []
        for idx, (dom, tbl) in enumerate(sections):
            dom_e = htmllib.escape(dom)
            items_html.append(f"""
<div class=\"domain-section\" id=\"dom-{idx}\">
  <h3 class=\"domain-header\" onclick=\"this.parentElement.classList.toggle('open')\">{dom_e} <span class=\"toggle\">▼</span></h3>
  <div class=\"records\">{tbl}</div>
</div>
""")
        content = '\n'.join(items_html)
        return f"""
<!DOCTYPE html>
<html lang=\"ru\">
<head>
<meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<title>{htmllib.escape(title)}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; background:#f7f9fb; color:#1f2937; }}
.container {{ max-width: 1100px; margin: auto; background:#fff; border:1px solid #e5e7eb; border-radius:8px; box-shadow:0 4px 10px rgba(0,0,0,.04); }}
.header {{ padding: 18px 22px; border-bottom:1px solid #e5e7eb; display:flex; justify-content:space-between; align-items:center; }}
.header h1 {{ margin:0; font-size:20px; }}
.header .meta {{ color:#6b7280; font-size:13px; }}
.table {{ width:100%; border-collapse:collapse; }}
.table th, .table td {{ padding:12px 14px; border-bottom:1px solid #eef2f7; vertical-align:top; }}
.table th {{ background:#f8fafc; text-align:left; font-weight:600; color:#374151; }}
tr.failed {{ background:#fff1f2; }}
tr.warning {{ background:#fff7ed; }}
tr.passed {{ background:#f0fdf4; }}
tr.timeout {{ background:#f3f4f6; }}
.status {{ width:110px; font-weight:600; text-transform:capitalize; }}
.name {{ width:320px; }}
.info a {{ color:#2563eb; text-decoration:none; }}
.info a:hover {{ text-decoration:underline; }}
.domain-section {{ border-top:1px solid #e5e7eb; }}
.domain-header {{ margin:0; padding:14px 18px; cursor:pointer; user-select:none; }}
.domain-header .toggle {{ font-size:12px; color:#6b7280; margin-left:6px; }}
.records {{ display:none; padding: 0 18px 18px; }}
.domain-section.open .records {{ display:block; }}
.footer {{ padding: 12px 14px; color:#6b7280; font-size:12px; border-top:1px solid #e5e7eb; }}
</style>
</head>
<body>
<div class=\"container\">
  <div class=\"header\"><h1>{htmllib.escape(title)}</h1><div class=\"meta\">Generated: {timestamp}</div></div>
  {content}
  <div class=\"footer\">{htmllib.escape(footer) if footer else ''}</div>
</div>
</body>
</html>
"""
