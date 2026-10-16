#!/usr/bin/env python3
"""Render docs/*.md into self-contained, themed HTML pages.

markdown (python-markdown) -> standalone HTML with a light/dark theme, a
generated table-of-contents sidebar, and Pygments-highlighted code blocks.
Each page is fully self-contained (inline CSS) so it works offline and can be
opened or served directly from docs/.

Usage:
    python3 docs/build_docs.py                 # rebuild the default doc set
    python3 docs/build_docs.py FILE.md ...      # build specific files
Output lands next to each input as <base>.html.
"""
import html
import os
import sys

import markdown
from markdown.extensions.toc import TocExtension
from pygments.formatters import HtmlFormatter

HERE = os.path.dirname(os.path.abspath(__file__))

# Default set when run with no arguments.
DEFAULT_DOCS = [
    "index.md",
    "10_Commands_Quick_Reference.md",
    "11_Code_And_Exploits.md",
    "12_Exam_Day_Runbook.md",
    "13_Tool_Cheatsheets.md",
]

# Palette lifted from the existing Triage.html docs for visual consistency.
# Code blocks use a dark "terminal" background in BOTH themes (like Triage),
# so a dark Pygments style stays readable regardless of the page theme.
BASE_CSS = """
:root{
  color-scheme: light dark;
  --bg:#f4f6f8; --surface:#fff; --surface-2:#eef1f4;
  --fg:#16202a; --muted:#5a6b7a; --faint:#8595a3; --border:#d8dee4;
  --accent:#1f6feb; --accent-soft:#e6f0ff;
  --term-bg:#0d1b24; --term-fg:#d6e6ef;
  --shadow:0 1px 3px rgba(20,32,42,.08), 0 6px 20px rgba(20,32,42,.05);
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]){
    --bg:#0b1016; --surface:#141b23; --surface-2:#1b2430;
    --fg:#d6e0ea; --muted:#8595a3; --faint:#61707e; --border:#263140;
    --accent:#4f9dff; --accent-soft:#14263c;
    --shadow:0 1px 3px rgba(0,0,0,.45), 0 6px 20px rgba(0,0,0,.35);
  }
}
:root[data-theme=dark]{
  --bg:#0b1016; --surface:#141b23; --surface-2:#1b2430;
  --fg:#d6e0ea; --muted:#8595a3; --faint:#61707e; --border:#263140;
  --accent:#4f9dff; --accent-soft:#14263c;
  --shadow:0 1px 3px rgba(0,0,0,.45), 0 6px 20px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth; scroll-padding-top:70px}
body{margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 var(--sans);
  -webkit-text-size-adjust:100%}
a{color:var(--accent); text-decoration:none}
a:hover{text-decoration:underline}
.topbar{position:sticky; top:0; z-index:20; background:var(--surface);
  border-bottom:1px solid var(--border); box-shadow:var(--shadow)}
.topbar .wrap{max-width:1180px; margin:0 auto; padding:12px 20px;
  display:flex; align-items:center; gap:12px}
.brand{font-weight:700; letter-spacing:.3px}
.brand .dot{color:var(--accent)}
#themeBtn{margin-left:auto; cursor:pointer; border:1px solid var(--border);
  background:var(--surface-2); color:var(--fg); border-radius:8px;
  padding:6px 12px; font:inherit; font-size:13px}
.layout{max-width:1180px; margin:0 auto; display:grid;
  grid-template-columns:260px minmax(0,1fr); gap:28px; padding:22px 20px 80px}
.sidebar{position:sticky; top:70px; align-self:start; max-height:calc(100vh - 90px);
  overflow:auto}
.toc-title{font-size:12px; text-transform:uppercase; letter-spacing:.08em;
  color:var(--faint); margin:4px 0 8px}
.toc ul{list-style:none; margin:0; padding:0 0 0 2px}
.toc li{margin:1px 0}
.toc a{display:block; padding:3px 8px; border-left:2px solid transparent;
  color:var(--muted); font-size:13.5px; border-radius:0 6px 6px 0}
.toc a:hover{color:var(--fg); background:var(--surface-2); text-decoration:none}
.toc .lvl-3 a{padding-left:20px; font-size:12.5px}
.toc .lvl-4 a{padding-left:32px; font-size:12px}
.content{min-width:0; background:var(--surface); border:1px solid var(--border);
  border-radius:14px; box-shadow:var(--shadow); padding:34px 40px}
.content>*:first-child{margin-top:0}
h1,h2,h3,h4{line-height:1.25; scroll-margin-top:72px}
h1{font-size:30px; margin:0 0 18px; padding-bottom:12px;
  border-bottom:2px solid var(--border)}
h2{font-size:22px; margin:34px 0 12px; padding-bottom:6px;
  border-bottom:1px solid var(--border)}
h3{font-size:17px; margin:24px 0 8px}
h4{font-size:15px; margin:18px 0 6px; color:var(--muted)}
p,li{overflow-wrap:anywhere}
code{font-family:var(--mono); font-size:.88em; background:var(--surface-2);
  border:1px solid var(--border); border-radius:5px; padding:.08em .38em}
pre{background:var(--term-bg); color:var(--term-fg); border-radius:10px;
  padding:14px 16px; overflow:auto; font-size:13px; line-height:1.5;
  border:1px solid #0a141b}
pre code{background:none; border:0; padding:0; color:inherit; font-size:inherit}
blockquote{margin:14px 0; padding:10px 16px; border-left:4px solid var(--accent);
  background:var(--accent-soft); border-radius:0 8px 8px 0; color:var(--fg)}
blockquote>*:first-child{margin-top:0} blockquote>*:last-child{margin-bottom:0}
table{border-collapse:collapse; width:100%; margin:14px 0; font-size:13.5px;
  display:block; overflow-x:auto}
th,td{border:1px solid var(--border); padding:7px 11px; text-align:left;
  vertical-align:top}
th{background:var(--surface-2); font-weight:600}
tr:nth-child(even) td{background:var(--surface-2)}
hr{border:0; border-top:1px solid var(--border); margin:28px 0}
img{max-width:100%; height:auto}
.headerlink{opacity:0; margin-left:.4em; font-weight:400; color:var(--faint)}
h1:hover .headerlink,h2:hover .headerlink,h3:hover .headerlink,
h4:hover .headerlink{opacity:1; text-decoration:none}
@media (max-width:860px){
  .layout{grid-template-columns:1fr; gap:0}
  .sidebar{position:static; max-height:none; margin-bottom:18px;
    border:1px solid var(--border); border-radius:12px; padding:12px 14px;
    background:var(--surface)}
  .content{padding:22px 18px; border-radius:12px}
}
"""

# Dark code-highlighting theme (works on the dark terminal background used in
# both page themes). Scoped to .codehilite so it never touches inline code.
PYGMENTS_CSS = HtmlFormatter(style="native").get_style_defs(".codehilite")


def render_toc(tokens):
    """Build a nested <ul> TOC from markdown's toc_tokens, skipping the page
    title (the single top-level H1) and rendering H2..H4."""
    def walk(items):
        out = []
        for it in items:
            lvl = it.get("level", 2)
            if lvl == 1:            # the page's H1 title -> not in the nav
                out += walk(it.get("children", []))
                continue
            if lvl > 4:
                continue
            # toc_tokens names are already HTML-escaped by markdown; don't re-escape.
            name = it.get("name", "") or ""
            out.append(f'<li class="lvl-{lvl}"><a href="#{it["id"]}">{name}</a>')
            kids = walk(it.get("children", []))
            if kids:
                out.append(f"<ul>{kids}</ul>")
            out.append("</li>")
        return "".join(out)

    inner = walk(tokens)
    if not inner:
        return ""
    return f'<div class="toc-title">On this page</div><ul>{inner}</ul>'


def page_title(tokens, fallback):
    # toc_tokens names are already HTML-escaped by markdown; safe in <title>.
    for it in tokens:
        if it.get("level") == 1 and it.get("name"):
            return it["name"]
    return html.escape(fallback)


def convert(src_path, out_path=None):
    with open(src_path, encoding="utf-8") as f:
        text = f.read()
    md = markdown.Markdown(extensions=[
        "tables", "fenced_code", "codehilite", "sane_lists",
        "attr_list", "md_in_html",
        # 1-4: keep the H1 in toc_tokens so page_title() can read it; the nav
        # itself skips level 1 (see render_toc), so it only lists H2..H4.
        TocExtension(permalink=True, toc_depth="1-4"),
    ], extension_configs={
        "codehilite": {"guess_lang": False, "css_class": "codehilite"},
    })
    body = md.convert(text)
    toc = render_toc(getattr(md, "toc_tokens", []))
    base = os.path.splitext(os.path.basename(src_path))[0]
    title = page_title(getattr(md, "toc_tokens", []), base)
    out_path = out_path or os.path.join(os.path.dirname(src_path), base + ".html")

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{title}</title>
<style>{BASE_CSS}{PYGMENTS_CSS}</style>
</head>
<body>
<header class="topbar"><div class="wrap">
  <span class="brand">OSCP Env<span class="dot"> / </span>Docs</span>
  <button id="themeBtn" type="button" aria-label="Toggle theme">Theme</button>
</div></header>
<div class="layout">
  <aside class="sidebar"><nav class="toc">{toc}</nav></aside>
  <main class="content">{body}</main>
</div>
<script>
(function(){{
  var KEY="oscp-docs-theme", root=document.documentElement,
      btn=document.getElementById("themeBtn");
  try{{ var s=localStorage.getItem(KEY); if(s) root.setAttribute("data-theme",s); }}catch(e){{}}
  btn.addEventListener("click", function(){{
    var cur=root.getAttribute("data-theme");
    if(!cur){{ cur=matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"; }}
    var next=cur==="dark"?"light":"dark";
    root.setAttribute("data-theme",next);
    try{{ localStorage.setItem(KEY,next); }}catch(e){{}}
  }});
}})();
</script>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


def main(argv):
    files = argv or [os.path.join(HERE, d) for d in DEFAULT_DOCS]
    for src in files:
        if not os.path.isfile(src):
            print(f"  [!] skip (not found): {src}")
            continue
        out = convert(src)
        size = os.path.getsize(out)
        print(f"  [+] {os.path.basename(src)} -> {os.path.basename(out)} ({size/1024:.0f} KB)")


if __name__ == "__main__":
    main(sys.argv[1:])
