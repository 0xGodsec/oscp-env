#!/bin/bash
# md2report.sh — convert an OSCP markdown report to styled PDF (+ optional DOCX).
# No pandoc needed: markdown -> HTML (python-markdown) -> PDF (weasyprint),
# and HTML -> DOCX (libreoffice). Run this on your final report before submitting.
#
# Usage:  md2report.sh <report.md> [-d]     (-d also makes a .docx)
#         output files land next to the input.
MD="$1"; DOCX=0; [ "$2" = "-d" ] && DOCX=1
[ -z "$MD" ] || [ ! -f "$MD" ] && { echo "Usage: md2report.sh <report.md> [-d]"; exit 1; }
BASE="${MD%.md}"; HTML="$BASE.html"; PDF="$BASE.pdf"

python3 - "$MD" "$HTML" <<'PY'
import sys, markdown
src, out = sys.argv[1], sys.argv[2]
body = markdown.markdown(open(src, encoding='utf-8').read(),
    extensions=['tables','fenced_code','toc','sane_lists'])
CSS = """
@page { size: A4; margin: 2cm; @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size:9px; color:#888; } }
body { font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 11px; line-height: 1.5; color:#1a1a1a; }
h1 { color:#0b5394; border-bottom:3px solid #0b5394; padding-bottom:6px; font-size:22px; }
h2 { color:#0b5394; border-bottom:1px solid #ccc; padding-bottom:3px; margin-top:22px; font-size:16px; }
h3 { color:#333; font-size:13px; margin-top:16px; }
code { background:#f4f4f4; padding:1px 4px; border-radius:3px; font-family:'DejaVu Sans Mono',monospace; font-size:10px; }
pre { background:#1e1e1e; color:#e6e6e6; padding:10px; border-radius:5px; overflow-x:auto; }
pre code { background:none; color:#e6e6e6; font-size:9.5px; }
table { border-collapse:collapse; width:100%; margin:10px 0; font-size:10px; }
th,td { border:1px solid #bbb; padding:5px 8px; text-align:left; }
th { background:#0b5394; color:#fff; }
tr:nth-child(even){ background:#f6f9fc; }
blockquote { border-left:4px solid #f0ad4e; background:#fff8ec; margin:8px 0; padding:6px 12px; color:#664d03; }
"""
html = f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{body}</body></html>"
open(out,'w',encoding='utf-8').write(html)
print(f"  [+] HTML -> {out}")
PY
[ -f "$HTML" ] || { echo "[!] HTML build failed"; exit 2; }

python3 -c "import weasyprint,sys; weasyprint.HTML('$HTML').write_pdf('$PDF')" \
  && echo "  [+] PDF  -> $PDF ($(du -h "$PDF"|cut -f1))" || echo "  [!] PDF build failed"

if [ "$DOCX" = 1 ]; then
  libreoffice --headless -env:UserInstallation=file:///tmp/lo_profile \
    --infilter="HTML (StarWriter)" --convert-to "docx:MS Word 2007 XML" \
    --outdir "$(dirname "$MD")" "$HTML" >/dev/null 2>&1 \
    && echo "  [+] DOCX -> $BASE.docx" || echo "  [!] DOCX build failed"
fi
rm -f "$HTML"
