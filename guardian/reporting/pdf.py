"""Zero-dependency pure-Python PDF generator for Guardian Security Reports.

Converts the Markdown report (`report.md`) into a clean, multi-page PDF 1.4 document
with proper headings, wrapped body text, bullet points, and page numbers.
"""
from pathlib import Path
import textwrap


def _pdf_escape(text: str) -> str:
    # Normalize common Unicode punctuation to Latin-1 / ASCII safe equivalents for PDF Helvetica
    repl = {
        "\u2014": "--", "\u2013": "-", "\u2192": "->", "\u2022": "*",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2265": ">=", "\u2264": "<=", "\u00b7": "|", "\u2026": "...",
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def markdown_to_pdf_bytes(md_text: str, title: str = "Supply Chain Guardian Security Report") -> bytes:
    """Render Markdown text into a valid multi-page PDF byte stream."""
    page_w, page_h = 612, 792  # US Letter
    margin_x, top_y, bottom_y = 48, 742, 52

    # Parse markdown lines into styled blocks: (font, size, leading, text)
    lines_spec = []
    for raw in md_text.splitlines():
        s = raw.rstrip()
        if not s:
            lines_spec.append(("F1", 9, 8, ""))
            continue
        if s.startswith("# "):
            lines_spec.append(("F2", 16, 22, s[2:].strip()))
            lines_spec.append(("F1", 9, 6, ""))
        elif s.startswith("## "):
            lines_spec.append(("F1", 9, 6, ""))
            lines_spec.append(("F2", 12.5, 17, s[3:].strip()))
        elif s.startswith("### "):
            lines_spec.append(("F2", 10.5, 14, s[4:].strip()))
        elif s.startswith("|") and set(s.replace("|", "").replace("-", "").replace(":", "").strip()) == set():
            continue  # skip markdown table separator row
        else:
            clean = s.replace("**", "").replace("`", "")
            if clean.startswith("|") and clean.endswith("|"):
                clean = " | ".join(c.strip() for c in clean.strip("|").split("|"))
            width = 92 if not clean.startswith("- ") else 88
            wrapped = textwrap.wrap(clean, width=width) or [clean]
            for idx, wline in enumerate(wrapped):
                prefix = "  " if (idx > 0 and clean.startswith("- ")) else ""
                lines_spec.append(("F1", 9.5, 13, prefix + wline))

    # Paginate
    pages = []
    cur = []
    y = top_y
    for font, size, leading, text in lines_spec:
        if y - leading < bottom_y:
            pages.append(cur)
            cur = []
            y = top_y
        if text:
            cur.append((font, size, margin_x, y, text))
        y -= leading
    if cur or not pages:
        pages.append(cur)

    # Build PDF objects
    # 1: Catalog, 2: Pages, 3: F1 (Helvetica), 4: F2 (Helvetica-Bold), then per page: Page + Content
    objs = []
    num_pages = len(pages)
    page_ids = [5 + i * 2 for i in range(num_pages)]

    objs.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objs.append(f"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>\nendobj\n".encode())
    objs.append(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objs.append(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

    for i, page_items in enumerate(pages):
        pid = 5 + i * 2
        cid = pid + 1
        stream_lines = []
        # Header / Footer
        stream_lines.append("BT /F2 8 Tf 48 765 Td (" + _pdf_escape(title) + ") Tj ET")
        stream_lines.append(f"BT /F1 8 Tf 510 30 Td (Page {i + 1} of {num_pages}) Tj ET")
        for font, size, x, py, text in page_items:
            stream_lines.append(f"BT /{font} {size} Tf {x} {py} Td ({_pdf_escape(text)}) Tj ET")
        stream_bytes = "\n".join(stream_lines).encode("latin-1", errors="replace")
        objs.append(
            f"{pid} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w} {page_h}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cid} 0 R >>\nendobj\n".encode()
        )
        objs.append(
            f"{cid} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode()
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objs:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode())
    out.extend(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return bytes(out)


def write_pdf(md_text: str, out_path: str | Path, title: str = "Supply Chain Guardian Security Report") -> Path:
    p = Path(out_path)
    p.write_bytes(markdown_to_pdf_bytes(md_text, title=title))
    return p
