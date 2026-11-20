"""Tiny dependency-free PDF writer (A4, Helvetica): headings, wrapped text, tables, horizontal bar charts. Output is a real PDF
(validated with qpdf/pdftotext in tests). Text is latin-1 only; other characters become '?'. No external fonts or network."""
import textwrap

W, H, M = 595, 842, 40


def _esc(s: str) -> str:
    s = str(s).encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Pdf:
    def __init__(self, title: str):
        self.title, self.pages, self.ops, self.y = title, [], [], H - M

    def _new(self):
        if self.ops:
            self.pages.append(self.ops)
        self.ops, self.y = [], H - M

    def _need(self, h: float):
        if self.y - h < M + 20:
            self._new()

    def text(self, s: str, size=10, bold=False, x=M, gap=3):
        self._need(size + gap)
        self.ops.append(f"BT /{'F2' if bold else 'F1'} {size} Tf {x} {self.y - size:.1f} Td ({_esc(s)}) Tj ET")
        self.y -= size + gap

    def heading(self, s: str):
        self.y -= 8
        self.text(s, 13, True, gap=5)

    def para(self, s: str, size=10, width=95):
        for line in textwrap.wrap(str(s), width) or [""]:
            self.text(line, size)

    def table(self, heads: list[str], rows: list[list], widths: list[int] | None = None):
        n = len(heads)
        widths = widths or [(W - 2 * M) // n] * n
        def row(vals, bold=False):
            self._need(14)
            x = M
            for v, w in zip(vals, widths):
                lim = max(3, int(w / 5))
                t = str(v)
                self.ops.append(f"BT /{'F2' if bold else 'F1'} 8 Tf {x} {self.y - 9:.1f} Td ({_esc(t if len(t) <= lim else t[:lim - 1] + '~')}) Tj ET")
                x += w
            self.y -= 12
        row(heads, True)
        for r in rows:
            row(r)
        self.y -= 4

    def bars(self, title: str, data: list[tuple[str, float]], max_bars=12):
        data = data[:max_bars]
        self.text(title, 10, True)
        top = max([v for _, v in data] + [1])
        for label, v in data:
            self._need(14)
            wbar = (W - 2 * M - 170) * (v / top)
            self.ops.append(f"BT /F1 8 Tf {M} {self.y - 9:.1f} Td ({_esc(str(label)[:28])}) Tj ET")
            self.ops.append(f"0.2 0.45 0.8 rg {M + 130} {self.y - 10:.1f} {max(wbar, 0.5):.1f} 9 re f 0 g")
            self.ops.append(f"BT /F1 8 Tf {M + 135 + wbar:.1f} {self.y - 9:.1f} Td ({_esc(self._fmt(v))}) Tj ET")
            self.y -= 13
        if not data:
            self.text("(no data in this period)", 8)
        self.y -= 4

    @staticmethod
    def _fmt(v):
        return str(int(v)) if float(v).is_integer() else f"{v:.1f}"

    def render(self) -> bytes:
        pages = self.pages + ([self.ops] if self.ops or not self.pages else [])
        objs: list[bytes] = []                      # object i+1
        n = len(pages)
        kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(n))
        objs += [b"<< /Type /Catalog /Pages 2 0 R >>", f"<< /Type /Pages /Kids [{kids}] /Count {n} >>".encode(),
                 b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                 b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
        for i, ops in enumerate(pages):
            foot = f"BT /F1 8 Tf {M} 20 Td ({_esc(self.title)} - page {i + 1} of {n}) Tj ET"
            stream = ("\n".join(ops + [foot])).encode("latin-1", "replace")
            objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {6 + 2 * i} 0 R >>".encode())
            objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        out, offs = bytearray(b"%PDF-1.4\n"), []
        for i, o in enumerate(objs, 1):
            offs.append(len(out))
            out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
        x = len(out)
        out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        for o in offs:
            out += f"{o:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
        return bytes(out)
