"""Generate the extension's PNG icons (a blue shield) using only the standard library.

Chrome requires PNG icons for Manifest V3 actions. Run:  python scripts/make_icons.py
"""
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "extension" / "icons"
BLUE = (29, 78, 216)
WHITE = (255, 255, 255)
SUPERSAMPLE = 4


def inside_shield(x, y):
    """Shield outline in unit coordinates (0..1)."""
    if y < 0.06 or y > 0.95 or x < 0.12 or x > 0.88:
        return False
    if y < 0.55:
        return True
    # Lower part tapers to a point at (0.5, 0.95).
    half_width = 0.38 * (0.95 - y) / 0.40
    return abs(x - 0.5) <= half_width


def inside_check(x, y):
    """A check mark drawn as two thick line segments."""
    def near_segment(ax, ay, bx, by, width):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        px, py = ax + t * dx, ay + t * dy
        return (x - px) ** 2 + (y - py) ** 2 <= width ** 2

    return near_segment(0.30, 0.48, 0.44, 0.63, 0.06) or near_segment(0.44, 0.63, 0.70, 0.34, 0.06)


def render(size):
    rows = []
    n = SUPERSAMPLE
    for py in range(size):
        row = bytearray([0])  # filter type 0
        for px in range(size):
            r = g = b = a = 0
            for sy in range(n):
                for sx in range(n):
                    x = (px + (sx + 0.5) / n) / size
                    y = (py + (sy + 0.5) / n) / size
                    if inside_shield(x, y):
                        color = WHITE if inside_check(x, y) else BLUE
                        r += color[0]; g += color[1]; b += color[2]; a += 255
            samples = n * n
            if a:
                covered = a // 255
                row += bytes([r // covered, g // covered, b // covered, a // samples])
            else:
                row += bytes([0, 0, 0, 0])
        rows.append(bytes(row))
    return b"".join(rows)


def png(size):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(render(size), 9))
        + chunk(b"IEND", b"")
    )


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for size in (16, 32, 48, 128):
        path = OUT / f"icon{size}.png"
        path.write_bytes(png(size))
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
