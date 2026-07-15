"""Generate all Tasty Treats pixel art (item sprites, block atlases, pack
icons) as PNGs, with no image-library dependency.

Usage: python3 tools/make_art.py <pack root>
"""
import os, struct, zlib, sys

PALETTE = {
    ".": (0, 0, 0, 0),          # transparent
    "x": (56, 39, 28, 255),     # outline dark brown
    "T": (222, 158, 78, 255),   # dough / shell / flake tan
    "t": (188, 126, 53, 255),   # tan shading
    "B": (210, 146, 70, 255),   # bun
    "s": (255, 244, 214, 255),  # sesame seeds
    "L": (106, 190, 48, 255),   # lettuce green
    "C": (255, 200, 40, 255),   # cheese yellow
    "Y": (255, 226, 120, 255),  # cheese highlight
    "P": (102, 57, 34, 255),    # meat / chocolate brown
    "p": (74, 40, 24, 255),     # meat shadow
    "R": (235, 64, 84, 255),    # red (tomato, pepperoni, cherry)
    "r": (186, 42, 60, 255),    # red shadow
    "q": (255, 150, 170, 255),  # pink (frosting, strawberry, naruto)
    "W": (255, 255, 255, 255),  # white
    "m": (232, 226, 216, 255),  # milk shadow
    "n": (255, 232, 170, 255),  # noodle cream
    "o": (255, 178, 84, 255),   # ramen broth orange
    "a": (226, 140, 52, 255),   # broth shadow
    "k": (156, 116, 72, 255),   # wood stick
    "u": (121, 78, 44, 255),    # bowl wood
    "d": (86, 53, 28, 255),     # bowl wood dark
    "g": (186, 190, 198, 255),  # spoon silver
    "c": (86, 190, 240, 255),   # cyan sprinkle
    "G": (96, 205, 88, 255),    # green (sprinkle, green onion)
    "O": (255, 163, 55, 255),   # orange candy ring
    "V": (186, 104, 224, 255),  # violet candy ring
    "e": (108, 112, 120, 255),  # appliance gray
    "E": (66, 70, 78, 255),     # appliance gray dark
}

# ---------------------------------------------------------------- item sprites

CHEESEBURGER = [
    "................",
    ".....xxxxxx.....",
    "...xxTTTTTTxx...",
    "..xTTsTTsTTTTx..",
    "..xTTTTTTTsTTx..",
    ".xTtTsTTTTTTTtx.",
    ".xLLLLLLLLLLLLx.",
    ".xCCYCCCCYCCCCx.",
    ".xPPPPPPPPPPPPx.",
    ".xpPPPPPPPPPPpx.",
    ".xBBBBBBBBBBBBx.",
    "..xBBBBBBBBBBx..",
    "...xxBBBBBBxx...",
    ".....xxxxxx.....",
    "................",
    "................",
]

RAINBOW_CANDY = [
    "......xxxx......",
    "....xxRRRRxx....",
    "...xRROOOORRx...",
    "..xROOGGGGOORx..",
    "..xROGccccGORx..",
    ".xRROcVVVVcORRx.",
    ".xROGcVWWVcGORx.",
    ".xROGcVWWVcGORx.",
    ".xRROcVVVVcORRx.",
    "..xROGccccGORx..",
    "..xROOGGGGOORx..",
    "...xRROOOORRx...",
    "....xxRRRRxx....",
    "......xkkx......",
    ".......kk.......",
    ".......kk.......",
]

RAMEN = [
    "........k.k.....",
    ".......k.k......",
    ".......k.k......",
    "......k.k.......",
    "..xnnxk.kxnnx...",
    ".xnqWnqkknnqnx..",
    "xoonnnnkknnnoox.",
    "xduuuuuuuuuuudx.",
    ".xduuuuuuuuudx..",
    ".xduuuuuuuuudx..",
    "..xduuuuuuudx...",
    "...xdduuuddx....",
    "....xddddddx....",
    ".....xxxxxx.....",
    "................",
    "................",
]

CEREAL = [
    ".............xg.",
    "............xgg.",
    "...........xgg..",
    "..........xggx..",
    "..xTx.xTx.xggx..",
    ".xWWTWWTWWxggWx.",
    "xmWWWWWWWWWWWWmx",
    "xduuuuuuuuuuudx.",
    ".xduuuuuuuuudx..",
    ".xduuuuuuuuudx..",
    "..xduuuuuuudx...",
    "...xdduuuddx....",
    "....xddddddx....",
    ".....xxxxxx.....",
    "................",
    "................",
]

ICE_CREAM = [
    ".......xR.......",
    "......xRRx......",
    "....xqqqqWWx....",
    "...xqqqqqWWWx...",
    "..xPPPqqqWWWWx..",
    "..xPPPPqqWWWWx..",
    ".xPPPPPqqWWWWWx.",
    "xduuuuuuuuuuudx.",
    ".xduuuuuuuuudx..",
    ".xduuuuuuuuudx..",
    "..xduuuuuuudx...",
    "...xdduuuddx....",
    "....xddddddx....",
    ".....xxxxxx.....",
    "................",
    "................",
]

PIZZA_SLICE = [
    "................",
    ".xxxxxxxxxxxxx..",
    ".xTTTTTTTTTTTx..",
    ".xtCCCCCCCCCtx..",
    "..xCCRrCCRrCx...",
    "..xCCRRCCRRCx...",
    "...xCCCCCCCx....",
    "...xCRrCCYCx....",
    "....xCCCCCx.....",
    "....xCRrCx......",
    ".....xCCCx......",
    ".....xCCx.......",
    "......xCx.......",
    "......xx........",
    "................",
    "................",
]

TACO = [
    "................",
    "................",
    "....xLxPxRxL....",
    "...xLPPRLLPRLx..",
    "..xLLPPRLPPRLLx.",
    ".xTLLPPRLLPRLTx.",
    "xTTTTTTTTTTTTTTx",
    "xtTTTTTTTTTTTtx.",
    ".xTTTTTTTTTTTx..",
    "..xTTTTTTTTTx...",
    "...xTTTTTTTx....",
    "....xxTTTxx.....",
    "......xxx.......",
    "................",
    "................",
    "................",
]

DONUT = [
    "................",
    ".....xxxxxx.....",
    "...xxqqqqqqxx...",
    "..xqqqqqqqqqqx..",
    ".xqqCqqcqqGqqx..",
    ".xqGqxxxxqqcqx..",
    ".xqqx....xqqqx..",
    ".xTqx....xqqTx..",
    ".xTTx....xTTTx..",
    "..xTTxxxxTTTx...",
    "..xTTTTTTTTTx...",
    "...xTTTTTTTx....",
    "....xxxxxxx.....",
    "................",
    "................",
    "................",
]

SUSHI = [
    "................",
    "................",
    "...xxxxx........",
    "..xRRRrrx.xxxx..",
    ".xRRRRRrrxWWWWx.",
    ".xrRRRRRrxWRWWx.",
    ".xWWWWWWxxWRRWx.",
    ".xWWmWWWxxWWWWx.",
    "..xWWWWx.xmmmx..",
    "xTTTTTTTTTTTTTTx",
    "xtTTTTTTTTTTTTtx",
    ".xxxxxxxxxxxxxx.",
    "................",
    "................",
    "................",
    "................",
]

SMOOTHIE = [
    "...........WR...",
    "..........WR....",
    "..........WR....",
    "..xxxxxxxxWRxx..",
    "..xmWWWWWWWWmx..",
    "..xqqqqqqqqqqx..",
    "..xqqqqqqqqqqx..",
    "..xqqqqqqqqqqx..",
    "..xqqqqqqqqqqx..",
    "..xqqqqqqqqqqx..",
    "...xqqqqqqqqx...",
    "...xqqqqqqqqx...",
    "....xxxxxxxx....",
    "................",
    "................",
    "................",
]

# The smoothie sprite is recolored per flavor (body color swapped for "q")
SMOOTHIE_FLAVORS = {
    "smoothie": "q",        # berry pink
    "melon_smoothie": "L",  # melon green
    "choco_smoothie": "P",  # chocolate brown
    "glow_smoothie": "C",   # glowing yellow
}

MILKSHAKE = [
    "...........WR...",
    "..........WR....",
    "..........WR....",
    "..xxxxxxxxWRxx..",
    "..xWWWWRWWWWWx..",
    "..xWWWWWWWWWWx..",
    "..xWmWWWWWmWWx..",
    "..xWWWWWWWWWWx..",
    "..xWWWWWWWWWWx..",
    "..xWWWWWWWWWWx..",
    "...xWWWWWWWWx...",
    "...xmWWWWWWmx...",
    "....xxxxxxxx....",
    "................",
    "................",
    "................",
]

CHEFS_HAT = [
    "................",
    "....xxxxxxx.....",
    "...xWWWWWWWx....",
    "..xWWWWWWWWWx...",
    "..xWWWWWWWWWx...",
    "..xWWmWWWWWWx...",
    "..xWWWWWWmWWx...",
    "...xWWWWWWWx....",
    "...xmmmmmmmx....",
    "...xWWWWWWWx....",
    "...xWWWWWWWx....",
    "...xxxxxxxxx....",
    "................",
    "................",
    "................",
    "................",
]

ITEMS = {
    "cheeseburger": CHEESEBURGER,
    "sushi": SUSHI,
    "milkshake": MILKSHAKE,
    "chefs_hat": CHEFS_HAT,
    "rainbow_candy": RAINBOW_CANDY,
    "ramen": RAMEN,
    "cereal": CEREAL,
    "ice_cream": ICE_CREAM,
    "pizza_slice": PIZZA_SLICE,
    "taco": TACO,
    "donut": DONUT,
}

# ------------------------------------------------------------- block atlases
# 32x32 atlas per bowl block. Regions consumed by models/blocks/bowl_food.geo.json:
#   ( 0, 0) 8x8   food top surface
#   ( 8, 0) 8x2   food edge (contents cube sides)
#   ( 0,10) 10x3  bowl side wood
#   (16,16) 10x10 bowl top/bottom wood

WOOD_SIDE = [
    "uuuuuuuuuu",
    "uduudduudu",
    "dddddddddd",
]

WOOD_TOP = (
    ["dddddddddd"]
    + ["duuuuuuuud"] * 8
    + ["dddddddddd"]
)

BLOCK_TOPS = {
    "ramen_bowl": [
        "oonnnnoo",
        "onnqqnno",
        "nnqWWqnn",
        "onqWWqno",
        "oGnnnnGo",
        "nnnnnnnn",
        "oonGnnoo",
        "aoooooooa"[:8],
    ],
    "cereal_bowl": [
        "WWTWWWTW",
        "WTtTWWWW",
        "WWWWWTtW",
        "WTWWWWTW",
        "WWTtWWWW",
        "WWWWTWWW",
        "WTWWWTtW",
        "mWWmWWWm",
    ],
    "ice_cream_bowl": [
        "PPPqqWWW",
        "PPqqqWWW",
        "PPqqWWWW",
        "PPPqqWWW",
        "PPqqqRWW",
        "PPqqWWWW",
        "PPPqqWWW",
        "PPqqqWWW",
    ],
}

BLOCK_EDGES = {
    "ramen_bowl": ["oooooooo", "aaaaaaaa"],
    "cereal_bowl": ["WWWWWWWW", "mmmmmmmm"],
    "ice_cream_bowl": ["PPqqWWWW", "PPqqWWWW"],
}

# Sushi board atlas regions (models/blocks/bowl_food.geo.json, sushi geometry):
#   ( 0, 0) 12x8  board top (light wood, grain)
#   ( 0, 8) 12x1  board edge
#   (16, 0) 4x4   salmon top with nori strap
#   (16, 4) 4x3   rice sides with nori strap
#   (24, 0) 4x4   rice bottom

BOARD_TOP = [
    "tttttttttttt",
    "tTTTTTTTTTTt",
    "tTTtTTTTTtTt",
    "tTTTTTtTTTTt",
    "tTtTTTTTTTTt",
    "tTTTTTTtTTTt",
    "tTTtTTTTTTTt",
    "tttttttttttt",
]
BOARD_EDGE = ["tttttttttttt"]
SALMON_TOP = ["RRRR", "RxxR", "RxxR", "rRRr"]
RICE_SIDE = ["RRRR", "WxxW", "WxxW"]
RICE_BOTTOM = ["WWWW"] * 4

# Blender atlas regions (geometry.demo_blender):
#   ( 0, 0) 8x4  motor base sides    ( 0, 8) 8x8  base top/bottom
#   (16, 0) 6x7  jar sides           (16, 8) 6x6  jar top/bottom
#   (24, 0) 4x1  lid sides           (24, 4) 4x4  lid top/bottom
BLENDER_BASE_SIDE = [
    "EEEEEEEE",
    "EeeeeeeE",
    "EeRGeeeE",
    "EEEEEEEE",
]
BLENDER_BASE_TOP = ["EEEEEEEE"] + ["EeeeeeeE"] * 6 + ["EEEEEEEE"]
BLENDER_JAR_SIDE = [
    "mmmmmm",
    "mWmmWm",
    "qqqqqq",
    "qqqqqq",
    "qqqqqq",
    "qqqqqq",
    "qqqqqq",
]
BLENDER_JAR_TOP = ["mmmmmm", "mqqqqm", "mqqqqm", "mqqqqm", "mqqqqm", "mmmmmm"]
BLENDER_LID_SIDE = ["EEEE"]
BLENDER_LID_TOP = ["EEEE", "EeeE", "EeeE", "EEEE"]

# Chef's hat attachable atlas (geometry.demo_chefs_hat):
#   (0, 0) 9x2  band sides        (0, 4) 9x9  band top/bottom
#   (16, 0) 8x4 puff sides        (16, 8) 8x8 puff top/bottom
HAT_BAND_SIDE = ["WWWWWWWWW", "mmmmmmmmm"]
HAT_BAND_TOP = ["mmmmmmmmm"] + ["mWWWWWWWm"] * 7 + ["mmmmmmmmm"]
HAT_PUFF_SIDE = [
    "WWWWWWWW",
    "WmWWWWmW",
    "WWWWWWWW",
    "mWWmmWWm",
]
HAT_PUFF_TOP = [
    "mWWWWWWm",
    "WWWmWWWW",
    "WWWWWWWW",
    "WmWWWWmW",
    "WWWWWWWW",
    "WWWWmWWW",
    "WmWWWWWW",
    "mWWWWWWm",
]

# ------------------------------------------------------------------ plumbing

def parse(rows, w=16, h=16):
    rows = (list(rows) + ["." * w] * h)[:h]
    return [[PALETTE[ch] for ch in row.ljust(w, ".")[:w]] for row in rows]

def blit(grid, rows, ox, oy):
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            grid[oy + y][ox + x] = PALETTE[ch]

def write_png(path, pixels, scale=1):
    h, w = len(pixels) * scale, len(pixels[0]) * scale
    raw = b""
    for row in pixels:
        line = b"\x00" + b"".join(bytes(p) * scale for p in row)
        raw += line * scale

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)

def main(base):
    os.makedirs(f"{base}/tasty_treats_rp/textures/items", exist_ok=True)
    os.makedirs(f"{base}/tasty_treats_rp/textures/blocks", exist_ok=True)
    for name, rows in ITEMS.items():
        write_png(f"{base}/tasty_treats_rp/textures/items/{name}.png", parse(rows))

    for name in BLOCK_TOPS:
        grid = [[PALETTE["."]] * 32 for _ in range(32)]
        blit(grid, BLOCK_TOPS[name], 0, 0)
        blit(grid, BLOCK_EDGES[name], 8, 0)
        blit(grid, WOOD_SIDE, 0, 10)
        blit(grid, WOOD_TOP, 16, 16)
        write_png(f"{base}/tasty_treats_rp/textures/blocks/{name}.png", grid)

    grid = [[PALETTE["."]] * 32 for _ in range(32)]
    blit(grid, BOARD_TOP, 0, 0)
    blit(grid, BOARD_EDGE, 0, 8)
    blit(grid, SALMON_TOP, 16, 0)
    blit(grid, RICE_SIDE, 16, 4)
    blit(grid, RICE_BOTTOM, 24, 0)
    write_png(f"{base}/tasty_treats_rp/textures/blocks/sushi_board.png", grid)

    for name, color in SMOOTHIE_FLAVORS.items():
        rows = [row.replace("q", color) for row in SMOOTHIE]
        write_png(f"{base}/tasty_treats_rp/textures/items/{name}.png", parse(rows))

    grid = [[PALETTE["."]] * 32 for _ in range(32)]
    blit(grid, BLENDER_BASE_SIDE, 0, 0)
    blit(grid, BLENDER_BASE_TOP, 0, 8)
    blit(grid, BLENDER_JAR_SIDE, 16, 0)
    blit(grid, BLENDER_JAR_TOP, 16, 8)
    blit(grid, BLENDER_LID_SIDE, 24, 0)
    blit(grid, BLENDER_LID_TOP, 24, 4)
    write_png(f"{base}/tasty_treats_rp/textures/blocks/blender.png", grid)

    os.makedirs(f"{base}/tasty_treats_rp/textures/models", exist_ok=True)
    grid = [[PALETTE["."]] * 32 for _ in range(32)]
    blit(grid, HAT_BAND_SIDE, 0, 0)
    blit(grid, HAT_BAND_TOP, 0, 4)
    blit(grid, HAT_PUFF_SIDE, 16, 0)
    blit(grid, HAT_PUFF_TOP, 16, 8)
    write_png(f"{base}/tasty_treats_rp/textures/models/chefs_hat.png", grid)

    icon = parse(CHEESEBURGER)
    write_png(f"{base}/tasty_treats_rp/pack_icon.png", icon, scale=8)
    write_png(f"{base}/tasty_treats_bp/pack_icon.png", icon, scale=8)
    print("wrote", len(ITEMS), "item sprites,", len(BLOCK_TOPS), "block atlases, 2 pack icons")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
