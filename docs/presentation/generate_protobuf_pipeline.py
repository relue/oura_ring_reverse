#!/usr/bin/env python3
"""
Generate Protobuf Parsing Pipeline diagram for presentation
Shows how we reverse-engineered Oura's data format including QEMU emulation
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Colors - Distinct palette
BLUE = ('#bbdefb', '#1976d2')
GREEN = ('#c8e6c9', '#388e3c')
YELLOW = ('#fff9c4', '#f9a825')
RED = ('#ffcdd2', '#d32f2f')
PURPLE = ('#e1bee7', '#7b1fa2')
ORANGE = ('#ffe0b2', '#e65100')
GRAY = ('#eceff1', '#607d8b')
DARK = ('#cfd8dc', '#37474f')


def create_protobuf_diagram():
    """Create the protobuf pipeline visualization with QEMU details"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "protobuf_pipeline.drawio"
    page = drawpyo.Page(file=file, name="Protobuf Pipeline")
    page.page_width = 1920
    page.page_height = 1080

    # Styles
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"

    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=26;fontFamily={COMIC_FONT};fontColor=#222222;"
    SUBTITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontSize=14;fontFamily={COMIC_FONT};fontColor=#666666;"
    CONTAINER_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=13;fontFamily={COMIC_FONT};fontColor=#222222;verticalAlign=top;align=left;spacingTop=5;spacingLeft=10;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=12;fontFamily={COMIC_FONT};fontColor=#222222;"
    CODE_STYLE = f"{SKETCH}rounded=0;whiteSpace=wrap;html=1;strokeWidth=1;fontSize=10;fontFamily=Courier New;fontColor=#333333;align=left;spacingLeft=6;spacingTop=4;"
    BADGE_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=11;fontFamily={COMIC_FONT};fontColor=#222222;"
    ARROW_STYLE = f"{SKETCH}strokeWidth=2;strokeColor=#666666;"
    LABEL_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=11;fontFamily={COMIC_FONT};fontColor=#555555;"

    # === TITLE ===
    title = Object(page=page, value="<b>🔬 Native Protobuf Parsing Pipeline</b>", width=550, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (420, 15)

    # === CHALLENGE BANNER ===
    challenge = Object(
        page=page,
        value="<b>⚠️ CHALLENGES:</b>  ARM64 lib on x86_64 • Android Bionic vs Linux glibc • No docs • 109K obfuscated lines",
        width=820, height=35
    )
    challenge.apply_style_string(CONTAINER_STYLE + f"fillColor={RED[0]};strokeColor={RED[1]};align=center;verticalAlign=middle;")
    challenge.position = (285, 55)

    # =========================================================================
    # PHASE 1: Schema Extraction
    # =========================================================================
    phase1 = Object(page=page, value="<b>─ PHASE 1: Schema Extraction ─</b>", width=260, height=280)
    phase1.apply_style_string(CONTAINER_STYLE + f"fillColor=#fafafa;strokeColor={BLUE[1]};")
    phase1.position = (30, 100)

    p1_steps = [
        ("📱 Java Decompile", "109,000 lines", BLUE, 135),
        ("🌳 tree-sitter parse", "375 classes", PURPLE, 195),
        ("🔄 Type resolution", "k4→int64", ORANGE, 255),
        ("📄 .proto file", "2,070 lines", GREEN, 315),
    ]

    p1_objs = []
    for label, desc, color, y in p1_steps:
        obj = Object(page=page, value=f"<b>{label}</b><br/><font style='font-size:10px;color:#555;'>{desc}</font>", width=180, height=45)
        obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (65, y)
        p1_objs.append(obj)

    for i in range(len(p1_objs) - 1):
        edge = Edge(page=page, source=p1_objs[i], target=p1_objs[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # =========================================================================
    # PHASE 2: QEMU Native Execution (the complex part!)
    # =========================================================================
    phase2 = Object(page=page, value="<b>─ PHASE 2: QEMU Native Execution ─</b>", width=420, height=280)
    phase2.apply_style_string(CONTAINER_STYLE + f"fillColor=#fff8e1;strokeColor={ORANGE[1]};")
    phase2.position = (310, 100)

    # QEMU box
    qemu_box = Object(
        page=page,
        value="<b>🖥️ QEMU User-Mode</b><br/><font style='font-size:10px;color:#555;'>ARM64 → x86_64 translation</font>",
        width=180, height=50
    )
    qemu_box.apply_style_string(BOX_STYLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};")
    qemu_box.position = (325, 135)

    # Android sysroot
    sysroot = Object(
        page=page,
        value="<b>📂 Android Sysroot</b><br/><font style='font-size:9px;color:#555;'>linker64 + bionic libc</font>",
        width=160, height=45
    )
    sysroot.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};")
    sysroot.position = (520, 135)

    # Bridge program
    bridge = Object(
        page=page,
        value="<b>🔧 C Bridge</b><br/><font style='font-size:9px;color:#555;'>NDK-compiled ARM64</font>",
        width=140, height=45
    )
    bridge.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};")
    bridge.position = (340, 195)

    # .so library
    so_lib = Object(
        page=page,
        value="<b>📦 libringeventparser.so</b><br/><font style='font-size:9px;color:#555;'>Oura's native parser</font>",
        width=180, height=45
    )
    so_lib.apply_style_string(BOX_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};")
    so_lib.position = (510, 195)

    # Key requirements box
    discoveries = Object(
        page=page,
        value="<b>🔧 Bridge Requirements:</b>\n• dlsym() C++ mangled names\n• Session(options=0xFF)\n• set_output_modes(0xFFFF)\n• Parse events one-by-one",
        width=200, height=90
    )
    discoveries.apply_style_string(CODE_STYLE + f"fillColor=#e8f5e9;strokeColor={GREEN[1]};fontSize=9;")
    discoveries.position = (325, 245)

    # Output protobuf
    pb_output = Object(
        page=page,
        value="<b>💾 ring_data.pb</b><br/><font style='font-size:10px;color:#555;'>682KB protobuf</font>",
        width=140, height=45
    )
    pb_output.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};")
    pb_output.position = (545, 305)

    # =========================================================================
    # PHASE 3: Python Decode
    # =========================================================================
    phase3 = Object(page=page, value="<b>─ PHASE 3: Python Decode ─</b>", width=200, height=280)
    phase3.apply_style_string(CONTAINER_STYLE + f"fillColor=#fafafa;strokeColor={GREEN[1]};")
    phase3.position = (750, 100)

    # protoc compile
    protoc = Object(
        page=page,
        value="<b>⚙️ protoc</b><br/><font style='font-size:10px;color:#555;'>.proto → _pb2.py</font>",
        width=140, height=45
    )
    protoc.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};")
    protoc.position = (780, 140)

    # Python code
    python_code = Object(
        page=page,
        value="from ring_pb2 import *\n\ndata = RingData()\ndata.ParseFromString(pb)\n\nprint(data.ibi_events)",
        width=160, height=90
    )
    python_code.apply_style_string(CODE_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};")
    python_code.position = (770, 200)

    # Result
    result = Object(
        page=page,
        value="<b>✅ Health Data!</b>",
        width=140, height=35
    )
    result.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};")
    result.position = (780, 310)

    # =========================================================================
    # RAW vs PARSED Section
    # =========================================================================
    raw_parsed = Object(page=page, value="<b>─ RAW vs PARSED ─</b>", width=920, height=200)
    raw_parsed.apply_style_string(CONTAINER_STYLE + f"fillColor=#fafafa;strokeColor={PURPLE[1]};")
    raw_parsed.position = (30, 400)

    # RAW hex
    raw_label = Object(page=page, value="<b>📥 RAW (BLE hex):</b>", width=130, height=20)
    raw_label.apply_style_string(LABEL_STYLE + "align=left;fontStyle=1;fontColor=#333;")
    raw_label.position = (50, 435)

    raw_hex = Object(
        page=page,
        value="08 c0 f7 e8 a7 06 10 48\n18 64 20 02 28 98 01 30\ne8 07 38 03 42 0a 08 48\n...(binary protobuf)",
        width=220, height=90
    )
    raw_hex.apply_style_string(CODE_STYLE + f"fillColor={DARK[0]};strokeColor={DARK[1]};")
    raw_hex.position = (50, 460)

    # Arrow
    arrow_label = Object(page=page, value="<b>──▶</b>", width=50, height=25)
    arrow_label.apply_style_string(LABEL_STYLE + "fontSize=18;fontStyle=1;")
    arrow_label.position = (290, 490)

    # QEMU process
    qemu_process = Object(
        page=page,
        value="<b>🖥️ QEMU + Bridge</b>\n\nenv -i qemu-aarch64\n  -L ./android_root\n  ./parser_bridge",
        width=180, height=100
    )
    qemu_process.apply_style_string(CODE_STYLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};fontSize=9;")
    qemu_process.position = (355, 445)

    # Arrow 2
    arrow2 = Object(page=page, value="<b>──▶</b>", width=50, height=25)
    arrow2.apply_style_string(LABEL_STYLE + "fontSize=18;fontStyle=1;")
    arrow2.position = (550, 490)

    # Protobuf intermediate
    pb_inter = Object(
        page=page,
        value="<b>📄 Protobuf</b>\n682KB binary",
        width=100, height=55
    )
    pb_inter.apply_style_string(BOX_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};fontSize=10;")
    pb_inter.position = (610, 465)

    # Arrow 3
    arrow3 = Object(page=page, value="<b>──▶</b>", width=50, height=25)
    arrow3.apply_style_string(LABEL_STYLE + "fontSize=18;fontStyle=1;")
    arrow3.position = (720, 490)

    # PARSED JSON
    parsed_json = Object(
        page=page,
        value='{\n  "timestamp": 1705512000,\n  "heart_rate": 72,\n  "spo2": 98,\n  "sleep_stage": "DEEP",\n  "ibi": [820, 815, 830]\n}',
        width=200, height=120
    )
    parsed_json.apply_style_string(CODE_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};")
    parsed_json.position = (780, 435)

    # =========================================================================
    # Health metric badges
    # =========================================================================
    badges = [
        ("❤️ Heart Rate", BLUE),
        ("😴 Sleep", PURPLE),
        ("🌡️ Temp", ORANGE),
        ("🫁 SpO2", GREEN),
        ("🏃 Activity", YELLOW),
        ("📊 HRV/IBI", BLUE),
    ]

    badge_x = 50
    for label, color in badges:
        badge = Object(page=page, value=f"<b>{label}</b>", width=100, height=30)
        badge.apply_style_string(BADGE_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        badge.position = (badge_x, 615)
        badge_x += 115

    # Stats line
    stats = Object(
        page=page,
        value="<b>✅ 144 messages  ✅ 44 enums  ✅ 962 fields  ✅ 109-field Event oneof</b>",
        width=550, height=25
    )
    stats.apply_style_string(LABEL_STYLE + "fontSize=12;fontColor=#388e3c;fontStyle=1;")
    stats.position = (700, 615)

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_protobuf_diagram()
    print("\n📂 Protobuf pipeline diagram ready!")
