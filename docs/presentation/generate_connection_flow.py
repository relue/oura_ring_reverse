#!/usr/bin/env python3
"""
Generate Connection Flow diagram for presentation
Shows: First Time Setup, Normal Connection, and Read Data flows
Simple style matching re_journey.drawio
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Colors
BLUE = ('#bbdefb', '#1976d2')
GREEN = ('#c8e6c9', '#388e3c')
YELLOW = ('#fff9c4', '#f9a825')
RED = ('#ffcdd2', '#d32f2f')
PURPLE = ('#e1bee7', '#7b1fa2')
ORANGE = ('#ffe0b2', '#e65100')
GRAY = ('#f5f5f5', '#666666')


def create_connection_flow_diagram():
    """Create simple connection flow visualization"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "connection_flow.drawio"
    page = drawpyo.Page(file=file, name="Connection Flow")
    page.page_width = 1920
    page.page_height = 1080

    # Styles - Simple sketch style
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"
    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=24;fontFamily={COMIC_FONT};fontColor=#222222;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=3;fontSize=14;fontFamily={COMIC_FONT};fontColor=#222222;arcSize=15;"
    ARROW_STYLE = f"{SKETCH}strokeWidth=3;strokeColor=#444444;"

    # Title
    title = Object(page=page, value="<b>🔗 Oura Ring Connection Flows</b>", width=500, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (150, 5)

    W, H = 170, 70

    # =========================================================================
    # Column 1: First Time Setup
    # =========================================================================
    setup_steps = [
        ("📱 Factory Reset", "Clear old key\nfrom ring", ORANGE, 55),
        ("📡 BLE Scan", "Find ring\n'Oura_XXXX'", BLUE, 155),
        ("🔗 Connect", "GATT + bonding", BLUE, 255),
        ("🔑 Generate Key", "Random AES-128\nkey", YELLOW, 355),
        ("📤 Send Key", "Write to ring\ncharacteristic", PURPLE, 455),
        ("✅ Key Stored!", "Both sides have\nshared secret", GREEN, 555),
    ]

    X1 = 50
    setup_objs = []
    for label, desc, color, y in setup_steps:
        obj = Object(
            page=page,
            value=f"<b>{label}</b><br/><font style='font-size:12px;color:#444;'>{desc}</font>",
            width=W, height=H
        )
        obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (X1, y)
        setup_objs.append(obj)

    for i in range(len(setup_objs) - 1):
        edge = Edge(page=page, source=setup_objs[i], target=setup_objs[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # =========================================================================
    # Column 2: Normal Connection (Auth)
    # =========================================================================
    auth_steps = [
        ("📡 BLE Connect", "Resume bonded\nconnection", BLUE, 55),
        ("📥 Get Challenge", "Ring sends 16\nrandom bytes", YELLOW, 155),
        ("🔐 Encrypt", "AES-128-ECB\nwith stored key", PURPLE, 255),
        ("📤 Send Response", "Write encrypted\nchallenge back", PURPLE, 355),
        ("✅ Authenticated!", "Ring unlocks\nall commands", GREEN, 455),
    ]

    X2 = 280
    auth_objs = []
    for label, desc, color, y in auth_steps:
        obj = Object(
            page=page,
            value=f"<b>{label}</b><br/><font style='font-size:12px;color:#444;'>{desc}</font>",
            width=W, height=H
        )
        obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (X2, y)
        auth_objs.append(obj)

    for i in range(len(auth_objs) - 1):
        edge = Edge(page=page, source=auth_objs[i], target=auth_objs[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # =========================================================================
    # Column 3: Read Data
    # =========================================================================
    read_steps = [
        ("📤 GetEvent Cmd", "Request data type\n(HR, Sleep...)", BLUE, 55),
        ("📥 BLE Stream", "Ring sends raw\nevent packets", PURPLE, 155),
        ("🖥️ QEMU Parse", "Native .so via\nARM64 emulation", ORANGE, 255),
        ("📄 Protobuf", "Structured\nRingData output", PURPLE, 355),
        ("🐍 Python", "Decode with\n_pb2.py", GREEN, 455),
        ("📊 Health Data!", "HR, Sleep, SpO2\nTemp, HRV", GREEN, 555),
    ]

    X3 = 510
    read_objs = []
    for label, desc, color, y in read_steps:
        obj = Object(
            page=page,
            value=f"<b>{label}</b><br/><font style='font-size:12px;color:#444;'>{desc}</font>",
            width=W, height=H
        )
        obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (X3, y)
        read_objs.append(obj)

    for i in range(len(read_objs) - 1):
        edge = Edge(page=page, source=read_objs[i], target=read_objs[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # =========================================================================
    # Column headers
    # =========================================================================
    header_style = f"text;html=1;strokeColor=none;fillColor=none;align=center;fontSize=16;fontFamily={COMIC_FONT};fontColor=#333;fontStyle=1;"

    h1 = Object(page=page, value="<b>1️⃣ First Setup</b>", width=150, height=25)
    h1.apply_style_string(header_style)
    h1.position = (60, 635)

    h2 = Object(page=page, value="<b>2️⃣ Auth (every time)</b>", width=170, height=25)
    h2.apply_style_string(header_style)
    h2.position = (280, 535)

    h3 = Object(page=page, value="<b>3️⃣ Read Data</b>", width=150, height=25)
    h3.apply_style_string(header_style)
    h3.position = (520, 635)

    # Connect columns with arrows
    edge1 = Edge(page=page, source=setup_objs[-1], target=auth_objs[0])
    edge1.apply_style_string(ARROW_STYLE + "strokeColor=#388e3c;")

    edge2 = Edge(page=page, source=auth_objs[-1], target=read_objs[0])
    edge2.apply_style_string(ARROW_STYLE + "strokeColor=#388e3c;")

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_connection_flow_diagram()
    print("\n📂 Connection flow diagram ready!")
