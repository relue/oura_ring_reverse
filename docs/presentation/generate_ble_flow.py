#!/usr/bin/env python3
"""
Generate BLE Protocol Flow - Accurate based on actual implementation
Horizontal lifelines with proper Edge arrows showing exact byte sequences
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Colors
BLUE = ('#bbdefb', '#1976d2')
GREEN = ('#c8e6c9', '#388e3c')
YELLOW = ('#fff9c4', '#f9a825')
PURPLE = ('#e1bee7', '#7b1fa2')
ORANGE = ('#ffe0b2', '#e65100')
GRAY = ('#eceff1', '#607d8b')
RED = ('#ffcdd2', '#d32f2f')


def create_ble_flow_diagram():
    """Create accurate BLE protocol flow with proper arrows"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "ble_flow.drawio"
    page = drawpyo.Page(file=file, name="BLE Flow")
    page.page_width = 1920
    page.page_height = 1080

    # Styles
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"
    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=26;fontFamily={COMIC_FONT};fontColor=#222222;"
    LABEL_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=10;fontFamily={COMIC_FONT};fontColor=#444444;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=11;fontFamily={COMIC_FONT};fontColor=#222222;"
    SECTION_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=14;fontFamily={COMIC_FONT};fontColor=#333;fontStyle=1;"
    WAYPOINT_STYLE = "ellipse;whiteSpace=wrap;html=1;fillColor=#333333;strokeColor=none;"
    ARROW_DOWN_STYLE = f"endArrow=classic;startArrow=none;strokeColor={BLUE[1]};strokeWidth=2;"
    ARROW_UP_STYLE = f"endArrow=classic;startArrow=none;strokeColor={GREEN[1]};strokeWidth=2;dashed=1;"
    CODE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;fontSize=9;fontFamily=Courier New;fontColor=#555;"

    # Title
    title = Object(page=page, value="<b>📡 BLE Protocol Flow</b>", width=300, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (420, 10)

    # Section labels
    sec1 = Object(page=page, value="<b>1️⃣ SETUP (once)</b>", width=280, height=28)
    sec1.apply_style_string(SECTION_STYLE + f"fillColor={BLUE[0]};strokeColor={BLUE[1]};")
    sec1.position = (70, 55)

    sec2 = Object(page=page, value="<b>2️⃣ AUTH (every connect)</b>", width=220, height=28)
    sec2.apply_style_string(SECTION_STYLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};")
    sec2.position = (400, 55)

    sec3 = Object(page=page, value="<b>3️⃣ DATA</b>", width=220, height=28)
    sec3.apply_style_string(SECTION_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};")
    sec3.position = (680, 55)

    # =========================================================================
    # Horizontal Lifelines
    # =========================================================================
    Y_PHONE = 160
    Y_RING = 420
    X_START = 60
    X_END = 950

    # Phone lifeline
    phone_label = Object(page=page, value="<b>📱 Phone</b>", width=65, height=30)
    phone_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=12;")
    phone_label.position = (X_START - 68, Y_PHONE - 15)

    phone_line = Object(page=page, value="", width=X_END - X_START, height=3)
    phone_line.apply_style_string(f"rounded=0;fillColor=#444444;strokeColor=none;")
    phone_line.position = (X_START, Y_PHONE)

    # Ring lifeline
    ring_label = Object(page=page, value="<b>💍 Ring</b>", width=65, height=30)
    ring_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=12;")
    ring_label.position = (X_START - 68, Y_RING - 15)

    ring_line = Object(page=page, value="", width=X_END - X_START, height=3)
    ring_line.apply_style_string(f"rounded=0;fillColor=#444444;strokeColor=none;")
    ring_line.position = (X_START, Y_RING)

    # Time arrow
    time_lbl = Object(page=page, value="<i>time →</i>", width=45, height=18)
    time_lbl.apply_style_string(LABEL_STYLE + "fontSize=9;fontColor=#888;")
    time_lbl.position = (X_END + 5, (Y_PHONE + Y_RING) // 2 - 9)

    # =========================================================================
    # Messages with ACCURATE protocol bytes
    # Format: (x_pos, label_top, label_bottom, bytes_top, bytes_bottom, direction)
    # =========================================================================
    messages = [
        # SETUP
        (90,  "Factory Reset", "", "1a 00", "", "down"),
        (90,  "", "ACK", "", "xx xx 1a 00", "up"),
        (155, "Set Auth Key", "", "24 10 <16B key>", "", "down"),
        (155, "", "ACK", "", "2f xx 24 00", "up"),
        (225, "TimeSync", "", "12 09 <8B UTC> <TZ>", "", "down"),
        (225, "", "Ring Time", "", "13 05 <4B time>", "up"),

        # AUTH
        (340, "Get Nonce", "", "2f 01 2b", "", "down"),
        (340, "", "Nonce", "", "2f xx 2c <15B>", "up"),
        (420, "Authenticate", "", "2f 11 2d <16B enc>", "", "down"),
        (420, "", "Auth OK", "", "2f xx 2e 00", "up"),

        # DATA
        (540, "GetEvent", "", "10 09 <ts> <max> <flags>", "", "down"),
        (540, "", "Batch Info", "", "11 06 <cnt> <bytes_left>", "up"),
        (620, "", "Event 0x6a", "", "6a <len> <ts> <data>", "up"),
        (680, "", "Event 0x46", "", "46 <len> <ts> <data>", "up"),
        (740, "", "Event ...", "", "xx <len> <ts> <data>", "up"),
        (820, "GetEvent", "", "10 09 <next_ts>...", "", "down"),
        (880, "", "Events...", "", "...", "up"),
    ]

    for x, label_top, label_bottom, bytes_top, bytes_bottom, direction in messages:
        # Create waypoints
        wp_phone = Object(page=page, value="", width=6, height=6)
        wp_phone.apply_style_string(WAYPOINT_STYLE)
        wp_phone.position = (x - 3, Y_PHONE - 3)

        wp_ring = Object(page=page, value="", width=6, height=6)
        wp_ring.apply_style_string(WAYPOINT_STYLE)
        wp_ring.position = (x - 3, Y_RING - 3)

        # Create edge with arrow
        if direction == "down":
            edge = Edge(page=page, source=wp_phone, target=wp_ring)
            edge.apply_style_string(ARROW_DOWN_STYLE)
            # Labels near phone (top)
            if label_top:
                lbl = Object(page=page, value=f"<b>{label_top}</b>", width=90, height=16)
                lbl.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};fontSize=9;")
                lbl.position = (x - 45, Y_PHONE - 28)
            if bytes_top:
                blbl = Object(page=page, value=bytes_top, width=110, height=14)
                blbl.apply_style_string(CODE_STYLE + f"fontColor={BLUE[1]};align=center;")
                blbl.position = (x - 55, Y_PHONE - 45)
        else:
            edge = Edge(page=page, source=wp_ring, target=wp_phone)
            edge.apply_style_string(ARROW_UP_STYLE)
            # Labels near ring (bottom)
            if label_bottom:
                lbl = Object(page=page, value=f"<b>{label_bottom}</b>", width=90, height=16)
                lbl.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};fontSize=9;")
                lbl.position = (x - 45, Y_RING + 18)
            if bytes_bottom:
                blbl = Object(page=page, value=bytes_bottom, width=120, height=14)
                blbl.apply_style_string(CODE_STYLE + f"fontColor={GREEN[1]};align=center;")
                blbl.position = (x - 60, Y_RING + 32)

    # =========================================================================
    # AES encrypt box in AUTH section
    # =========================================================================
    encrypt = Object(page=page, value="<b>🔐 AES-128-ECB</b><br/><font style='font-size:8px;'>pad 15B→16B, encrypt</font>", width=100, height=40)
    encrypt.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=10;")
    encrypt.position = (365, (Y_PHONE + Y_RING) // 2 - 20)

    # =========================================================================
    # Characteristics box
    # =========================================================================
    char_box = Object(
        page=page,
        value="<b>BLE Characteristics:</b><br/>"
              "Write: 98ed0002-...<br/>"
              "Notify: 98ed0003-...",
        width=150, height=55
    )
    char_box.apply_style_string(BOX_STYLE + f"fillColor=#fafafa;strokeColor=#ccc;fontSize=9;align=left;spacingLeft=8;")
    char_box.position = (30, 480)

    # =========================================================================
    # Legend
    # =========================================================================
    leg1 = Object(page=page, value="<b>───▶</b> Phone → Ring", width=110, height=16)
    leg1.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};align=left;fontSize=10;")
    leg1.position = (30, 545)

    leg2 = Object(page=page, value="<b>- - ▶</b> Ring → Phone", width=110, height=16)
    leg2.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};align=left;fontSize=10;")
    leg2.position = (30, 565)

    # =========================================================================
    # Key info boxes
    # =========================================================================
    key_box = Object(
        page=page,
        value="<b>🔑 Auth Key:</b> 16 bytes<br/>"
              "<b>Nonce:</b> 15B → pad → 16B<br/>"
              "<b>Ring Time:</b> deciseconds",
        width=140, height=55
    )
    key_box.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=9;align=left;spacingLeft=8;")
    key_box.position = (200, 480)

    event_box = Object(
        page=page,
        value="<b>📊 Event Tags:</b><br/>"
              "0x6a=Sleep, 0x46=Temp<br/>"
              "0x5a=IBI, 0x41-0x80=...",
        width=140, height=55
    )
    event_box.apply_style_string(BOX_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};fontSize=9;align=left;spacingLeft=8;")
    event_box.position = (360, 480)

    # Result indicators
    res1 = Object(page=page, value="<b>✅ Ring configured</b>", width=120, height=26)
    res1.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=10;")
    res1.position = (130, Y_RING + 65)

    res2 = Object(page=page, value="<b>✅ Authenticated</b>", width=110, height=26)
    res2.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=10;")
    res2.position = (360, Y_RING + 65)

    res3 = Object(page=page, value="<b>✅ Health Data</b>", width=100, height=26)
    res3.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=10;")
    res3.position = (680, Y_RING + 65)

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_ble_flow_diagram()
    print("\n📂 BLE flow diagram ready!")
