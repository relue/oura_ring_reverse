#!/usr/bin/env python3
"""
Generate BLE First-Time Setup Flow
Horizontal lifelines with sequential request-response arrows (no hex bytes)
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


def create_setup_diagram():
    """Create first-time setup BLE flow"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "ble_setup.drawio"
    page = drawpyo.Page(file=file, name="First Time Setup")
    page.page_width = 1200
    page.page_height = 700

    # Styles
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"
    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=24;fontFamily={COMIC_FONT};fontColor=#222222;"
    LABEL_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=11;fontFamily={COMIC_FONT};fontColor=#444444;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=12;fontFamily={COMIC_FONT};fontColor=#222222;"
    WAYPOINT_STYLE = "ellipse;whiteSpace=wrap;html=1;fillColor=#333333;strokeColor=none;"
    ARROW_DOWN_STYLE = f"endArrow=classic;startArrow=none;strokeColor={BLUE[1]};strokeWidth=2;"
    ARROW_UP_STYLE = f"endArrow=classic;startArrow=none;strokeColor={GREEN[1]};strokeWidth=2;dashed=1;"

    # Title
    title = Object(page=page, value="<b>📱 First-Time Setup</b>", width=300, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (450, 15)

    # =========================================================================
    # Horizontal Lifelines
    # =========================================================================
    Y_PHONE = 120
    Y_RING = 380
    X_START = 120
    X_END = 1050

    # Phone lifeline
    phone_label = Object(page=page, value="<b>📱 Phone</b>", width=80, height=35)
    phone_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=14;")
    phone_label.position = (X_START - 95, Y_PHONE - 17)

    phone_line = Object(page=page, value="", width=X_END - X_START, height=3)
    phone_line.apply_style_string("rounded=0;fillColor=#444444;strokeColor=none;")
    phone_line.position = (X_START, Y_PHONE)

    # Ring lifeline
    ring_label = Object(page=page, value="<b>💍 Ring</b>", width=80, height=35)
    ring_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=14;")
    ring_label.position = (X_START - 95, Y_RING - 17)

    ring_line = Object(page=page, value="", width=X_END - X_START, height=3)
    ring_line.apply_style_string("rounded=0;fillColor=#444444;strokeColor=none;")
    ring_line.position = (X_START, Y_RING)

    # Time arrow
    time_lbl = Object(page=page, value="<i>time →</i>", width=50, height=20)
    time_lbl.apply_style_string(LABEL_STYLE + "fontSize=10;fontColor=#888;")
    time_lbl.position = (X_END + 10, (Y_PHONE + Y_RING) // 2 - 10)

    # =========================================================================
    # Sequential Messages (request at x, response at x+50)
    # Format: (x_req, x_resp, label_req, label_resp)
    # =========================================================================
    messages = [
        # BLE Connect & Bond
        (150, 200, "BLE Scan", "Found 'Oura_XXXX'"),
        (260, 310, "Connect", "Connected"),
        (370, 420, "Pair & Bond", "Bonded"),

        # Factory Reset
        (500, 560, "Factory Reset", "ACK"),

        # Set Auth Key
        (640, 700, "Set Auth Key", "Key Stored"),

        # Time Sync
        (790, 860, "Time Sync", "Ring Time"),
    ]

    for x_req, x_resp, label_req, label_resp in messages:
        # Request waypoints
        wp_phone_req = Object(page=page, value="", width=6, height=6)
        wp_phone_req.apply_style_string(WAYPOINT_STYLE)
        wp_phone_req.position = (x_req - 3, Y_PHONE - 3)

        wp_ring_req = Object(page=page, value="", width=6, height=6)
        wp_ring_req.apply_style_string(WAYPOINT_STYLE)
        wp_ring_req.position = (x_req - 3, Y_RING - 3)

        # Request arrow (down)
        edge_req = Edge(page=page, source=wp_phone_req, target=wp_ring_req)
        edge_req.apply_style_string(ARROW_DOWN_STYLE)

        # Request label
        lbl_req = Object(page=page, value=f"<b>{label_req}</b>", width=100, height=20)
        lbl_req.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};")
        lbl_req.position = (x_req - 50, Y_PHONE - 35)

        # Response waypoints
        wp_ring_resp = Object(page=page, value="", width=6, height=6)
        wp_ring_resp.apply_style_string(WAYPOINT_STYLE)
        wp_ring_resp.position = (x_resp - 3, Y_RING - 3)

        wp_phone_resp = Object(page=page, value="", width=6, height=6)
        wp_phone_resp.apply_style_string(WAYPOINT_STYLE)
        wp_phone_resp.position = (x_resp - 3, Y_PHONE - 3)

        # Response arrow (up)
        edge_resp = Edge(page=page, source=wp_ring_resp, target=wp_phone_resp)
        edge_resp.apply_style_string(ARROW_UP_STYLE)

        # Response label
        lbl_resp = Object(page=page, value=f"<b>{label_resp}</b>", width=100, height=20)
        lbl_resp.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};")
        lbl_resp.position = (x_resp - 50, Y_RING + 20)

    # =========================================================================
    # Section dividers & labels
    # =========================================================================
    sec_style = f"text;html=1;strokeColor=none;fillColor=none;align=center;fontSize=12;fontFamily={COMIC_FONT};fontColor=#666;fontStyle=1;"

    sec1 = Object(page=page, value="BLE Connection", width=200, height=20)
    sec1.apply_style_string(sec_style)
    sec1.position = (200, 60)

    sec2 = Object(page=page, value="Ring Configuration", width=280, height=20)
    sec2.apply_style_string(sec_style)
    sec2.position = (580, 60)

    # Key generation note
    key_note = Object(
        page=page,
        value="<b>🔑 Generate</b><br/>Random AES-128 key",
        width=110, height=45
    )
    key_note.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=10;")
    key_note.position = (615, (Y_PHONE + Y_RING) // 2 - 22)

    # =========================================================================
    # Legend & Result
    # =========================================================================
    leg1 = Object(page=page, value="<b>───▶</b> Phone → Ring", width=120, height=18)
    leg1.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};align=left;fontSize=11;")
    leg1.position = (130, 450)

    leg2 = Object(page=page, value="<b>- - ▶</b> Ring → Phone", width=120, height=18)
    leg2.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};align=left;fontSize=11;")
    leg2.position = (130, 475)

    result = Object(page=page, value="<b>✅ Ring Ready!</b><br/>Key stored on both sides", width=180, height=50)
    result.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=12;")
    result.position = (920, 450)

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_setup_diagram()
    print("\n📂 First-time setup diagram ready!")
