#!/usr/bin/env python3
"""
Generate Combined BLE Flow - Both Setup and Normal Connection on one slide
Two horizontal timeline charts stacked vertically
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


def create_message_pair(page, x_req, x_resp, label_req, label_resp,
                        Y_PHONE, Y_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                        ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN):
    """Helper to create request-response arrow pair"""
    wp_phone_req = Object(page=page, value="", width=5, height=5)
    wp_phone_req.apply_style_string(WAYPOINT_STYLE)
    wp_phone_req.position = (x_req - 2, Y_PHONE - 2)

    wp_ring_req = Object(page=page, value="", width=5, height=5)
    wp_ring_req.apply_style_string(WAYPOINT_STYLE)
    wp_ring_req.position = (x_req - 2, Y_RING - 2)

    edge_req = Edge(page=page, source=wp_phone_req, target=wp_ring_req)
    edge_req.apply_style_string(ARROW_DOWN_STYLE)

    lbl_req = Object(page=page, value=f"<b>{label_req}</b>", width=85, height=18)
    lbl_req.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};fontSize=11;")
    lbl_req.position = (x_req - 42, Y_PHONE - 26)

    wp_ring_resp = Object(page=page, value="", width=5, height=5)
    wp_ring_resp.apply_style_string(WAYPOINT_STYLE)
    wp_ring_resp.position = (x_resp - 2, Y_RING - 2)

    wp_phone_resp = Object(page=page, value="", width=5, height=5)
    wp_phone_resp.apply_style_string(WAYPOINT_STYLE)
    wp_phone_resp.position = (x_resp - 2, Y_PHONE - 2)

    edge_resp = Edge(page=page, source=wp_ring_resp, target=wp_phone_resp)
    edge_resp.apply_style_string(ARROW_UP_STYLE)

    lbl_resp = Object(page=page, value=f"<b>{label_resp}</b>", width=85, height=18)
    lbl_resp.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};fontSize=11;")
    lbl_resp.position = (x_resp - 42, Y_RING + 14)


def create_combined_diagram():
    """Create both flows on one slide"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "ble_combined.drawio"
    page = drawpyo.Page(file=file, name="BLE Protocol")
    page.page_width = 1920
    page.page_height = 1080

    # Styles
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"
    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=22;fontFamily={COMIC_FONT};fontColor=#222222;"
    SECTION_TITLE = f"text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=14;fontFamily={COMIC_FONT};fontColor=#333;fontStyle=1;"
    LABEL_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=9;fontFamily={COMIC_FONT};fontColor=#444444;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=10;fontFamily={COMIC_FONT};fontColor=#222222;"
    WAYPOINT_STYLE = "ellipse;whiteSpace=wrap;html=1;fillColor=#333333;strokeColor=none;"
    ARROW_DOWN_STYLE = f"endArrow=classic;startArrow=none;strokeColor={BLUE[1]};strokeWidth=2;"
    ARROW_UP_STYLE = f"endArrow=classic;startArrow=none;strokeColor={GREEN[1]};strokeWidth=2;dashed=1;"

    # Main Title
    title = Object(page=page, value="<b>📡 BLE Protocol Flow</b>", width=280, height=30)
    title.apply_style_string(TITLE_STYLE)
    title.position = (420, 8)

    # =========================================================================
    # CHART 1: First-Time Setup (top half)
    # =========================================================================
    Y1_PHONE = 95
    Y1_RING = 210
    X_START = 100
    X_END = 920

    # Section title
    sec1_title = Object(page=page, value="<b>1️⃣ First-Time Setup</b>", width=160, height=22)
    sec1_title.apply_style_string(SECTION_TITLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};rounded=1;align=center;")
    sec1_title.position = (X_START, 45)

    # Phone lifeline
    phone1_label = Object(page=page, value="<b>📱</b>", width=45, height=40)
    phone1_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=22;")
    phone1_label.position = (X_START - 55, Y1_PHONE - 20)

    phone1_line = Object(page=page, value="", width=X_END - X_START, height=2)
    phone1_line.apply_style_string("rounded=0;fillColor=#555;strokeColor=none;")
    phone1_line.position = (X_START, Y1_PHONE)

    # Ring lifeline
    ring1_label = Object(page=page, value="<b>💍</b>", width=45, height=40)
    ring1_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=22;")
    ring1_label.position = (X_START - 55, Y1_RING - 20)

    ring1_line = Object(page=page, value="", width=X_END - X_START, height=2)
    ring1_line.apply_style_string("rounded=0;fillColor=#555;strokeColor=none;")
    ring1_line.position = (X_START, Y1_RING)

    # Setup messages
    setup_msgs = [
        (130, 170, "Scan", "Found"),
        (220, 260, "Connect", "OK"),
        (310, 350, "Pair/Bond", "Bonded"),
        (420, 470, "Factory Reset", "ACK"),
        (550, 600, "Set Auth Key", "Stored"),
        (690, 750, "Time Sync", "Ring Time"),
    ]

    for x_req, x_resp, label_req, label_resp in setup_msgs:
        create_message_pair(page, x_req, x_resp, label_req, label_resp,
                           Y1_PHONE, Y1_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                           ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN)

    # Key generation note
    key_note = Object(page=page, value="<b>🔑 AES Key</b>", width=70, height=28)
    key_note.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=9;")
    key_note.position = (540, (Y1_PHONE + Y1_RING) // 2 - 14)

    # Result 1
    res1 = Object(page=page, value="<b>✅ Ready</b>", width=70, height=25)
    res1.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=10;")
    res1.position = (830, (Y1_PHONE + Y1_RING) // 2 - 12)

    # =========================================================================
    # CHART 2: Normal Connection (bottom half)
    # =========================================================================
    Y2_PHONE = 320
    Y2_RING = 435
    X_END2 = 920

    # Section title
    sec2_title = Object(page=page, value="<b>2️⃣ Normal Connection</b>", width=180, height=22)
    sec2_title.apply_style_string(SECTION_TITLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};rounded=1;align=center;")
    sec2_title.position = (X_START, 270)

    # Phone lifeline
    phone2_label = Object(page=page, value="<b>📱</b>", width=45, height=40)
    phone2_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=22;")
    phone2_label.position = (X_START - 55, Y2_PHONE - 20)

    phone2_line = Object(page=page, value="", width=X_END2 - X_START, height=2)
    phone2_line.apply_style_string("rounded=0;fillColor=#555;strokeColor=none;")
    phone2_line.position = (X_START, Y2_PHONE)

    # Ring lifeline
    ring2_label = Object(page=page, value="<b>💍</b>", width=45, height=40)
    ring2_label.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};fontSize=22;")
    ring2_label.position = (X_START - 55, Y2_RING - 20)

    ring2_line = Object(page=page, value="", width=X_END2 - X_START, height=2)
    ring2_line.apply_style_string("rounded=0;fillColor=#555;strokeColor=none;")
    ring2_line.position = (X_START, Y2_RING)

    # Connection messages
    conn_msgs = [
        (130, 170, "Scan", "Found"),
        (220, 260, "Connect", "OK"),
    ]

    for x_req, x_resp, label_req, label_resp in conn_msgs:
        create_message_pair(page, x_req, x_resp, label_req, label_resp,
                           Y2_PHONE, Y2_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                           ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN)

    # Auth messages
    auth_msgs = [
        (330, 380, "Get Nonce", "Nonce"),
        (450, 500, "Auth Response", "Auth OK"),
    ]

    for x_req, x_resp, label_req, label_resp in auth_msgs:
        create_message_pair(page, x_req, x_resp, label_req, label_resp,
                           Y2_PHONE, Y2_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                           ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN)

    # AES box
    aes_box = Object(page=page, value="<b>🔐 AES</b>", width=55, height=25)
    aes_box.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=9;")
    aes_box.position = (400, (Y2_PHONE + Y2_RING) // 2 - 12)

    # GetEvent request
    x_get = 570
    wp_get1 = Object(page=page, value="", width=5, height=5)
    wp_get1.apply_style_string(WAYPOINT_STYLE)
    wp_get1.position = (x_get - 2, Y2_PHONE - 2)

    wp_get2 = Object(page=page, value="", width=5, height=5)
    wp_get2.apply_style_string(WAYPOINT_STYLE)
    wp_get2.position = (x_get - 2, Y2_RING - 2)

    edge_get = Edge(page=page, source=wp_get1, target=wp_get2)
    edge_get.apply_style_string(ARROW_DOWN_STYLE)

    lbl_get = Object(page=page, value="<b>GetEvent</b>", width=80, height=18)
    lbl_get.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};fontSize=11;")
    lbl_get.position = (x_get - 40, Y2_PHONE - 26)

    # Streaming notifications
    notify_x = [620, 680, 740, 800, 860]
    notify_labels = ["Batch", "Sleep", "HR", "Temp", "..."]

    for x, label in zip(notify_x, notify_labels):
        wp_n1 = Object(page=page, value="", width=5, height=5)
        wp_n1.apply_style_string(WAYPOINT_STYLE)
        wp_n1.position = (x - 2, Y2_RING - 2)

        wp_n2 = Object(page=page, value="", width=5, height=5)
        wp_n2.apply_style_string(WAYPOINT_STYLE)
        wp_n2.position = (x - 2, Y2_PHONE - 2)

        edge_n = Edge(page=page, source=wp_n1, target=wp_n2)
        edge_n.apply_style_string(ARROW_UP_STYLE)

        lbl_n = Object(page=page, value=f"<b>{label}</b>", width=55, height=16)
        lbl_n.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};fontSize=10;")
        lbl_n.position = (x - 27, Y2_RING + 12)

    # Notify bracket
    notify_bracket = Object(page=page, value="<b>📥 Notifications</b>", width=120, height=18)
    notify_bracket.apply_style_string(LABEL_STYLE + f"fontColor={PURPLE[1]};fontSize=9;")
    notify_bracket.position = (680, Y2_RING + 28)

    # =========================================================================
    # Legend (right side)
    # =========================================================================
    leg_x = 950

    leg_title = Object(page=page, value="<b>Legend</b>", width=70, height=20)
    leg_title.apply_style_string(LABEL_STYLE + "fontSize=11;fontColor=#333;")
    leg_title.position = (leg_x, 60)

    leg1 = Object(page=page, value="<b>──▶</b> Write", width=80, height=16)
    leg1.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};align=left;fontSize=10;")
    leg1.position = (leg_x, 85)

    leg2 = Object(page=page, value="<b>- -▶</b> Notify", width=80, height=16)
    leg2.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};align=left;fontSize=10;")
    leg2.position = (leg_x, 105)

    # Info boxes
    char_box = Object(
        page=page,
        value="<b>BLE UUIDs</b><br/>"
              "Write: 98ed0002<br/>"
              "Notify: 98ed0003",
        width=110, height=50
    )
    char_box.apply_style_string(BOX_STYLE + f"fillColor=#fafafa;strokeColor=#ccc;fontSize=8;align=left;spacingLeft=6;")
    char_box.position = (leg_x, 140)

    key_info = Object(
        page=page,
        value="<b>🔑 Auth Key</b><br/>"
              "16-byte AES-128<br/>"
              "Stored on both sides",
        width=110, height=50
    )
    key_info.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=8;align=left;spacingLeft=6;")
    key_info.position = (leg_x, 200)

    data_info = Object(
        page=page,
        value="<b>📊 Health Data</b><br/>"
              "HR, Sleep, SpO2<br/>"
              "Temp, HRV, Steps",
        width=110, height=50
    )
    data_info.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=8;align=left;spacingLeft=6;")
    data_info.position = (leg_x, 260)

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_combined_diagram()
    print("\n📂 Combined BLE diagram ready!")
