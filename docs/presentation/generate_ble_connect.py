#!/usr/bin/env python3
"""
Generate BLE Normal Connection Flow
Horizontal lifelines with sequential request-response arrows (no hex bytes)
Shows: Pair → Connect → Auth → GetEvent → Listen Notify
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


def create_connect_diagram():
    """Create normal connection BLE flow"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "ble_connect.drawio"
    page = drawpyo.Page(file=file, name="Normal Connection")
    page.page_width = 1400
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
    title = Object(page=page, value="<b>🔄 Normal Connection (after setup)</b>", width=400, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (500, 15)

    # =========================================================================
    # Horizontal Lifelines
    # =========================================================================
    Y_PHONE = 120
    Y_RING = 380
    X_START = 120
    X_END = 1280

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
    # Sequential Messages
    # =========================================================================

    # --- CONNECTION PHASE ---
    conn_messages = [
        (150, 200, "BLE Scan", "Found Ring"),
        (270, 320, "Connect", "Connected"),
    ]

    for x_req, x_resp, label_req, label_resp in conn_messages:
        create_message_pair(page, x_req, x_resp, label_req, label_resp,
                           Y_PHONE, Y_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                           ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN)

    # --- AUTHENTICATION PHASE ---
    auth_messages = [
        (420, 480, "Get Nonce", "Nonce (15 bytes)"),
        (560, 620, "Auth Response", "Auth OK"),
    ]

    for x_req, x_resp, label_req, label_resp in auth_messages:
        create_message_pair(page, x_req, x_resp, label_req, label_resp,
                           Y_PHONE, Y_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                           ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN)

    # AES Encrypt box
    encrypt = Object(
        page=page,
        value="<b>🔐 AES-128</b><br/>Encrypt nonce",
        width=100, height=45
    )
    encrypt.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};fontSize=10;")
    encrypt.position = (500, (Y_PHONE + Y_RING) // 2 - 22)

    # --- DATA PHASE ---
    # GetEvent request
    x_get = 720
    wp_phone_get = Object(page=page, value="", width=6, height=6)
    wp_phone_get.apply_style_string(WAYPOINT_STYLE)
    wp_phone_get.position = (x_get - 3, Y_PHONE - 3)

    wp_ring_get = Object(page=page, value="", width=6, height=6)
    wp_ring_get.apply_style_string(WAYPOINT_STYLE)
    wp_ring_get.position = (x_get - 3, Y_RING - 3)

    edge_get = Edge(page=page, source=wp_phone_get, target=wp_ring_get)
    edge_get.apply_style_string(ARROW_DOWN_STYLE)

    lbl_get = Object(page=page, value="<b>GetEvent</b>", width=100, height=20)
    lbl_get.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};")
    lbl_get.position = (x_get - 50, Y_PHONE - 35)

    # Batch info response
    x_batch = 780
    wp_ring_batch = Object(page=page, value="", width=6, height=6)
    wp_ring_batch.apply_style_string(WAYPOINT_STYLE)
    wp_ring_batch.position = (x_batch - 3, Y_RING - 3)

    wp_phone_batch = Object(page=page, value="", width=6, height=6)
    wp_phone_batch.apply_style_string(WAYPOINT_STYLE)
    wp_phone_batch.position = (x_batch - 3, Y_PHONE - 3)

    edge_batch = Edge(page=page, source=wp_ring_batch, target=wp_phone_batch)
    edge_batch.apply_style_string(ARROW_UP_STYLE)

    lbl_batch = Object(page=page, value="<b>Batch Info</b>", width=100, height=20)
    lbl_batch.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};")
    lbl_batch.position = (x_batch - 50, Y_RING + 20)

    # Multiple notification events
    event_positions = [860, 940, 1020, 1100]
    event_labels = ["Sleep Data", "Heart Rate", "Temperature", "HRV Data"]

    for i, (x_evt, label) in enumerate(zip(event_positions, event_labels)):
        wp_ring_evt = Object(page=page, value="", width=6, height=6)
        wp_ring_evt.apply_style_string(WAYPOINT_STYLE)
        wp_ring_evt.position = (x_evt - 3, Y_RING - 3)

        wp_phone_evt = Object(page=page, value="", width=6, height=6)
        wp_phone_evt.apply_style_string(WAYPOINT_STYLE)
        wp_phone_evt.position = (x_evt - 3, Y_PHONE - 3)

        edge_evt = Edge(page=page, source=wp_ring_evt, target=wp_phone_evt)
        edge_evt.apply_style_string(ARROW_UP_STYLE)

        lbl_evt = Object(page=page, value=f"<b>{label}</b>", width=90, height=20)
        lbl_evt.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};fontSize=10;")
        lbl_evt.position = (x_evt - 45, Y_RING + 20)

    # Notify bracket
    notify_box = Object(page=page, value="", width=280, height=30)
    notify_box.apply_style_string(f"{SKETCH}rounded=0;fillColor=none;strokeColor={PURPLE[1]};strokeWidth=2;dashed=1;")
    notify_box.position = (840, Y_RING + 45)

    notify_lbl = Object(page=page, value="<b>📥 BLE Notifications (streaming)</b>", width=220, height=20)
    notify_lbl.apply_style_string(LABEL_STYLE + f"fontColor={PURPLE[1]};fontSize=10;")
    notify_lbl.position = (890, Y_RING + 80)

    # =========================================================================
    # Section labels
    # =========================================================================
    sec_style = f"text;html=1;strokeColor=none;fillColor=none;align=center;fontSize=12;fontFamily={COMIC_FONT};fontColor=#666;fontStyle=1;"

    sec1 = Object(page=page, value="Connect", width=150, height=20)
    sec1.apply_style_string(sec_style)
    sec1.position = (180, 60)

    sec2 = Object(page=page, value="Authenticate", width=180, height=20)
    sec2.apply_style_string(sec_style)
    sec2.position = (460, 60)

    sec3 = Object(page=page, value="Read Health Data", width=300, height=20)
    sec3.apply_style_string(sec_style)
    sec3.position = (880, 60)

    # =========================================================================
    # Legend
    # =========================================================================
    leg1 = Object(page=page, value="<b>───▶</b> Phone → Ring (Write)", width=160, height=18)
    leg1.apply_style_string(LABEL_STYLE + f"fontColor={BLUE[1]};align=left;fontSize=11;")
    leg1.position = (130, 450)

    leg2 = Object(page=page, value="<b>- - ▶</b> Ring → Phone (Notify)", width=160, height=18)
    leg2.apply_style_string(LABEL_STYLE + f"fontColor={GREEN[1]};align=left;fontSize=11;")
    leg2.position = (130, 475)

    # Characteristic info
    char_box = Object(
        page=page,
        value="<b>BLE Characteristics:</b><br/>"
              "Write: 98ed0002-...<br/>"
              "Notify: 98ed0003-...",
        width=150, height=55
    )
    char_box.apply_style_string(BOX_STYLE + f"fillColor=#fafafa;strokeColor=#ccc;fontSize=9;align=left;spacingLeft=8;")
    char_box.position = (130, 510)

    # Result
    result = Object(page=page, value="<b>📊 Health Data!</b><br/>HR, Sleep, SpO2, Temp, HRV", width=180, height=50)
    result.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=12;")
    result.position = (1100, 450)

    file.write()
    print(f"✅ Created {file.file_name}")


def create_message_pair(page, x_req, x_resp, label_req, label_resp,
                        Y_PHONE, Y_RING, WAYPOINT_STYLE, ARROW_DOWN_STYLE,
                        ARROW_UP_STYLE, LABEL_STYLE, BLUE, GREEN):
    """Helper to create request-response arrow pair"""
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


if __name__ == "__main__":
    create_connect_diagram()
    print("\n📂 Normal connection diagram ready!")
