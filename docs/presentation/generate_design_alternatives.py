#!/usr/bin/env python3
"""
Generate three design alternatives for BLE flow diagrams
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Common colors
BLUE = ('#dae8fc', '#6c8ebf')
GREEN = ('#d5e8d4', '#82b366')
YELLOW = ('#fff2cc', '#d6b656')
RED = ('#f8cecc', '#b85450')
PURPLE = ('#e1d5e7', '#9673a6')
ORANGE = ('#ffe6cc', '#d79b00')
GRAY = ('#f5f5f5', '#666666')
DARK = ('#222222', '#222222')

# Flow data with labels
FLOWS = {
    "first_time": {
        "title": "🆕 First-Time Setup",
        "steps": [
            ("🔄 Factory Reset", "Clears stored data", RED),
            ("🔗 Connect", "BLE connection", BLUE),
            ("🤝 Pair", "Secure bonding", BLUE),
            ("🔑 SetAuthKey", "Store shared secret", YELLOW),
            ("🕐 SyncTime", "Align clocks", BLUE),
            ("✅ Ready", "", GREEN),
        ]
    },
    "normal": {
        "title": "🔄 Normal Connection",
        "steps": [
            ("🔗 Connect", "BLE reconnect", BLUE),
            ("🔐 Authenticate", "Prove identity (AES)", YELLOW),
            ("📡 Subscribe", "Enable data stream", BLUE),
            ("✅ Syncing", "", GREEN),
        ]
    },
    "read_data": {
        "title": "📥 Read Data",
        "steps": [
            ("📡 Subscribed", "Channel ready", BLUE),
            ("📤 Request", "GetEvent command", PURPLE),
            ("📨 Receive", "Batched transfer", ORANGE),
            ("🔄 Parse", "Decode Protobuf", BLUE),
            ("✅ Data Ready", "", GREEN),
        ]
    }
}


# ============================================================
# DESIGN 1: Classic with Labels Inside (Compact)
# ============================================================
def create_design1():
    """Classic boxes with two-line labels inside each node"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "design1_classic_compact.drawio"
    page = drawpyo.Page(file=file, name="Classic Compact")

    TITLE_STYLE = "text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=14;fontFamily=Helvetica;fontColor=#222222;"
    BOX_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=12;fontFamily=Helvetica;fontColor=#222222;shadow=1;arcSize=15;"

    W, H = 130, 50
    SPACING = 60
    COL_SPACING = 160
    Y_START = 50

    all_cols = []
    for col_idx, (key, flow) in enumerate(FLOWS.items()):
        x = 30 + col_idx * COL_SPACING

        # Title
        title = Object(page=page, value=f"<b>{flow['title']}</b>", width=W, height=25)
        title.apply_style_string(TITLE_STYLE)
        title.position = (x, Y_START - 35)

        # Steps
        objects = []
        for i, (name, label, color) in enumerate(flow['steps']):
            y = Y_START + i * SPACING

            # Two-line text: name bold, label smaller
            if label:
                text = f"<b>{name}</b><br/><font style='font-size:10px;color:#666666;'>{label}</font>"
            else:
                text = f"<b>{name}</b>"

            obj = Object(page=page, value=text, width=W, height=H)
            obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
            obj.position = (x, y)
            objects.append(obj)

        # Edges
        for i in range(len(objects) - 1):
            Edge(page=page, source=objects[i], target=objects[i + 1])

        all_cols.append(objects)

    file.write()
    print(f"✅ {file.file_name}")


# ============================================================
# DESIGN 2: Timeline/Infographic Style (Numbered Circles)
# ============================================================
def create_design2():
    """Timeline style with numbered circles and text to the right"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "design2_timeline.drawio"
    page = drawpyo.Page(file=file, name="Timeline")

    TITLE_STYLE = "text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=14;fontFamily=Helvetica;fontColor=#222222;"
    CIRCLE_STYLE = "ellipse;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=12;fontFamily=Helvetica;fontStyle=1;fontColor=white;shadow=1;"
    TEXT_STYLE = "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;fontSize=11;fontFamily=Helvetica;fontColor=#222222;"
    LINE_STYLE = "strokeWidth=2;strokeColor=#cccccc;dashed=1;fillColor=none;"

    CIRCLE_SIZE = 36
    SPACING = 50
    COL_SPACING = 170
    Y_START = 50

    for col_idx, (key, flow) in enumerate(FLOWS.items()):
        x = 40 + col_idx * COL_SPACING

        # Title
        title = Object(page=page, value=f"<b>{flow['title']}</b>", width=140, height=25)
        title.apply_style_string(TITLE_STYLE)
        title.position = (x - 10, Y_START - 40)

        # Vertical line (timeline)
        line_height = (len(flow['steps']) - 1) * SPACING
        line = Object(page=page, value="", width=2, height=line_height)
        line.apply_style_string(LINE_STYLE)
        line.position = (x + CIRCLE_SIZE/2 - 1, Y_START + CIRCLE_SIZE/2)

        # Steps
        prev_circle = None
        for i, (name, label, color) in enumerate(flow['steps']):
            y = Y_START + i * SPACING

            # Numbered circle
            circle = Object(page=page, value=str(i + 1), width=CIRCLE_SIZE, height=CIRCLE_SIZE)
            circle.apply_style_string(CIRCLE_STYLE + f"fillColor={color[1]};strokeColor={color[1]};")
            circle.position = (x, y)

            # Text to the right
            display_name = name.split(" ", 1)[1] if " " in name else name  # Remove emoji
            if label:
                text_content = f"<b>{display_name}</b><br/><font color='#888888'>{label}</font>"
            else:
                text_content = f"<b>{display_name}</b>"

            text = Object(page=page, value=text_content, width=110, height=40)
            text.apply_style_string(TEXT_STYLE)
            text.position = (x + CIRCLE_SIZE + 8, y - 2)

            prev_circle = circle

    file.write()
    print(f"✅ {file.file_name}")


# ============================================================
# DESIGN 3: Card/Tile Style (Modern Flat)
# ============================================================
def create_design3():
    """Modern card/tile style with icons and subtle shadows"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "design3_cards.drawio"
    page = drawpyo.Page(file=file, name="Cards")

    HEADER_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=0;fontSize=13;fontFamily=Helvetica;fontStyle=1;fontColor=white;arcSize=8;"
    CARD_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=1;fontSize=11;fontFamily=Helvetica;fontColor=#333333;shadow=0;arcSize=8;align=left;spacingLeft=10;"
    ARROW_STYLE = "shape=mxgraph.arrows2.arrow;dy=0.6;dx=20;notch=0;strokeWidth=0;"

    W, H = 140, 38
    SPACING = 48
    COL_SPACING = 165
    Y_START = 70
    HEADER_COLORS = [('#b85450', '#b85450'), ('#6c8ebf', '#6c8ebf'), ('#9673a6', '#9673a6')]

    for col_idx, (key, flow) in enumerate(FLOWS.items()):
        x = 25 + col_idx * COL_SPACING
        header_color = HEADER_COLORS[col_idx]

        # Column header (colored banner)
        header = Object(page=page, value=flow['title'], width=W, height=32)
        header.apply_style_string(HEADER_STYLE + f"fillColor={header_color[0]};")
        header.position = (x, Y_START - 45)

        # Steps as cards
        objects = []
        for i, (name, label, color) in enumerate(flow['steps']):
            y = Y_START + i * SPACING

            # Clean name (keep emoji)
            if label:
                text = f"{name}<br/><font style='font-size:9px;color:#888888;'>{label}</font>"
            else:
                text = f"{name}"

            card = Object(page=page, value=text, width=W, height=H)
            card.apply_style_string(CARD_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
            card.position = (x, y)
            objects.append(card)

        # Small arrows between cards
        for i in range(len(objects) - 1):
            arrow = Object(page=page, value="", width=12, height=10)
            arrow.apply_style_string(ARROW_STYLE + f"fillColor=#cccccc;rotation=90;")
            arrow_y = Y_START + i * SPACING + H + 2
            arrow.position = (x + W/2 - 6, arrow_y)

    file.write()
    print(f"✅ {file.file_name}")


# Run all
if __name__ == "__main__":
    create_design1()
    create_design2()
    create_design3()
    print("\n📂 Three design alternatives ready!")
