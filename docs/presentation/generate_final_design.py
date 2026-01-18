#!/usr/bin/env python3
"""
Generate final BLE flow diagram - Design 1 improved with equal height columns
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

# Flow data with labels
FLOWS = [
    {
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
    {
        "title": "🔄 Normal Connection",
        "steps": [
            ("🔗 Connect", "BLE reconnect", BLUE),
            ("🔐 Authenticate", "Prove identity (AES)", YELLOW),
            ("📡 Subscribe", "Enable data stream", BLUE),
            ("✅ Syncing", "", GREEN),
        ]
    },
    {
        "title": "📥 Read Data",
        "steps": [
            ("📡 Subscribed", "Channel ready", BLUE),
            ("📤 Request", "GetEvent command", PURPLE),
            ("📨 Receive", "Batched transfer", ORANGE),
            ("🔄 Parse", "Decode Protobuf", BLUE),
            ("✅ Data Ready", "", GREEN),
        ]
    }
]


def create_final_design():
    """Classic boxes with equal height columns and dynamic spacing"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "ble_flows_final.drawio"
    page = drawpyo.Page(file=file, name="BLE Flows")

    # Styles with larger fonts
    TITLE_STYLE = "text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=16;fontFamily=Helvetica;fontColor=#222222;"
    BOX_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=14;fontFamily=Helvetica;fontColor=#222222;shadow=1;arcSize=12;"

    # Dimensions
    W, H = 150, 55
    COL_SPACING = 360  # Double spacing between pillars
    Y_START = 60
    X_START = 30

    # Find max steps to determine total height
    max_steps = max(len(flow['steps']) for flow in FLOWS)
    TOTAL_HEIGHT = 420  # Fixed total height for all columns

    for col_idx, flow in enumerate(FLOWS):
        x = X_START + col_idx * COL_SPACING
        num_steps = len(flow['steps'])

        # Calculate dynamic spacing for this column
        # Space between nodes = (total_height - num_nodes * node_height) / (num_nodes - 1)
        if num_steps > 1:
            spacing = (TOTAL_HEIGHT - num_steps * H) / (num_steps - 1)
        else:
            spacing = 0

        # Title
        title = Object(page=page, value=f"<b>{flow['title']}</b>", width=W, height=30)
        title.apply_style_string(TITLE_STYLE)
        title.position = (x, Y_START - 45)

        # Steps
        objects = []
        for i, (name, label, color) in enumerate(flow['steps']):
            y = Y_START + i * (H + spacing)

            # Two-line text: name bold, label smaller gray
            if label:
                text = f"<b>{name}</b><br/><font style='font-size:11px;color:#666666;'>{label}</font>"
            else:
                text = f"<b>{name}</b>"

            obj = Object(page=page, value=text, width=W, height=H)
            obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
            obj.position = (x, y)
            objects.append(obj)

        # Edges between nodes
        for i in range(len(objects) - 1):
            Edge(page=page, source=objects[i], target=objects[i + 1])

    file.write()
    print(f"✅ {file.file_name}")


if __name__ == "__main__":
    create_final_design()
    print("\n📂 Final design ready!")
