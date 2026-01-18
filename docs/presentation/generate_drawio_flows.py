#!/usr/bin/env python3
"""
Generate three BLE flow diagrams in Draw.io format with optional labels
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Design Constants
SOFT_BLACK = "#222222"
FONT_SIZE = 14
LABEL_FONT_SIZE = 11
FONT_FAMILY = "Helvetica"

# Colors
BLUE_FILL, BLUE_STROKE = '#dae8fc', '#6c8ebf'
GREEN_FILL, GREEN_STROKE = '#d5e8d4', '#82b366'
YELLOW_FILL, YELLOW_STROKE = '#fff2cc', '#d6b656'
RED_FILL, RED_STROKE = '#f8cecc', '#b85450'
PURPLE_FILL, PURPLE_STROKE = '#e1d5e7', '#9673a6'
ORANGE_FILL, ORANGE_STROKE = '#ffe6cc', '#d79b00'
GRAY_FILL, GRAY_STROKE = '#f5f5f5', '#999999'

# Styles
BOX = f"rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize={FONT_SIZE};fontFamily={FONT_FAMILY};fontColor={SOFT_BLACK};shadow=1;arcSize=12;"
END = f"ellipse;whiteSpace=wrap;html=1;strokeWidth=2;fontSize={FONT_SIZE};fontFamily={FONT_FAMILY};fontStyle=1;fontColor={SOFT_BLACK};shadow=1;"
TITLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=16;fontFamily={FONT_FAMILY};fontColor={SOFT_BLACK};"
LABEL = f"rounded=1;whiteSpace=wrap;html=1;strokeWidth=1;fontSize={LABEL_FONT_SIZE};fontFamily={FONT_FAMILY};fontColor=#666666;fontStyle=2;dashed=1;"

W, H = 160, 50
LABEL_W = 140
SPACING = 70
X_START = 40
Y_START = 50


def create_flow(filename, title, steps, labels=None):
    """Create a single flow diagram"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = filename
    page = drawpyo.Page(file=file, name="Flow")

    # Title
    title_obj = Object(page=page, value=title, width=W + (LABEL_W + 20 if labels else 0), height=30)
    title_obj.apply_style_string(TITLE)
    title_obj.position = (X_START, Y_START - 40)

    # Steps
    objects = []
    for i, (icon, text, fill, stroke, is_end) in enumerate(steps):
        y = Y_START + i * SPACING

        obj = Object(page=page, value=f"{icon} {text}", width=W, height=H)
        if is_end:
            obj.apply_style_string(END + f"fillColor={fill};strokeColor={stroke};")
        else:
            obj.apply_style_string(BOX + f"fillColor={fill};strokeColor={stroke};")
        obj.position = (X_START, y)
        objects.append(obj)

        # Add label if provided
        if labels and i < len(labels) and labels[i]:
            label_obj = Object(page=page, value=labels[i], width=LABEL_W, height=H - 10)
            label_obj.apply_style_string(LABEL + f"fillColor={GRAY_FILL};strokeColor={GRAY_STROKE};")
            label_obj.position = (X_START + W + 20, y + 5)

    # Edges
    for i in range(len(objects) - 1):
        Edge(page=page, source=objects[i], target=objects[i + 1])

    file.write()
    print(f"✅ {filename}")


# Flow 1: First-Time Setup
steps1 = [
    ("🔄", "Factory Reset", RED_FILL, RED_STROKE, False),
    ("🔗", "Connect", BLUE_FILL, BLUE_STROKE, False),
    ("🤝", "Pair", BLUE_FILL, BLUE_STROKE, False),
    ("🔑", "SetAuthKey", YELLOW_FILL, YELLOW_STROKE, False),
    ("🕐", "SyncTime", BLUE_FILL, BLUE_STROKE, False),
    ("✅", "Ready", GREEN_FILL, GREEN_STROKE, True),
]
labels1 = [
    "ResetMemory 0x1a<br/>Frida tracing",
    "Service 98ed0001<br/>SweetBlue hooks",
    "Android BLE Bonding<br/>BluetoothDevice",
    "0x24 + 16-byte key<br/>Cloud sync",
    "0x12/0x13<br/>Unix timestamp + TZ",
    None,
]

# Flow 2: Normal Connection
steps2 = [
    ("🔗", "Connect", BLUE_FILL, BLUE_STROKE, False),
    ("🔐", "Authenticate", YELLOW_FILL, YELLOW_STROKE, False),
    ("📡", "Subscribe", BLUE_FILL, BLUE_STROKE, False),
    ("✅", "Syncing", GREEN_FILL, GREEN_STROKE, True),
]
labels2 = [
    "Write 98ed0002<br/>Notify 98ed0003",
    "Nonce + AES-ECB<br/>0x2b→0x2c→0x2d→0x2e",
    "SetFeatureSubscription<br/>0x26/0x27 CCCD",
    None,
]

# Flow 3: Read Data
steps3 = [
    ("📡", "Subscribed", BLUE_FILL, BLUE_STROKE, False),
    ("📤", "Request Data", PURPLE_FILL, PURPLE_STROKE, False),
    ("📨", "Receive Chunks", ORANGE_FILL, ORANGE_STROKE, False),
    ("🔄", "Parse Response", BLUE_FILL, BLUE_STROKE, False),
    ("✅", "Data Ready", GREEN_FILL, GREEN_STROKE, True),
]
labels3 = [
    "Notify characteristic<br/>ready for data",
    "GetEvent 0x10/0x11<br/>SyncTime, RData",
    "MTU ~244 bytes<br/>MORE_REQUEST 0x01",
    "Protobuf ≥0x41<br/>libringeventparser.so",
    None,
]

# Generate without labels (clean version)
create_flow("flow_1_drawio.drawio", "🆕 First-Time Setup", steps1)
create_flow("flow_2_drawio.drawio", "🔄 Normal Connection", steps2)
create_flow("flow_3_drawio.drawio", "📥 Read Data", steps3)

# Generate with labels
create_flow("flow_1_drawio_labels.drawio", "🆕 First-Time Setup", steps1, labels1)
create_flow("flow_2_drawio_labels.drawio", "🔄 Normal Connection", steps2, labels2)
create_flow("flow_3_drawio_labels.drawio", "📥 Read Data", steps3, labels3)

print("\n📂 Draw.io flows ready!")
