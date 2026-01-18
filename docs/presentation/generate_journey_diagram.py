#!/usr/bin/env python3
"""
Generate Reverse Engineering Journey diagram for presentation
Shows the discovery path from connection to full data access
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Colors - More distinct palette
BLUE = ('#bbdefb', '#1976d2')      # Bright blue
GREEN = ('#c8e6c9', '#388e3c')     # Strong green
YELLOW = ('#fff9c4', '#f9a825')    # Vivid yellow
RED = ('#ffcdd2', '#d32f2f')       # Bold red
PURPLE = ('#e1bee7', '#7b1fa2')    # Deep purple
ORANGE = ('#ffe0b2', '#e65100')    # Vibrant orange
GRAY = ('#f5f5f5', '#666666')


def create_journey_diagram():
    """Create the reverse engineering journey visualization"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "re_journey.drawio"
    page = drawpyo.Page(file=file, name="RE Journey")
    # Widescreen 16:9 canvas (1920x1080)
    page.page_width = 1920
    page.page_height = 1080

    # Styles - COMIC style with hand-drawn look
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"  # Schoolgirl notes style font
    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=24;fontFamily={COMIC_FONT};fontColor=#222222;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=3;fontSize=14;fontFamily={COMIC_FONT};fontColor=#222222;arcSize=15;"
    FAIL_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=3;fontSize=14;fontFamily={COMIC_FONT};fontColor=#222222;arcSize=15;dashed=1;dashPattern=8 8;"
    ARROW_STYLE = f"{SKETCH}strokeWidth=3;strokeColor=#444444;"
    DISCOVERY_STYLE = f"{SKETCH}shape=callout;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=13;fontFamily={COMIC_FONT};fontColor=#333333;perimeter=calloutPerimeter;position=0.5;position2=0;base=15;size=10;"
    SCRIPT_STYLE = f"{SKETCH}shape=note;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=11;fontFamily={COMIC_FONT};fontColor=#555555;backgroundOutline=1;align=left;spacingLeft=4;"

    # Title
    title = Object(page=page, value="<b>🔍 Reverse Engineering Journey</b>", width=500, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (150, 5)

    # Journey steps (left column - main path)
    # Format: (label, description, color, is_fail, y_position)
    steps = [
        ("1️⃣ BLE Connect", "Connection works!\nBonding uses RPA", BLUE, False, 55),
        ("2️⃣ Send Commands", "Try to send data...", YELLOW, False, 155),
        ("❌ FAILED", "Commands rejected\nby ring", RED, True, 255),
        ("3️⃣ Trace App", "What does app do\non connect?", PURPLE, False, 355),
        ("💡 Found Auth!", "Ring requires\nauthentication", GREEN, False, 455),
        ("4️⃣ Trace Auth", "How does auth work?", PURPLE, False, 555),
        ("🔑 Found Key", "AES-128 shared secret\nin app database", GREEN, False, 655),
    ]

    step_objects = []
    X_LEFT = 50
    W, H = 170, 70  # Larger nodes

    for label, desc, color, is_fail, y in steps:
        style = FAIL_STYLE if is_fail else BOX_STYLE
        obj = Object(
            page=page,
            value=f"<b>{label}</b><br/><font style='font-size:12px;color:#444;'>{desc}</font>",
            width=W, height=H
        )
        obj.apply_style_string(style + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (X_LEFT, y)
        step_objects.append(obj)

    # Arrows between steps
    for i in range(len(step_objects) - 1):
        edge = Edge(page=page, source=step_objects[i], target=step_objects[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # Second column - breakthrough path
    steps2 = [
        ("5️⃣ Use Key", "Authenticate with\ncaptured key", YELLOW, False, 55),
        ("✅ Commands Work!", "Can send any\ncommand now", GREEN, False, 155),
        ("6️⃣ Read Data", "GetEvent commands\nfor sensor data", PURPLE, False, 255),
        ("✅ Data Access!", "Protobuf decoded\nhealth data", GREEN, False, 355),
    ]

    step2_objects = []
    X_MID = 280  # More spacing for wide presentation

    for label, desc, color, is_fail, y in steps2:
        style = FAIL_STYLE if is_fail else BOX_STYLE
        obj = Object(
            page=page,
            value=f"<b>{label}</b><br/><font style='font-size:12px;color:#444;'>{desc}</font>",
            width=W, height=H
        )
        obj.apply_style_string(style + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (X_MID, y)
        step2_objects.append(obj)

    # Arrows for second column
    for i in range(len(step2_objects) - 1):
        edge = Edge(page=page, source=step2_objects[i], target=step2_objects[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # Connect key discovery to using key
    edge = Edge(page=page, source=step_objects[-1], target=step2_objects[0])
    edge.apply_style_string("strokeWidth=3;strokeColor=#82b366;")

    # Third column - own key path
    steps3 = [
        ("7️⃣ Factory Reset", "Full reset clears\nauth key from ring", ORANGE, False, 455),
        ("8️⃣ Fresh Setup", "Set our OWN\nauth key!", YELLOW, False, 555),
        ("🎉 Full Control", "Independent from\nOura app!", GREEN, False, 655),
    ]

    step3_objects = []
    X_RIGHT = 510  # More spacing for wide presentation

    for label, desc, color, is_fail, y in steps3:
        obj = Object(
            page=page,
            value=f"<b>{label}</b><br/><font style='font-size:12px;color:#444;'>{desc}</font>",
            width=W, height=H
        )
        obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        obj.position = (X_RIGHT, y)
        step3_objects.append(obj)

    # Arrows for third column
    for i in range(len(step3_objects) - 1):
        edge = Edge(page=page, source=step3_objects[i], target=step3_objects[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # Connect data access to factory reset investigation
    edge = Edge(page=page, source=step2_objects[-1], target=step3_objects[0])
    edge.apply_style_string("strokeWidth=3;strokeColor=#d79b00;")

    # Right side: Frida script annotations
    scripts = [
        ("comprehensive_\nconnection_trace.js", BLUE, 90),
        ("trace_complete_\nauth_flow.js", YELLOW, 165),
        ("capture_auth_key.js", GREEN, 240),
        ("trace-all-\noperations.js", PURPLE, 90),
        ("force_ble_\nfactory_reset.js", ORANGE, 390),
        ("complete_setup_\ntrace.js", YELLOW, 465),
    ]

    X_SCRIPTS = 720
    for name, color, y in scripts:
        script = Object(page=page, value=name, width=95, height=40)
        script.apply_style_string(SCRIPT_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        script.position = (X_SCRIPTS, y)

    # Label for scripts column
    scripts_label = Object(page=page, value="<b>🎣 Frida Scripts</b>", width=100, height=20)
    scripts_label.apply_style_string("text;html=1;strokeColor=none;fillColor=none;align=center;fontSize=10;fontColor=#666666;fontStyle=1;")
    scripts_label.position = (715, 55)

    # Final discovery callout
    discovery = Object(
        page=page,
        value="<b>📊 Result:</b> Sleep events,\nheart rate, SpO2,\ntemperature data!",
        width=130, height=55
    )
    discovery.apply_style_string(BOX_STYLE + "fillColor=#e8f5e9;strokeColor=#4caf50;fontSize=10;")
    discovery.position = (510, 355)

    # Arrow from data access to discovery
    edge = Edge(page=page, source=step2_objects[-1], target=discovery)
    edge.apply_style_string("strokeWidth=2;strokeColor=#4caf50;")

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_journey_diagram()
    print("\n📂 Journey diagram ready!")
