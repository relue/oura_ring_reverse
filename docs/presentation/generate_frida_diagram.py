#!/usr/bin/env python3
"""
Generate Frida instrumentation diagram for presentation
Shows how Frida hooks into the Oura app to capture auth data
With phases matching the actual Frida script structure
"""

import drawpyo
from drawpyo.diagram import Object, Edge

# Colors matching our existing diagrams
BLUE = ('#dae8fc', '#6c8ebf')
GREEN = ('#d5e8d4', '#82b366')
YELLOW = ('#fff2cc', '#d6b656')
RED = ('#f8cecc', '#b85450')
PURPLE = ('#e1d5e7', '#9673a6')
ORANGE = ('#ffe6cc', '#d79b00')
GRAY = ('#f5f5f5', '#666666')


def create_frida_diagram():
    """Create a visual showing Frida hooking into auth flow with phases"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "frida_instrumentation.drawio"
    page = drawpyo.Page(file=file, name="Frida Hooks")

    # Styles
    TITLE_STYLE = "text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=18;fontFamily=Helvetica;fontColor=#222222;"
    PHASE_STYLE = "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=12;fontFamily=Helvetica;fontColor=#666666;"
    CONTAINER_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=12;fontFamily=Helvetica;fontColor=#222222;dashed=0;arcSize=6;verticalAlign=top;spacingTop=8;"
    BOX_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=12;fontFamily=Helvetica;fontColor=#222222;shadow=1;arcSize=10;"
    HOOK_STYLE = "ellipse;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=20;fontFamily=Helvetica;fontColor=white;shadow=1;"
    CAPTURE_STYLE = "shape=note;whiteSpace=wrap;html=1;strokeWidth=1;fontSize=10;fontFamily=Courier New;fontColor=#333333;align=left;spacingLeft=6;spacingTop=4;backgroundOutline=1;"
    ARROW_STYLE = "edgeStyle=orthogonalEdgeStyle;orthogonalLoop=1;rounded=1;strokeWidth=2;strokeColor=#e85d04;dashed=1;dashPattern=3 3;"
    FLOW_ARROW = "strokeWidth=2;strokeColor=#666666;"
    TRIGGER_STYLE = "rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=11;fontFamily=Helvetica;fontColor=white;fontStyle=1;shadow=1;arcSize=15;"

    # === TITLE ===
    title = Object(page=page, value="<b>🔍 Frida Runtime Instrumentation</b>", width=400, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (180, 5)

    # === TRIGGER: When does this happen? ===
    trigger = Object(
        page=page,
        value="📱 App connects to 💍 Ring",
        width=180, height=35
    )
    trigger.apply_style_string(TRIGGER_STYLE + "fillColor=#6c8ebf;strokeColor=#3a5a8c;")
    trigger.position = (30, 50)

    trigger_arrow = Object(page=page, value="triggers auth →", width=100, height=20)
    trigger_arrow.apply_style_string("text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=10;fontColor=#666666;fontStyle=2;")
    trigger_arrow.position = (215, 57)

    # === LEFT COLUMN: App Methods (What we hook) ===

    app_label = Object(page=page, value="<b>📱 Oura App (Java)</b>", width=180, height=25)
    app_label.apply_style_string(PHASE_STYLE + "align=center;fontColor=#333333;fontSize=13;")
    app_label.position = (40, 95)

    # Phase boxes with methods
    phases = [
        ("STEP 1", "GetAuthNonce", "Request challenge", BLUE, 125),
        ("STEP 2", "AES.doFinal()", "Encrypt with key", YELLOW, 210),
        ("STEP 3", "Authenticate", "Send to ring", PURPLE, 295),
    ]

    method_objects = []
    for phase, method, desc, color, y in phases:
        # Phase label
        phase_label = Object(page=page, value=f"<b>{phase}</b>", width=55, height=20)
        phase_label.apply_style_string(PHASE_STYLE)
        phase_label.position = (30, y + 12)

        # Method box
        method_obj = Object(
            page=page,
            value=f"<b>{method}</b><br/><font style='font-size:10px;color:#666;'>{desc}</font>",
            width=130, height=50
        )
        method_obj.apply_style_string(BOX_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        method_obj.position = (90, y)
        method_objects.append(method_obj)

    # Flow arrows between methods
    for i in range(len(method_objects) - 1):
        edge = Edge(page=page, source=method_objects[i], target=method_objects[i + 1])
        edge.apply_style_string(FLOW_ARROW)

    # === CENTER: Hook symbols ===
    hook_ys = [137, 222, 307]
    hooks = []
    for y in hook_ys:
        hook = Object(page=page, value="🎣", width=32, height=32)
        hook.apply_style_string(HOOK_STYLE + "fillColor=#e85d04;strokeColor=#bf4a00;")
        hook.position = (235, y)
        hooks.append(hook)

    # === RIGHT COLUMN: Captured Data ===

    capture_label = Object(page=page, value="<b>🔍 Frida Captures</b>", width=180, height=25)
    capture_label.apply_style_string(PHASE_STYLE + "align=center;fontColor=#2e7d32;fontSize=13;")
    capture_label.position = (320, 95)

    captures = [
        ("📋 <b>Nonce</b>", "16 random bytes\nfrom ring challenge", GREEN, 125),
        ("🔑 <b>Key + Cipher</b>", "Auth key from DB\n+ encrypted output", ORANGE, 210),
        ("✅ <b>Result</b>", "SUCCESS (0x00)\nor FAIL status", GREEN, 295),
    ]

    capture_objects = []
    for title_text, data, color, y in captures:
        cap = Object(
            page=page,
            value=f"{title_text}<br/><font style='font-size:9px;'>{data}</font>",
            width=140, height=55
        )
        cap.apply_style_string(CAPTURE_STYLE + f"fillColor={color[0]};strokeColor={color[1]};")
        cap.position = (295, y)
        capture_objects.append(cap)

    # Dashed arrows from hooks to captures
    for hook, capture in zip(hooks, capture_objects):
        edge = Edge(page=page, source=hook, target=capture)
        edge.apply_style_string(ARROW_STYLE)

    # === BOTTOM: Database hook note ===
    db_note = Object(
        page=page,
        value="🗄️ <b>Also hooked:</b> DbRingConfiguration.getAuthKey() → captures stored 16-byte shared secret",
        width=420, height=30
    )
    db_note.apply_style_string("rounded=1;whiteSpace=wrap;html=1;strokeWidth=1;fontSize=11;fontFamily=Helvetica;fontColor=#555555;fillColor=#fff8e1;strokeColor=#ffb300;align=center;arcSize=10;")
    db_note.position = (45, 365)

    # === Console output example ===
    console = Object(
        page=page,
        value="<b>Console Output:</b><br/><font style='font-family:monospace;font-size:9px;'>STEP 1b: Nonce: a1 b2 c3 d4 ...<br/>STEP 2b: Encrypted: 7f 8e 9d ...<br/>STEP 3b: ✅ AUTH SUCCESS!</font>",
        width=200, height=65
    )
    console.apply_style_string("rounded=1;whiteSpace=wrap;html=1;strokeWidth=1;fontSize=10;fontFamily=Helvetica;fontColor=#333333;fillColor=#263238;strokeColor=#455a64;align=left;spacingLeft=8;fontColor=#e0e0e0;arcSize=8;")
    console.position = (470, 130)

    # Arrow from captures to console
    console_label = Object(page=page, value="real-time<br/>output →", width=50, height=35)
    console_label.apply_style_string("text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=9;fontColor=#888888;fontStyle=2;")
    console_label.position = (438, 165)

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_frida_diagram()
    print("\n📂 Frida diagram ready!")
