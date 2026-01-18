#!/usr/bin/env python3
"""
Generate ML Models & Sleep Score Calculation slide (Widescreen)
Shows: Model decryption + Sleep Score Pipeline with accurate library names
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
CYAN = ('#b2ebf2', '#00838f')


def create_ml_sleep_diagram():
    """Create ML & Sleep Score visualization - Widescreen layout"""
    file = drawpyo.File()
    file.file_path = "/home/witcher/projects/oura_ring_reverse/docs/presentation"
    file.file_name = "ml_sleep.drawio"
    page = drawpyo.Page(file=file, name="ML Sleep Score")
    page.page_width = 1920
    page.page_height = 1080

    # Styles
    SKETCH = "sketch=1;curveFitting=1;jiggle=2;hachureGap=4;"
    COMIC_FONT = "Architects Daughter"
    TITLE_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;fontStyle=1;fontSize=24;fontFamily={COMIC_FONT};fontColor=#222222;"
    SECTION_TITLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=13;fontFamily={COMIC_FONT};fontColor=#333;fontStyle=1;"
    LABEL_STYLE = f"text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=10;fontFamily={COMIC_FONT};fontColor=#555;"
    BOX_STYLE = f"{SKETCH}rounded=1;whiteSpace=wrap;html=1;strokeWidth=2;fontSize=11;fontFamily={COMIC_FONT};fontColor=#222222;"
    ARROW_STYLE = f"endArrow=classic;startArrow=none;strokeWidth=2;strokeColor=#666;"

    # Main Title
    title = Object(page=page, value="<b>🧠 ML Models & Sleep Score Calculation</b>", width=450, height=35)
    title.apply_style_string(TITLE_STYLE)
    title.position = (350, 10)

    # =========================================================================
    # ROW 1: Model Decryption Flow (horizontal)
    # =========================================================================
    row1_y = 70
    sec1_title = Object(page=page, value="<b>🔓 MODEL DECRYPTION</b>", width=180, height=22)
    sec1_title.apply_style_string(SECTION_TITLE + f"fillColor={RED[0]};strokeColor={RED[1]};rounded=1;")
    sec1_title.position = (30, row1_y)

    box_w, box_h = 110, 70
    box_y = row1_y + 35

    # APK
    apk = Object(page=page, value="<b>📦 APK</b><br/>28 encrypted<br/>PyTorch models", width=box_w, height=box_h)
    apk.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};")
    apk.position = (30, box_y)

    # Encrypted
    enc = Object(page=page, value="<b>🔒 Encrypted</b><br/>AES-256-GCM<br/>[IV][data][tag]", width=box_w, height=box_h)
    enc.apply_style_string(BOX_STYLE + f"fillColor={RED[0]};strokeColor={RED[1]};")
    enc.position = (170, box_y)

    # Key
    key = Object(page=page, value="<b>🔑 Key Found!</b><br/>secrets.json<br/>in APK", width=box_w, height=box_h)
    key.apply_style_string(BOX_STYLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};")
    key.position = (310, box_y)

    # Decrypted
    dec = Object(page=page, value="<b>✅ Decrypted</b><br/>TorchScript .pt<br/>torch.jit.load()", width=box_w, height=box_h)
    dec.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};")
    dec.position = (450, box_y)

    # Models list
    models = Object(page=page, value="<b>Models:</b> SleepNet, HRV, Activity, Stress, Steps, Illness...", width=320, height=22)
    models.apply_style_string(LABEL_STYLE + "fontSize=10;align=left;")
    models.position = (590, box_y + 25)

    # Arrows
    edge1 = Edge(page=page, source=apk, target=enc)
    edge1.apply_style_string(ARROW_STYLE)
    edge2 = Edge(page=page, source=enc, target=key)
    edge2.apply_style_string(ARROW_STYLE)
    edge3 = Edge(page=page, source=key, target=dec)
    edge3.apply_style_string(ARROW_STYLE)

    # =========================================================================
    # ROW 2: Sleep Score Pipeline (horizontal)
    # =========================================================================
    row2_y = 195
    sec2_title = Object(page=page, value="<b>😴 SLEEP SCORE PIPELINE</b>", width=220, height=22)
    sec2_title.apply_style_string(SECTION_TITLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};rounded=1;")
    sec2_title.position = (30, row2_y)

    pipe_y = row2_y + 35
    pipe_w, pipe_h = 130, 85

    # Step 1: Raw BLE
    p1 = Object(page=page, value="<b>💓 Raw BLE</b><br/>Events<br/><font style='font-size:9px;'>IBI, Motion, Temp</font>", width=pipe_w, height=pipe_h)
    p1.apply_style_string(BOX_STYLE + f"fillColor={BLUE[0]};strokeColor={BLUE[1]};")
    p1.position = (30, pipe_y)

    # Step 2: Parser
    p2 = Object(page=page, value="<b>📄 Parser</b><br/><font style='font-size:9px;'>libringeventparser.so</font><br/><font style='font-size:9px;'>parser_bridge.c</font>", width=pipe_w, height=pipe_h)
    p2.apply_style_string(BOX_STYLE + f"fillColor={GRAY[0]};strokeColor={GRAY[1]};")
    p2.position = (185, pipe_y)

    # Step 3: IBI Correction - COMPLEX with callback!
    p3 = Object(page=page, value="<b>🔧 IBI Correct</b><br/><font style='font-size:9px;'>libappecore.so</font><br/><font style='font-size:9px;color:#d32f2f;'><b>callback hack!</b></font>", width=pipe_w, height=pipe_h)
    p3.apply_style_string(BOX_STYLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};")
    p3.position = (340, pipe_y)

    # Step 4: SleepNet ML - the ONLY neural network!
    p4 = Object(page=page, value="<b>🧠 SleepNet</b><br/><font style='font-size:9px;'>PyTorch .pt</font><br/><font style='font-size:9px;color:#7b1fa2;'><b>neural network!</b></font>", width=pipe_w, height=pipe_h)
    p4.apply_style_string(BOX_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};")
    p4.position = (495, pipe_y)

    # Step 5: Aggregation
    p5 = Object(page=page, value="<b>📊 Aggregate</b><br/><font style='font-size:9px;'>Stage minutes</font><br/><font style='font-size:9px;'>Python</font>", width=pipe_w, height=pipe_h)
    p5.apply_style_string(BOX_STYLE + f"fillColor={CYAN[0]};strokeColor={CYAN[1]};")
    p5.position = (650, pipe_y)

    # Step 6: Score Calc - NOT ML, just weighted formula
    p6 = Object(page=page, value="<b>📐 Score Calc</b><br/><font style='font-size:9px;'>libappecore.so</font><br/><font style='font-size:9px;color:#388e3c;'><b>formula, not ML</b></font>", width=pipe_w, height=pipe_h)
    p6.apply_style_string(BOX_STYLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};")
    p6.position = (805, pipe_y)

    # Final Score - shows full output
    score = Object(
        page=page,
        value="<b>📊 Output</b><br/>"
              "<font style='font-size:9px;'>Score: 85<br/>"
              "6 contributors<br/>"
              "Quality flag</font>",
        width=90, height=pipe_h
    )
    score.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=11;")
    score.position = (960, pipe_y)

    # Pipeline arrows
    pipes = [p1, p2, p3, p4, p5, p6, score]
    for i in range(len(pipes) - 1):
        edge = Edge(page=page, source=pipes[i], target=pipes[i + 1])
        edge.apply_style_string(ARROW_STYLE)

    # SleepNet output example box
    # SleepNet output example box - human readable
    sleepnet_out = Object(
        page=page,
        value="<b>SleepNet classifies every 30 seconds:</b><br/>"
              "<font style='font-size:9px;'>"
              "11:00pm → <font color='#2196f3'><b>Light</b></font> (65% sure)<br/>"
              "11:30pm → <font color='#3f51b5'><b>Deep</b></font> (71% sure)<br/>"
              "1:00am  → <font color='#9c27b0'><b>REM</b></font> (58% sure)<br/>"
              "6:30am  → <font color='#f44336'><b>Awake</b></font> (82% sure)"
              "</font>",
        width=220, height=80
    )
    sleepnet_out.apply_style_string(BOX_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};fontSize=10;align=left;spacingLeft=8;")
    sleepnet_out.position = (460, pipe_y + pipe_h + 25)

    # Mini hypnogram visualization with labels
    hypno_label = Object(page=page, value="<b>Night timeline:</b>", width=100, height=16)
    hypno_label.apply_style_string(LABEL_STYLE + "fontSize=9;align=left;")
    hypno_label.position = (700, pipe_y + pipe_h + 28)

    # Awake level
    h_awake = Object(page=page, value="<font color='#fff' style='font-size:7px;'>Awake</font>", width=90, height=12)
    h_awake.apply_style_string(f"rounded=0;fillColor=#f44336;strokeColor=none;")
    h_awake.position = (700, pipe_y + pipe_h + 46)

    # Light level
    h_light = Object(page=page, value="<font color='#fff' style='font-size:7px;'>Light</font>", width=90, height=14)
    h_light.apply_style_string(f"rounded=0;fillColor=#2196f3;strokeColor=none;")
    h_light.position = (700, pipe_y + pipe_h + 60)

    # Deep level
    h_deep = Object(page=page, value="<font color='#fff' style='font-size:7px;'>Deep</font>", width=90, height=16)
    h_deep.apply_style_string(f"rounded=0;fillColor=#3f51b5;strokeColor=none;")
    h_deep.position = (700, pipe_y + pipe_h + 76)

    # REM level
    h_rem = Object(page=page, value="<font color='#fff' style='font-size:7px;'>REM</font>", width=90, height=12)
    h_rem.apply_style_string(f"rounded=0;fillColor=#9c27b0;strokeColor=none;")
    h_rem.position = (700, pipe_y + pipe_h + 94)

    # Labels under pipeline
    labels = [
        (30, "BLE Events"),
        (185, "→ Protobuf"),
        (340, "ibi_correction_bridge"),
        (495, "torch.jit.load()"),
        (650, "Python"),
        (805, "sleep_score_minutes"),
    ]
    for x, txt in labels:
        lbl = Object(page=page, value=txt, width=pipe_w, height=18)
        lbl.apply_style_string(LABEL_STYLE + "fontSize=8;fontColor=#888;")
        lbl.position = (x, pipe_y + pipe_h + 5)

    # =========================================================================
    # ROW 3: Key Insights (horizontal boxes)
    # =========================================================================
    row3_y = 380
    sec3_title = Object(page=page, value="<b>💡 KEY INSIGHTS</b>", width=140, height=22)
    sec3_title.apply_style_string(SECTION_TITLE + f"fillColor={YELLOW[0]};strokeColor={YELLOW[1]};rounded=1;")
    sec3_title.position = (30, row3_y)

    insight_y = row3_y + 35
    insight_w, insight_h = 180, 75

    i1 = Object(page=page, value="<b>🎯 REM is ML-only</b><br/>Raw protobuf has no REM<br/>SleepNet detects it", width=insight_w, height=insight_h)
    i1.apply_style_string(BOX_STYLE + f"fillColor={PURPLE[0]};strokeColor={PURPLE[1]};fontSize=10;")
    i1.position = (30, insight_y)

    i2 = Object(page=page, value="<b>🔧 Callback Hack</b><br/>alloc_state(ctx, callback)<br/>Register OUR function!", width=insight_w, height=insight_h)
    i2.apply_style_string(BOX_STYLE + f"fillColor={ORANGE[0]};strokeColor={ORANGE[1]};fontSize=10;")
    i2.position = (230, insight_y)

    i3 = Object(page=page, value="<b>🖥️ QEMU ARM64</b><br/>qemu-aarch64 -L<br/>Android linker64", width=insight_w, height=insight_h)
    i3.apply_style_string(BOX_STYLE + f"fillColor={BLUE[0]};strokeColor={BLUE[1]};fontSize=10;")
    i3.position = (430, insight_y)

    i4 = Object(page=page, value="<b>🔑 Keys in APK</b><br/>secrets.json<br/>AES-256 base64", width=insight_w, height=insight_h)
    i4.apply_style_string(BOX_STYLE + f"fillColor={RED[0]};strokeColor={RED[1]};fontSize=10;")
    i4.position = (630, insight_y)

    i5 = Object(page=page, value="<b>📈 Score Output</b><br/>sleepScore: 85<br/>+ 6 contributors", width=insight_w, height=insight_h)
    i5.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=10;")
    i5.position = (830, insight_y)

    # Score output detail box - human readable
    score_detail = Object(
        page=page,
        value="<b>Sleep Score: 85/100</b><br/>"
              "<font style='font-size:9px;'>"
              "├ Total Sleep: 90 <font color='#666'>(7h 12m)</font><br/>"
              "├ Deep Sleep: 88 <font color='#666'>(1h 24m)</font><br/>"
              "├ REM Sleep: 82 <font color='#666'>(1h 45m)</font><br/>"
              "├ Efficiency: 85 <font color='#666'>(88%)</font><br/>"
              "├ Latency: 95 <font color='#666'>(&lt;10min)</font><br/>"
              "└ Disturbances: 78 <font color='#666'>(2x)</font>"
              "</font>",
        width=180, height=110
    )
    score_detail.apply_style_string(BOX_STYLE + f"fillColor={GREEN[0]};strokeColor={GREEN[1]};fontSize=10;align=left;spacingLeft=8;")
    score_detail.position = (820, pipe_y + pipe_h + 15)

    file.write()
    print(f"✅ Created {file.file_name}")


if __name__ == "__main__":
    create_ml_sleep_diagram()
    print("\n📂 ML Sleep Score diagram ready!")
