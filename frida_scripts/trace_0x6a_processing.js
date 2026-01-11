/**
 * Trace 0x6a (SLEEP_PERIOD_INFO_2) event processing in native library
 *
 * Hooks:
 * 1. EventParser::parse_api_sleep_period_info() - shows binary format parsing
 * 2. ProtobufSerializer::serialize_api_sleep_period_info() - shows protobuf assembly
 */

// Helper to format byte arrays
function hexdump(buffer, length) {
    if (!buffer || length === 0) return "<empty>";

    const bytes = [];
    for (let i = 0; i < Math.min(length, 64); i++) {
        bytes.push(buffer.add(i).readU8().toString(16).padStart(2, '0'));
    }

    if (length > 64) {
        return bytes.join(' ') + '... (' + length + ' bytes total)';
    }
    return bytes.join(' ');
}

// Helper to read C++ std::vector
function readVector(vectorPtr) {
    try {
        // std::vector layout: [begin, end, capacity]
        const begin = vectorPtr.readPointer();
        const end = vectorPtr.add(Process.pointerSize).readPointer();
        const size = end.sub(begin).toInt32();

        return {
            begin: begin,
            end: end,
            size: size,
            count: size
        };
    } catch (e) {
        return { size: -1, error: e.message };
    }
}

console.log("\n=".repeat(80));
console.log("TRACING 0x6a EVENT PROCESSING IN NATIVE LIBRARY");
console.log("=".repeat(80));

const baseAddr = Module.findBaseAddress("libringeventparser.so");
if (!baseAddr) {
    console.error("❌ libringeventparser.so not loaded yet");
} else {
    console.log("✓ libringeventparser.so base: " + baseAddr);

    // Hook 1: EventParser::parse_api_sleep_period_info(Event const&)
    const parseAddr = baseAddr.add(0x281f08);
    console.log("✓ Hooking parse_api_sleep_period_info at: " + parseAddr);

    Interceptor.attach(parseAddr, {
        onEnter: function(args) {
            // args[0] = this pointer (EventParser*)
            // args[1] = const Event& (reference to Event object)

            this.eventPtr = args[1];

            try {
                // Event structure (simplified):
                // - tag (uint8_t at offset 0 or in struct)
                // - data/payload (vector<uint8_t>)

                // Try to read the event data
                // The Event class likely has the data as a std::vector
                // We need to find the offset - try common layouts

                const tag = this.eventPtr.readU8();
                console.log("\n" + "─".repeat(80));
                console.log("📥 PARSE: parse_api_sleep_period_info() CALLED");
                console.log("  Event tag: 0x" + tag.toString(16) + " (" + tag + ")");

                // Try to read vector at various offsets
                for (let offset of [8, 16, 24]) {
                    try {
                        const vecInfo = readVector(this.eventPtr.add(offset));
                        if (vecInfo.size > 0 && vecInfo.size < 1000) {
                            console.log("  Event data (offset " + offset + ", " + vecInfo.size + " bytes):");
                            console.log("    " + hexdump(vecInfo.begin, vecInfo.size));

                            // If this is 14 bytes, it's likely the 0x6a payload
                            if (vecInfo.size === 14) {
                                console.log("  ✓ Found 14-byte 0x6a payload!");
                                this.payloadPtr = vecInfo.begin;
                                this.payloadSize = vecInfo.size;

                                // Parse the structure based on our understanding
                                const timestampOffset = vecInfo.begin.readU32();
                                const heartRate = vecInfo.begin.add(4).readU8();
                                const hrTrend = vecInfo.begin.add(5).readU8();
                                const val_6_7 = vecInfo.begin.add(6).readU16();
                                const val_8_9 = vecInfo.begin.add(8).readU16();
                                const val_10_11 = vecInfo.begin.add(10).readU16();
                                const val_12_13 = vecInfo.begin.add(12).readU16();

                                console.log("  Decoded fields:");
                                console.log("    [0-3]  Timestamp offset: " + timestampOffset + " seconds");
                                console.log("    [4]    Heart rate: " + heartRate + " BPM");
                                console.log("    [5]    HR trend/quality: " + hrTrend);
                                console.log("    [6-7]  Value: " + val_6_7 + " (0x" + val_6_7.toString(16) + ")");
                                console.log("    [8-9]  Value: " + val_8_9 + " (0x" + val_8_9.toString(16) + ")");
                                console.log("    [10-11] Value: " + val_10_11 + " (0x" + val_10_11.toString(16) + ")");
                                console.log("    [12-13] Value: " + val_12_13 + " (0x" + val_12_13.toString(16) + ")");
                            }
                            break;
                        }
                    } catch (e) {
                        // Continue to next offset
                    }
                }
            } catch (e) {
                console.log("  Error reading event: " + e.message);
            }
        },

        onLeave: function(retval) {
            console.log("  ✓ Parse completed, return value: " + retval);
        }
    });

    // Hook 2: ProtobufSerializer::serialize_api_sleep_period_info(...)
    const serializeAddr = baseAddr.add(0x23bdac);
    console.log("✓ Hooking serialize_api_sleep_period_info at: " + serializeAddr);

    let sampleCount = 0;

    Interceptor.attach(serializeAddr, {
        onEnter: function(args) {
            // args[0] = this pointer (ProtobufSerializer*)
            // args[1] = variant (RingData or Event)
            // args[2] = const vector<ParsedEvent>&

            sampleCount++;

            console.log("\n" + "─".repeat(80));
            console.log("📤 SERIALIZE: serialize_api_sleep_period_info() CALLED (#" + sampleCount + ")");

            try {
                // args[2] is a reference to vector<ParsedEvent>
                const vecInfo = readVector(args[2]);
                console.log("  ParsedEvent vector:");
                console.log("    Size: " + vecInfo.size + " bytes");
                console.log("    Count: ~" + Math.floor(vecInfo.size / 100) + " events (estimate)");

                // Try to understand ParsedEvent structure
                // Each ParsedEvent likely contains the decoded fields
                console.log("  First ParsedEvent data:");
                if (vecInfo.begin && vecInfo.size > 0) {
                    console.log("    " + hexdump(vecInfo.begin, Math.min(100, vecInfo.size)));
                }
            } catch (e) {
                console.log("  Error reading ParsedEvent vector: " + e.message);
            }
        },

        onLeave: function(retval) {
            console.log("  ✓ Serialization completed");
            console.log("  Return value: " + retval);
        }
    });

    console.log("\n✓ Hooks installed! Waiting for 0x6a events...");
    console.log("  Trigger by: Click 'Get Sleep' in app");
    console.log("=".repeat(80) + "\n");
}
