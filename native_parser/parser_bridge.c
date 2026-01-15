/*
 * parser_bridge.c - Bridge to call Oura's libringeventparser.so
 *
 * Uses the C++ RingEventParser class:
 *   RingEventParser::RingEventParser()  - constructor
 *   RingEventParser::parse_events(data, len, &events_received) - parse
 *   RingEventParser::create_protobuf(RingData*) - get protobuf
 *
 * Uses rep::RingData protobuf message:
 *   RingData::RingData(Arena*, bool) - constructor
 *   RingData::ByteSizeLong() - get size
 *   MessageLite::SerializeToArray(void*, int) - serialize
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

// RingEventParser class methods (first param is 'this' pointer)
typedef void (*parser_ctor_t)(void* this_ptr);
typedef void* (*parse_events_t)(void* this_ptr, const uint8_t* data, uint32_t len, uint32_t* events_received);
typedef void (*create_protobuf_t)(void* this_ptr, void* ring_data);
typedef void (*parser_dtor_t)(void* this_ptr);
typedef void (*set_time_mapping_t)(void* this_ptr, uint32_t ring_time, uint64_t unix_time);
typedef void* (*get_protobuf_t)(void* this_ptr);
typedef size_t (*get_protobuf_size_t)(void* this_ptr);
typedef void (*process_queued_t)(void* this_ptr);
typedef void* (*get_session_t)(void* this_ptr);
typedef void (*set_session_t)(void* this_ptr, void* session);
typedef void (*enable_mode_t)(void* this_ptr);
typedef void (*set_output_modes_t)(void* this_ptr, uint32_t modes);

// C-style API (rep_* functions)
typedef void* (*rep_parseEvents_t)(const uint8_t* data, uint32_t len, uint32_t* out_len);
typedef void* (*rep_create_session_t)(void);
typedef void* (*rep_process_chunk_t)(void* session, const uint8_t* data, uint32_t len);
typedef void* (*rep_end_session_t)(void* session);
typedef void (*rep_free_protobuf_t)(void* protobuf);

// rep::RingData protobuf message methods
typedef void (*ringdata_ctor_t)(void* this_ptr, void* arena, int flag);
typedef size_t (*ringdata_bytesize_t)(void* this_ptr);
typedef void (*ringdata_clear_t)(void* this_ptr);

// Protobuf serialization (from libprotobuf-lite, works on any MessageLite)
typedef int (*SerializeToArray_t)(void* msg, void* data, int size);

static int hex_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char* hex, uint8_t* out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = 0;
    for (size_t i = 0; i + 1 < hex_len && byte_len < max_len; i += 2) {
        int hi = hex_to_nibble(hex[i]);
        int lo = hex_to_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) { i--; continue; }
        out[byte_len++] = (hi << 4) | lo;
    }
    return byte_len;
}

// Structure to hold individual events
typedef struct {
    uint8_t* data;
    size_t len;
} Event;

typedef struct {
    Event* events;
    size_t count;
    size_t total_bytes;
} EventList;

static EventList* read_events_file(const char* filepath) {
    FILE* f = fopen(filepath, "r");
    if (!f) { fprintf(stderr, "Failed to open %s\n", filepath); return NULL; }

    EventList* list = calloc(1, sizeof(EventList));
    if (!list) { fclose(f); return NULL; }

    size_t capacity = 10000;
    list->events = malloc(capacity * sizeof(Event));
    if (!list->events) { free(list); fclose(f); return NULL; }

    char line[2048];
    uint8_t temp_buf[1024];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char* hex_data = NULL;
        int pipe_count = 0;
        for (char* p = line; *p; p++) {
            if (*p == '|') { pipe_count++; if (pipe_count == 3) { hex_data = p + 1; break; } }
        }
        if (!hex_data) continue;
        char* nl = strchr(hex_data, '\n'); if (nl) *nl = '\0';

        int bytes_read = hex_to_bytes(hex_data, temp_buf, sizeof(temp_buf));
        if (bytes_read > 0) {
            if (list->count >= capacity) {
                capacity *= 2;
                list->events = realloc(list->events, capacity * sizeof(Event));
            }
            list->events[list->count].data = malloc(bytes_read);
            memcpy(list->events[list->count].data, temp_buf, bytes_read);
            list->events[list->count].len = bytes_read;
            list->total_bytes += bytes_read;
            list->count++;
        }
    }
    fclose(f);
    fprintf(stderr, "Read %zu events, %zu bytes total\n", list->count, list->total_bytes);
    return list;
}

static void free_event_list(EventList* list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->events[i].data);
    }
    free(list->events);
    free(list);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hex_events_file> [ring_time utc_millis]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Parse ring events and output protobuf to stdout.\n");
        fprintf(stderr, "Optional sync point args for correct timestamps.\n");
        return 1;
    }

    // Load libraries
    fprintf(stderr, "Loading libraries...\n");
    void* proto_handle = dlopen("libprotobuf-lite.so", RTLD_NOW | RTLD_GLOBAL);
    if (!proto_handle) { fprintf(stderr, "protobuf: %s\n", dlerror()); return 1; }

    void* parser_handle = dlopen("libringeventparser.so", RTLD_NOW);
    if (!parser_handle) { fprintf(stderr, "parser: %s\n", dlerror()); return 1; }
    fprintf(stderr, "  Libraries loaded OK\n");

    // ========================================
    // Get RingEventParser methods
    // ========================================
    parser_ctor_t parser_ctor = (parser_ctor_t)dlsym(parser_handle, "_ZN15RingEventParserC1Ev");
    parse_events_t parse_events = (parse_events_t)dlsym(parser_handle, "_ZN15RingEventParser12parse_eventsEPKhjPj");
    create_protobuf_t create_pb = (create_protobuf_t)dlsym(parser_handle, "_ZN15RingEventParser15create_protobufEPN3rep8RingDataE");
    parser_dtor_t parser_dtor = (parser_dtor_t)dlsym(parser_handle, "_ZN15RingEventParserD1Ev");
    set_time_mapping_t set_time_mapping = (set_time_mapping_t)dlsym(parser_handle, "_ZN15RingEventParser24set_initial_time_mappingEjm");
    get_protobuf_t get_protobuf = (get_protobuf_t)dlsym(parser_handle, "_ZNK15RingEventParser12get_protobufEv");
    get_protobuf_size_t get_protobuf_size = (get_protobuf_size_t)dlsym(parser_handle, "_ZNK15RingEventParser17get_protobuf_sizeEv");
    process_queued_t process_queued = (process_queued_t)dlsym(parser_handle, "_ZN15RingEventParser21process_queued_eventsEv");
    get_session_t get_session = (get_session_t)dlsym(parser_handle, "_ZN15RingEventParser7sessionEv");
    set_session_t set_session = (set_session_t)dlsym(parser_handle, "_ZN15RingEventParser11set_sessionEP7Session");

    // Session class methods
    typedef void (*session_ctor_t)(void* this_ptr, void* options);
    session_ctor_t session_ctor = (session_ctor_t)dlsym(parser_handle, "_ZN7SessionC1ERK12s_RepOptions");
    typedef void (*session_end_t)(void* this_ptr);
    session_end_t session_end = (session_end_t)dlsym(parser_handle, "_ZN7Session11end_sessionEv");
    typedef void* (*session_protobuf_t)(void* this_ptr);
    session_protobuf_t session_protobuf = (session_protobuf_t)dlsym(parser_handle, "_ZN7Session8protobufEv");
    fprintf(stderr, "  Session::end_session: %p\n", (void*)session_end);
    fprintf(stderr, "  Session::protobuf: %p\n", (void*)session_protobuf);

    // Output mode functions
    enable_mode_t enable_ring_events = (enable_mode_t)dlsym(parser_handle, "_ZN15RingEventParser30enable_ring_events_output_modeEv");
    set_output_modes_t set_output_modes = (set_output_modes_t)dlsym(parser_handle, "_ZN15RingEventParser16set_output_modesEj");
    fprintf(stderr, "  enable_ring_events_output_mode: %p\n", (void*)enable_ring_events);
    fprintf(stderr, "  set_output_modes: %p\n", (void*)set_output_modes);

    fprintf(stderr, "  RingEventParser::ctor: %p\n", (void*)parser_ctor);
    fprintf(stderr, "  RingEventParser::parse_events: %p\n", (void*)parse_events);
    fprintf(stderr, "  RingEventParser::create_protobuf: %p\n", (void*)create_pb);
    fprintf(stderr, "  RingEventParser::set_initial_time_mapping: %p\n", (void*)set_time_mapping);
    fprintf(stderr, "  RingEventParser::get_protobuf: %p\n", (void*)get_protobuf);
    fprintf(stderr, "  RingEventParser::get_protobuf_size: %p\n", (void*)get_protobuf_size);
    fprintf(stderr, "  RingEventParser::get_session: %p\n", (void*)get_session);
    fprintf(stderr, "  RingEventParser::set_session: %p\n", (void*)set_session);
    fprintf(stderr, "  Session::Session: %p\n", (void*)session_ctor);

    // ========================================
    // Get C-style rep_* functions
    // ========================================
    rep_parseEvents_t rep_parse = (rep_parseEvents_t)dlsym(parser_handle, "rep_parseEvents");
    rep_create_session_t rep_create = (rep_create_session_t)dlsym(parser_handle, "rep_create_session");
    rep_process_chunk_t rep_chunk = (rep_process_chunk_t)dlsym(parser_handle, "rep_process_chunk");
    rep_end_session_t rep_end = (rep_end_session_t)dlsym(parser_handle, "rep_end_session");
    rep_free_protobuf_t rep_free_pb = (rep_free_protobuf_t)dlsym(parser_handle, "rep_free_protobuf");

    fprintf(stderr, "  rep_parseEvents: %p\n", (void*)rep_parse);
    fprintf(stderr, "  rep_create_session: %p\n", (void*)rep_create);
    fprintf(stderr, "  rep_process_chunk: %p\n", (void*)rep_chunk);
    fprintf(stderr, "  rep_end_session: %p\n", (void*)rep_end);

    // ========================================
    // Get rep::RingData methods (from parser library!)
    // ========================================
    ringdata_ctor_t ringdata_ctor = (ringdata_ctor_t)dlsym(parser_handle, "_ZN3rep8RingDataC1EPN6google8protobuf5ArenaEb");
    ringdata_bytesize_t ringdata_bytesize = (ringdata_bytesize_t)dlsym(parser_handle, "_ZNK3rep8RingData12ByteSizeLongEv");
    ringdata_clear_t ringdata_clear = (ringdata_clear_t)dlsym(parser_handle, "_ZN3rep8RingData5ClearEv");

    fprintf(stderr, "  RingData::ctor: %p\n", (void*)ringdata_ctor);
    fprintf(stderr, "  RingData::ByteSizeLong: %p\n", (void*)ringdata_bytesize);
    fprintf(stderr, "  RingData::Clear: %p\n", (void*)ringdata_clear);

    // ========================================
    // Get protobuf serialization (from protobuf-lite)
    // ========================================
    SerializeToArray_t serialize = (SerializeToArray_t)dlsym(proto_handle,
        "_ZNK6google8protobuf11MessageLite16SerializeToArrayEPvi");
    fprintf(stderr, "  SerializeToArray: %p\n", (void*)serialize);

    if (!parser_ctor || !parse_events || !create_pb) {
        fprintf(stderr, "ERROR: Required parser functions not found\n");
        return 1;
    }
    if (!ringdata_ctor || !ringdata_bytesize) {
        fprintf(stderr, "ERROR: Required RingData functions not found\n");
        return 1;
    }
    if (!serialize) {
        fprintf(stderr, "ERROR: SerializeToArray not found\n");
        return 1;
    }

    // ========================================
    // Read events file
    // ========================================
    EventList* event_list = read_events_file(argv[1]);
    if (!event_list) return 1;

    // ========================================
    // TRY #1: Simple rep_parseEvents C function
    // SKIP: Crashes with wrong signature, needs more reverse engineering
    // ========================================
    (void)rep_parse;  // suppress unused warning

    // ========================================
    // TRY #2: Session-based API
    // SKIP: Also crashes - C functions likely need JNI wrapper setup
    // ========================================
    (void)rep_create; (void)rep_chunk; (void)rep_end; (void)rep_free_pb;

    // ========================================
    // TRY #3: C++ RingEventParser class
    // ========================================
    fprintf(stderr, "\n=== Trying C++ RingEventParser class ===\n");

    // ========================================
    // Create RingEventParser instance
    // ========================================
    fprintf(stderr, "\n=== Creating RingEventParser ===\n");
    void* parser = calloc(1, 8192);  // Generous allocation
    if (!parser) { fprintf(stderr, "Failed to alloc parser\n"); return 1; }

    parser_ctor(parser);
    fprintf(stderr, "  Parser constructed\n");

    // ========================================
    // Enable output modes
    // ========================================
    if (enable_ring_events) {
        fprintf(stderr, "\n=== Enabling ring_events output mode ===\n");
        enable_ring_events(parser);
    }
    if (set_output_modes) {
        fprintf(stderr, "  Setting output_modes to 0xFFFFFFFF (all)\n");
        set_output_modes(parser, 0xFFFFFFFF);  // Try enabling all modes
    }

    // ========================================
    // Create and set Session (required for parsing!)
    // ========================================
    fprintf(stderr, "\n=== Creating Session ===\n");
    void* session = NULL;

    if (session_ctor && set_session) {
        // Allocate space for Session (guess 4KB) and s_RepOptions (guess 256 bytes)
        session = calloc(1, 8192);  // Session might be large
        void* options = malloc(256);
        memset(options, 0xFF, 256);  // Try ALL bits set - enable everything!

        if (session && options) {
            fprintf(stderr, "  Calling Session constructor with zeroed options...\n");
            session_ctor(session, options);
            fprintf(stderr, "  Session constructed at: %p\n", session);

            fprintf(stderr, "  Setting session on parser...\n");
            set_session(parser, session);
            fprintf(stderr, "  Session set!\n");
        }
        free(options);  // options should be copied
    } else {
        fprintf(stderr, "  WARNING: Cannot create Session (missing functions)\n");
    }

    // ========================================
    // Set time mapping using actual sync point
    // With single parse_events() call, this should be fast
    // ========================================
    if (set_time_mapping) {
        fprintf(stderr, "\n=== Setting initial time mapping ===\n");
        uint32_t ring_time = 0;
        uint64_t utc_millis = 1768120998ULL * 1000;  // fallback

        if (argc >= 4) {
            ring_time = (uint32_t)strtoul(argv[2], NULL, 10);
            utc_millis = strtoull(argv[3], NULL, 10);
            fprintf(stderr, "  Using sync point: ring_time=%u, utc_millis=%llu\n",
                    ring_time, (unsigned long long)utc_millis);
        } else {
            fprintf(stderr, "  Using fallback: ring_time=0, utc=%llu\n",
                    (unsigned long long)utc_millis);
        }
        set_time_mapping(parser, ring_time, utc_millis);
    }

    // ========================================
    // Create rep::RingData instance
    // ========================================
    fprintf(stderr, "\n=== Creating RingData protobuf ===\n");
    void* ring_data = calloc(1, 4096);  // Generous allocation for protobuf object
    if (!ring_data) { fprintf(stderr, "Failed to alloc RingData\n"); return 1; }

    // RingData(Arena* arena, bool is_message_owned)
    // Pass NULL arena, false for not message-owned
    ringdata_ctor(ring_data, NULL, 0);
    fprintf(stderr, "  RingData constructed\n");

    // ========================================
    // Concatenate all events into single buffer
    // ========================================
    fprintf(stderr, "\n=== Concatenating %zu events (%zu bytes) ===\n",
            event_list->count, event_list->total_bytes);

    uint8_t* all_data = malloc(event_list->total_bytes);
    if (!all_data) { fprintf(stderr, "Failed to alloc concatenated buffer\n"); return 1; }

    size_t offset = 0;
    for (size_t i = 0; i < event_list->count; i++) {
        memcpy(all_data + offset, event_list->events[i].data, event_list->events[i].len);
        offset += event_list->events[i].len;
    }
    fprintf(stderr, "  Concatenated %zu bytes\n", offset);

    // ========================================
    // Parse ALL events in ONE call
    // ========================================
    fprintf(stderr, "\n=== Parsing all data in SINGLE call ===\n");
    uint32_t events_received = 0;
    void* parse_result = parse_events(parser, all_data, (uint32_t)offset, &events_received);
    fprintf(stderr, "  DONE: events_received=%u, result=%p\n", events_received, parse_result);

    free(all_data);

    // ========================================
    // Process queued events
    // ========================================
    if (process_queued) {
        fprintf(stderr, "\n=== Calling process_queued_events ===\n");
        process_queued(parser);
        fprintf(stderr, "  Done\n");
    }

    // ========================================
    // Try get_protobuf() first (internal protobuf)
    // ========================================
    void* internal_pb = NULL;
    size_t internal_pb_size = 0;
    if (get_protobuf && get_protobuf_size) {
        fprintf(stderr, "\n=== Trying get_protobuf() ===\n");
        internal_pb = get_protobuf(parser);
        internal_pb_size = get_protobuf_size(parser);
        fprintf(stderr, "  Internal protobuf: %p, size: %zu\n", internal_pb, internal_pb_size);
    }

    // ========================================
    // Create protobuf from parsed data (into our RingData)
    // ========================================
    fprintf(stderr, "\n=== Calling create_protobuf ===\n");
    create_pb(parser, ring_data);
    fprintf(stderr, "  create_protobuf completed\n");

    // ========================================
    // Get size and serialize
    // ========================================
    fprintf(stderr, "\n=== Serializing RingData ===\n");
    size_t pb_size = ringdata_bytesize(ring_data);
    fprintf(stderr, "  RingData::ByteSizeLong: %zu bytes\n", pb_size);

    // Also try internal protobuf if available
    if (internal_pb && internal_pb_size > 0) {
        fprintf(stderr, "  Internal protobuf size: %zu bytes (from get_protobuf_size)\n", internal_pb_size);
    }

    if (pb_size > 0 && pb_size < 300*1024*1024) {  // Allow up to 300MB
        uint8_t* output = malloc(pb_size);
        if (!output) { fprintf(stderr, "Failed to alloc output\n"); return 1; }

        int result = serialize(ring_data, output, (int)pb_size);
        fprintf(stderr, "  SerializeToArray returned: %d\n", result);

        if (result) {
            fprintf(stderr, "  SUCCESS! Writing %zu bytes to stdout\n", pb_size);
            fwrite(output, 1, pb_size, stdout);
            fflush(stdout);
        } else {
            fprintf(stderr, "  Serialization failed!\n");
            // Dump first 64 bytes for debugging
            fprintf(stderr, "  First 64 bytes of ring_data object:\n  ");
            uint8_t* p = (uint8_t*)ring_data;
            for (int i = 0; i < 64; i++) {
                fprintf(stderr, "%02x ", p[i]);
                if ((i+1) % 16 == 0) fprintf(stderr, "\n  ");
            }
            fprintf(stderr, "\n");
        }
        free(output);
    } else if (pb_size == 0) {
        fprintf(stderr, "  WARNING: Protobuf is empty (size=0)\n");
        fprintf(stderr, "  This likely means no events were parsed.\n");

        // Dump parser internal state for debugging
        fprintf(stderr, "  Parser object first 128 bytes:\n  ");
        uint8_t* p = (uint8_t*)parser;
        for (int i = 0; i < 128; i++) {
            fprintf(stderr, "%02x ", p[i]);
            if ((i+1) % 16 == 0) fprintf(stderr, "\n  ");
        }
        fprintf(stderr, "\n");
    } else {
        fprintf(stderr, "  ERROR: Suspicious size %zu\n", pb_size);
    }

    // ========================================
    // Cleanup
    // ========================================
    if (parser_dtor) {
        fprintf(stderr, "\nCalling destructor...\n");
        parser_dtor(parser);
    }
    free(parser);
    free(ring_data);
    free_event_list(event_list);

    fprintf(stderr, "\nDone.\n");
    return (pb_size > 0) ? 0 : 1;
}
