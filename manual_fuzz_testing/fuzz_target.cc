#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "yara.h"

// 1. Define a struct for user_data:
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset; // To keep track of how much data has been read
} CustomStreamData;

// This is the custom stream read function
size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    CustomStreamData *stream_data = (CustomStreamData *)user_data;
    const uint8_t *buffer = stream_data->data + stream_data->offset;
    size_t bytes_to_read = size * count;
    size_t available_bytes = stream_data->size - stream_data->offset;

    if (bytes_to_read > available_bytes) {
        bytes_to_read = available_bytes;
    }

    memcpy(ptr, buffer, bytes_to_read);
    stream_data->offset += bytes_to_read; // Update the offset
    return bytes_to_read;
}

extern "C" {
    // This is the fuzz target function
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        // Ensure size is greater than zero and not null
        if (size == 0 || data == nullptr) {
            return 0;
        }

        YR_RULES *rules = nullptr;
        yr_initialize();  // Initialize YARA

        // Create a custom YR_STREAM from fuzzed input data
        YR_STREAM stream;
        // 2. Initialize our custom data with the fuzzed input details
        CustomStreamData custom_data = {data, size, 0}; 
        // 3. Pass the address of our custom data to stream.user_data
        stream.user_data = (void *)&custom_data;  
        stream.read = custom_stream_read; // Use our custom read function
        
        // Load rules from the stream
        int result = yr_rules_load_stream(&stream, &rules);

        // If the rules are successfully loaded, we can process them
        if (result == ERROR_SUCCESS && rules) {
            // The rules are valid and compiled, process them
            // For now, we're just verifying successful load
        }

        if (rules) {
            yr_rules_destroy(rules);  // Clean up the rules
        }

        yr_finalize();  // Finalize YARA
        return 0; // Return success
    }
}