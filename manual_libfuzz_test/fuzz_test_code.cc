#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream> // For file operations
#include <vector>  // For dynamic array
#include "yara.h"

// Define the structure for handling custom stream data
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} CustomStreamData;

// Define the custom read function to handle the input stream
size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    CustomStreamData *s = (CustomStreamData *)user_data;
    size_t want = size * count;
    size_t available = s->size - s->offset;
    if (want > available) want = available;
    memcpy(ptr, s->data + s->offset, want);
    s->offset += want;
    return want / size;
}

// Original fuzzer test function (renamed for clarity in main)
int test_yara_input(const uint8_t *data, size_t size) {
    // Initialize YARA
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "YARA initialization failed\n");
        return 0; // Failure to initialize YARA
    }

    // Debugging: Print input size
    printf("Input size: %zu bytes\n", size);

    // Set up YARA rule stream
    CustomStreamData s = { data, size, 0 };
    YR_STREAM ys = { .user_data = &s, .read = custom_stream_read };

    YR_RULES *rules = NULL;

    // Load YARA rules from the stream of input data
    if (yr_rules_load_stream(&ys, &rules) == ERROR_SUCCESS) {
        printf("YARA rules loaded successfully.\n");

        // YARA rules loaded successfully, perform additional checks here
        yr_rules_destroy(rules); // Cleanup
    } else {
        fprintf(stderr, "Failed to load YARA rules\n");
    }

    // Finalize YARA
    yr_finalize();
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_yara_rules_file>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(file_size);
    if (!file.read((char*)buffer.data(), file_size)) {
        fprintf(stderr, "Error: Could not read file %s\n", filename);
        return 1;
    }

    printf("Reading %zu bytes from file: %s\n", buffer.size(), filename);

    // Call the testing function with the file content
    return test_yara_input(buffer.data(), buffer.size());
}