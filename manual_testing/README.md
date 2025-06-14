This guide documents the process for manually testing YARA API functions before submitting to OSS Fuzz. The setup includes building YARA, creating a fuzz target, and running tests with custom input.

## Directory Structure

- `CMakeLists.txt`: CMake configuration for building YARA and the fuzz target.
- `fuzz_target.cc`: The source file for fuzz testing YARA APIs.
- `fuzz_target`: Compiled fuzz target binary.
- `test_example`: Directory containing example YARA rules for testing.
    - `valid_rule.yar`: Example YARA rule file.
    - `valid_rule.yarc`: Compiled YARA rule file.
- `yara`: YARA source and build files.

## Prerequisites

Install the necessary dependencies on your system:

```bash
sudo apt update

sudo apt install clang llvm pkg-config g++ automake autoconf make libtool bison flex libpcre3-dev libssl-dev
```

## Setup and Testing

### 1. Build YARA

Build YARA by running the following commands:

```bash
cd yara

./bootstrap.sh

./configure

make
```

### 2. Create and Compile YARA Rule

Compile your YARA rule into a `.yarc` file using the `yarac` compiler in the `yara` directory:

```bash
./yara/yarac test_example/valid_rule.yar test_example/valid_rule.yarc
```

### 3. Compile the Fuzz Target

To compile the `fuzz_target.cc` file, run:

```bash
cmake .

make
```

This will generate the `fuzz_target` binary.

### 4. Run the Fuzz Target

Execute the fuzz target with the compiled rule as input:

```bash
./fuzz_target < test_example/valid_rule.yarc
```

### 5. Modify Fuzz Target for API Testing

The `fuzz_target.cc` can be modified to test different YARA APIs. The current target is set up to test any API by loading and interacting with the provided YARA rule.

### Example: Fuzzing `yr_rules_load_stream`

The `fuzz_target.cc` is already configured to fuzz the `yr_rules_load_stream` function. Here's a summary of how it works:

1. The fuzz target loads the compiled rule file (`valid_rule.yarc`).
2. It calls `yr_rules_load_stream` to load the rule stream.
3. If successful, the target prints a success message.

You can modify `fuzz_target.cc` to test other YARA APIs. For example, to test the `yr_rules_scan_file` function, you could add the following code:

```cpp
// Example: Scan a file with loaded rules
int scan_result = yr_rules_scan_file(rules, "example_file.txt", 0, nullptr, nullptr, 0);
if (scan_result == ERROR_SUCCESS) {
    std::cout << "File scanned successfully!" << std::endl;
}
```