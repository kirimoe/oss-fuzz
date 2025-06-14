# Manual YARA Rule Stream Testing

This project demonstrates **manual testing of YARA compiled rules** loaded from a custom input stream in C++.

---

## Overview

The code in this directory implements a simple test harness (`fuzz_test_code.cc`) that reads a compiled YARA rules file (`.yarc`) as a stream, loads it using `yr_rules_load_stream()`, and reports success or failure.

This setup allows you to manually test how YARA handles valid and invalid compiled rule data.

---

## Directory Structure

- `fuzz_test_code.cc` — C++ test program that reads input from `stdin` and loads YARA rules via stream.
- `test_rule.yar` — Sample YARA source rule.
- `test_rule.yarc` — Compiled version of `test_rule.yar`.
- `test_rule_invalid.yarc` — Manually corrupted `.yarc` file used for testing error handling.

---

## Usage Instructions

### 1. Write or modify your test code

- Place your C++ code in `fuzz_test_code.cc`.
- Ensure the program reads binary data from standard input (`stdin`).
- The code should initialize YARA, load the rules from the input stream, and finalize YARA.

### 2. Build the test program

Run the following commands in this directory:

```bash
cmake .
make
```

This will produce an executable named fuzz_test_code.

### 3. Prepare a valid YARA rule and compile it

Write a YARA rule in test_rule.yar, for example:

```yara
rule ExampleRule {
    strings:
        $a = "test_string"
    condition:
        $a
}
```

Compile it to a .yarc file using the YARA compiler:

```bash
../manual_fuzz_testing/yara/yarac test_rule.yar test_rule.yarc
```

### 4. Run the test program with the compiled rule

Pass the compiled .yarc file to your program via standard input:

```bash
./fuzz_test_code < test_rule.yarc
```
Output: Rules loaded successfully

### 5. Test with an invalid rule

You can create an invalid compiled rule by editing test_rule.yarc with a hex editor (hexedit or similar), corrupting some bytes, and saving as test_rule_invalid.yarc.

Run the test program with the corrupted file:

```bash
./fuzz_test_code < test_rule_invalid.yarc
```
Output: yr_rules_load_stream failed

The program may crash depending on the extent of corruption.

### Screenshot

![alt text](<Output_Images/Screenshot from 2025-06-14 18-39-46.png>)
![alt text](<Output_Images/Screenshot from 2025-06-14 18-41-10.png>)
![alt text](<Output_Images/Screenshot from 2025-06-14 18-41-52.png>)