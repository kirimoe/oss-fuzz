# OSS-Fuzz: Continuous Fuzzing for Just YARA

This repo aims to use OSS Fuzz to fuzz test the YARA's functionality of parsing yara compiled rules

## Overview
![OSS-Fuzz process diagram](docs/images/process.png)

## Documentation
Read our [detailed documentation] to learn how to use OSS-Fuzz.

[detailed documentation]: https://google.github.io/oss-fuzz

## Steps to Run the fuzzer

##### make sure to be in OSS fuzz directory
```bash
cd ~/oss-fuzz
```
##### Build the image
```bash
sudo python3 infra/helper.py build_image yara
```
##### Build the fuzzers
```bash
sudo python3 infra/helper.py build_fuzzers yara
```
##### Run the fuzzers (It will stop after finding a single crash)
Use the -max_total_time=N option only if you want to run the fuzzer for specific amount of time
```bash
sudo python3 infra/helper.py run_fuzzer yara yara_rules_fuzzer -- -max_total_time=30
```
##### Run the fuzzer for longer duration (Continue after the crash)
```bash
sudo python3 infra/helper.py run_fuzzer yara yara_rules_fuzzer -- -fork=1 -ignore_crashes=1
```
##### Run the fuzzer for longer duration (Continue after the crash) - Multithreading
```bash
sudo python3 infra/helper.py run_fuzzer yara yara_rules_fuzzer -- -jobs=4 -workers=4 -fork=1 -ignore_crashes=1
```
##### check the coverage (Totally Optional)
```bash
sudo python3 infra/helper.py build_fuzzers --sanitizer coverage yara
```
###### visaulize coverage (Totally Optional)
Run this and click the websever link to navigate to the coverage results
```bash
sudo python3 infra/helper.py coverage --fuzz-target=yara_rules_fuzzer --corpus-dir=./build/corpus/yara/yara_rules_fuzzer yara
```
