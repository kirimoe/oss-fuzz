# OSS-Fuzz: Continuous Fuzzing for Open Source Software

[Fuzz testing] is a well-known technique for uncovering programming errors in
software. Many of these detectable errors, like [buffer overflow], can have
serious security implications. Google has found [thousands] of security
vulnerabilities and stability bugs by deploying [guided in-process fuzzing of
Chrome components], and we now want to share that service with the open source
community.

[Fuzz testing]: https://en.wikipedia.org/wiki/Fuzz_testing
[buffer overflow]: https://en.wikipedia.org/wiki/Buffer_overflow
[thousands]: https://issues.chromium.org/issues?q=label:Stability-LibFuzzer%20-status:Duplicate,WontFix
[guided in-process fuzzing of Chrome components]: https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html

In cooperation with the [Core Infrastructure Initiative] and the [OpenSSF],
OSS-Fuzz aims to make common open source software more secure and stable by
combining modern fuzzing techniques with scalable, distributed execution.
Projects that do not qualify for OSS-Fuzz (e.g. closed source) can run their own
instances of [ClusterFuzz] or [ClusterFuzzLite].

[Core Infrastructure Initiative]: https://www.coreinfrastructure.org/
[OpenSSF]: https://www.openssf.org/

We support the [libFuzzer], [AFL++], and [Honggfuzz] fuzzing engines in
combination with [Sanitizers], as well as [ClusterFuzz], a distributed fuzzer
execution environment and reporting tool.

[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[Honggfuzz]: https://github.com/google/honggfuzz
[Sanitizers]: https://github.com/google/sanitizers
[ClusterFuzz]: https://github.com/google/clusterfuzz
[ClusterFuzzLite]: https://google.github.io/clusterfuzzlite/

Currently, OSS-Fuzz supports C/C++, Rust, Go, Python, Java/JVM, and JavaScript code. Other languages
supported by [LLVM] may work too. OSS-Fuzz supports fuzzing x86_64 and i386
builds.

[LLVM]: https://llvm.org

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
##### If corpus directory not there make it
```bash
mkdir -p ~/oss-fuzz/build/corpus/yara/yara_rules_fuzzer
```
##### run the fuzzer
```bash
sudo python3 infra/helper.py run_fuzzer --corpus-dir=./build/corpus/yara/yara_rules_fuzzer yara yara_rules_fuzzer -- -max_total_time=30
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