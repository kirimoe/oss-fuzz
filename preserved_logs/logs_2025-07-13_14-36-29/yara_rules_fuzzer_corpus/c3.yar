rule no_strings_present {
  condition:
    uint32(0) == 0xDEADBEEF
}
