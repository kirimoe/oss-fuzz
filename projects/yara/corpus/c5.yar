rule string_modifiers {
  strings:
    $nocase = "CaSe InSeNsItIvE" nocase
    $fullword = "full word match" fullword
    $xor_key = "encrypted" xor
    $xor_range = "range_xor" xor(0x01-0xFF)
    $base64_str = "SGVsbG8gV29ybGQh" base64
    $base64wide_str = "SABlAGwAbABvACwAIABXAG8AcgBsAGQAIQ==" base64wide
  condition:
    any of them
}
