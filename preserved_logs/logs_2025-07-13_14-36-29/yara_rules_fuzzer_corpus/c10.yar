rule integer_reads {
  condition:
    uint8(0) == 0x4D and
    uint16(1) == 0x5A90 and
    uint32(2) == 0x00000000 and
    int8(0) == 77 and
    int16(1) == 23184 and
    int32(2) == 0 and
    uint16be(0) == 0x4D5A and
    uint32be(0) == 0x4D5A0000
}
