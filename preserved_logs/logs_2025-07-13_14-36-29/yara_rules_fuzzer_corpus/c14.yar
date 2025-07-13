import "pe"

rule check_pe_section {
  condition:
    uint16(0) == 0x5A4D and pe.sections[0].name == ".text"
}
