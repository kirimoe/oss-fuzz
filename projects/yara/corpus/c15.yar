import "elf"

rule check_elf_header {
  condition:
    uint32(0) == 0x464c457f and elf.type == elf.ET_EXEC
}
