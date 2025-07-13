rule file_props {
  condition:
    filesize > 1MB and entrypoint == 0x401000
}
