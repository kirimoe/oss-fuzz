rule count_at_offset {
  strings:
    $a = "AAA"
  condition:
    #a >= 2 and $a at 100
}
