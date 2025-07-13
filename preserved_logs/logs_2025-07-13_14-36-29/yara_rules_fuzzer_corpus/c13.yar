rule for_count_them {
  strings:
    $a = "patternA"
    $b = "patternB"
    $c = "patternC"
  condition:
    for 2 of them : (true)
}
