rule boolean_logic {
  strings:
    $s1 = "part1"
    $s2 = "part2"
    $s3 = "part3"
  condition:
    ($s1 and $s2) or not $s3
}
