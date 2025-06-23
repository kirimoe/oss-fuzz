rule for_all_them {
  strings:
    $s1 = "common_prefix_1"
    $s2 = "common_prefix_2"
    $s3 = "common_prefix_3"
  condition:
    for all of them : ($)
}
