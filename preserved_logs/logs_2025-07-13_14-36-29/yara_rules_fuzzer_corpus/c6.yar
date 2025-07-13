private rule private_rule_example {
  strings:
    $p = "secret_data"
  condition:
    $p
}

global rule global_rule_example {
  strings:
    $g = "common_indicator"
  condition:
    $g
}
