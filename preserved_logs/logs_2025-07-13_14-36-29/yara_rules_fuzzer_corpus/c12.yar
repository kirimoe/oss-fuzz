rule for_any_them {
  strings:
    $x = "needle"
    $y = "haystack"
  condition:
    for any of ($x, $y) : ($ at 0)
}
