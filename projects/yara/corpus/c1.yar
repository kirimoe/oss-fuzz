rule basic_string_match {
  strings:
    $a = "Hello, World!"
  condition:
    $a
}
