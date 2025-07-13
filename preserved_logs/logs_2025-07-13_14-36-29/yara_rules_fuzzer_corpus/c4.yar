rule various_strings {
  strings:
    $ascii = "simple ascii string"
    $wide = "wide string" wide
    $hex = { 10 20 30 [4-6] 70 80 90 }
    $regex = /regex [0-9]{3}/
  condition:
    all of them
}
