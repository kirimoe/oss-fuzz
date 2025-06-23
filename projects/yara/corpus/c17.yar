rule rule_with_meta_and_tags : tag1 tag2 malware {
  meta:
    author = "John Doe"
    date = "2024-06-14"
    version = "1.0"
    description = "A rule with meta information and tags"
  strings:
    $s = "metadata_string"
  condition:
    $s
}
