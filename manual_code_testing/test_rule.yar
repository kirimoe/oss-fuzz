rule ExampleRule
{
    strings:
        $text_string = "test_string"
    condition:
        $text_string
}
