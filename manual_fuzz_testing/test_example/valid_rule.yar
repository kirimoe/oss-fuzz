// yrcc test_malicious.yar test_malicious.yarc

rule TestMaliciousString
{
    meta:
        description = "This is description"
        author = "Sahil"
        date = "2025-06-12"

    strings:
        $good_string = "helloworld" ascii

    condition:
        $good_string
}
