import "cuckoo"
import "math"
import "hash"

rule multi_module_check {
  strings:
    $md5 = "MD5-Hash"
  condition:
    cuckoo.network.http_request(/foo/) and math.entropy(0, filesize) > 7.0 and hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"
}
