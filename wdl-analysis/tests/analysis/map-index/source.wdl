## This is a test of indexing a map.

version 1.1

task test {
    Map[String, String] a = {"foo": "bar", "baz": "qux"}

    # OK
    String x = a["foo"]

    # BAD
    String y = a[5]
    
    command <<<>>>
}