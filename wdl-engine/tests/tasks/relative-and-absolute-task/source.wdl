version 1.2

task relative_and_absolute {
  command <<<
  mkdir -p my/path/to
  printf "something" > my/path/to/something.txt
  >>>

  output {
    File something = read_string("my/path/to/something.txt")
    File bashrc = "/root/.bashrc"
  }

  requirements {
    container: "ubuntu:focal"
  }
}
