howsmyssl
=========

howsmyssl is the web app behind [https://howsmyssl.com](https://howsmyssl.com).

Orientation
--------
This is a Go project.

The HTML code goes in `templates/`. Templates are generated with Go's
`html/template` package. Determining the client's security is done in
client_info.go.

This project requires [Go 1.2][go1.2] to build with TLS 1.1 and 1.2
support. `go build` will generate a static binary called howsmyssl. This repo
is `go get`'able, of course.

It has a fork of the Go crypto/tls library at ./tls/ in order to add a
ServerHandshake and expose the ClientHello struct.

Building
--------

    go get
    go build
    ./howsmyssl &
    curl -k https://localhost:10443/a/check

It's been useful to me to use [justrun][justrun] to recompile the project
while modifying the template. Typical use is simply:

    justrun -c "go build && ./howsmyssl" -i howsmyssl . templates/`

(Justrun has the benefit of controlling the lifecycle of a process, unlike
most other file watch utilities.)

[go1.2]: http://golang.org/doc/go1.2
[justrun]: https://github.com/jmhodges/justrun
