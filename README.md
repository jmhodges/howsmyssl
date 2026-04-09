howsmyssl
=========

howsmyssl is the web app behind [https://howsmyssl.com](https://howsmyssl.com).

Orientation
--------
This is a Go project.

The HTML code goes in `templates/`. Templates are generated with Go's
`html/template` package. Determining the client's security is done in
client_info.go.

`go build` will generate a static binary called howsmyssl. This repo is `go
get`'able, of course.

It has a fork of the Go 1.10's crypto/tls library at ./tls110/ in order to add a
ServerHandshake and expose the ClientHello struct.

It's been useful to me to use [justrun][justrun] to recompile the project
while modifying the template. Typical use is simply:

    justrun -c "go build && ./howsmyssl" -i howsmyssl . templates/

(Justrun has the benefit of controlling the lifecycle of a process, unlike
most other file watch utilities.)

[justrun]: https://github.com/jmhodges/justrun
