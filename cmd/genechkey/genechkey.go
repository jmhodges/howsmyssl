// genechkey makes a new Encrypted Client Hello (ECH) key file for howsmyssl's
// -echKeysFile flag, and prints the ECHConfigList that clients need, base64
// encoded as the "ech" parameter of an HTTPS DNS record wants it.
//
// The file holds a private key: keep it out of the repository and treat it
// like the TLS certificate's key.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jmhodges/howsmyssl/echkeys"
)

var (
	publicName = flag.String("publicName", "", "the DNS name clients put in the outer, unencrypted ClientHello (required)")
	out        = flag.String("out", "", "path to write the new key file to; it must not exist yet (required)")
)

func main() {
	flag.Parse()
	if *publicName == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	keyFile, configList, err := echkeys.Generate(*publicName)
	if err != nil {
		log.Fatalf("unable to make an ECH key: %s", err)
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		log.Fatalf("unable to create %s: %s", *out, err)
	}
	if _, err := f.Write(keyFile); err != nil {
		f.Close()
		log.Fatalf("unable to write %s: %s", *out, err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("unable to write %s: %s", *out, err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(configList))
}
