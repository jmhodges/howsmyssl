// genechkey makes a new Encrypted Client Hello (ECH) key file for howsmyssl's
// -echKeysFile flag, and prints the ECHConfigList that clients need, base64
// encoded as the "ech" parameter of an HTTPS DNS record wants it.
//
// The server's TLS certificate must also cover the public name, or clients
// whose ECH offer is rejected can't check the retry configs and fail.
//
// To rotate keys, pass the current file as -addTo. The new file at -out holds
// a new key first, which the server sends as its retry config, and then the
// keys of the old file, which it still accepts. Deploy it, publish the printed
// config, and once clients have dropped the old config (wait out the DNS
// record's TTL), delete the old key's two PEM blocks from the end of the file.
//
// The file holds private keys: keep it out of the repository and treat it
// like the TLS certificate's key.
package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jmhodges/howsmyssl/echkeys"
)

var (
	publicName = flag.String("publicName", "", "the DNS name clients put in the outer, unencrypted ClientHello; the TLS certificate must cover it (required)")
	out        = flag.String("out", "", "path to write the new key file to; it must not exist yet (required)")
	addTo      = flag.String("addTo", "", "an existing key file whose keys the new file keeps, after the new key, to rotate keys without breaking clients holding an old config")
)

func main() {
	flag.Parse()
	if *publicName == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	var keyFile, configList []byte
	var err error
	if *addTo == "" {
		keyFile, configList, err = echkeys.Generate(*publicName)
	} else {
		var existing []byte
		existing, err = os.ReadFile(*addTo)
		if err != nil {
			log.Fatalf("unable to read %s: %s", *addTo, err)
		}
		keyFile, configList, err = echkeys.AddKey(existing, *publicName)
		if err != nil {
			err = fmt.Errorf("%s: %w", *addTo, err)
		}
	}
	if err != nil {
		log.Fatalf("unable to make an ECH key: %s", err)
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		log.Fatalf("unable to create %s: %s", *out, err)
	}
	_, writeErr := f.Write(keyFile)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		log.Fatalf("unable to write %s: %s", *out, err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(configList))
}
