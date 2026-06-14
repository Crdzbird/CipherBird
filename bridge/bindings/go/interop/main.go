// Go "party" for the Go <-> Flutter/Dart interop example.
//
// It speaks authenticated public-key encryption (Box / X25519). Subcommands:
//
//	keygen                                  -> prints "<pubHex> <secHex>"
//	enc <recipientPubHex> <senderSecHex> <msg>  -> prints "<ciphertextHex>"
//	dec <senderPubHex> <recipientSecHex> <ctHex> -> prints the decrypted UTF-8
//
// The ciphertext format is identical to what every other CryptoLib binding
// produces, because all of them call the same native library. See
// bridge/bindings/interop/run.sh for the orchestration of all three directions.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
)

func die(msg string) {
	fmt.Fprintln(os.Stderr, "go-party: "+msg)
	os.Exit(1)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		die("bad hex: " + err.Error())
	}
	return b
}

func main() {
	if err := cryptolib.Init(); err != nil {
		die("init: " + err.Error())
	}
	if len(os.Args) < 2 {
		die("usage: keygen | enc <recipPub> <senderSec> <msg> | dec <senderPub> <recipSec> <ct>")
	}

	switch os.Args[1] {
	case "keygen":
		kp := cryptolib.BoxKeygen()
		fmt.Printf("%s %s\n", hex.EncodeToString(kp.Public), hex.EncodeToString(kp.Secret))

	case "enc":
		if len(os.Args) != 5 {
			die("enc needs <recipientPubHex> <senderSecHex> <msg>")
		}
		ct, err := cryptolib.BoxEncrypt([]byte(os.Args[4]), unhex(os.Args[2]), unhex(os.Args[3]))
		if err != nil {
			die("encrypt: " + err.Error())
		}
		fmt.Println(hex.EncodeToString(ct))

	case "dec":
		if len(os.Args) != 5 {
			die("dec needs <senderPubHex> <recipientSecHex> <ctHex>")
		}
		pt, err := cryptolib.BoxDecrypt(unhex(os.Args[4]), unhex(os.Args[2]), unhex(os.Args[3]))
		if err != nil {
			die("decrypt (auth failed?): " + err.Error())
		}
		fmt.Println(string(pt))

	default:
		die("unknown command: " + os.Args[1])
	}
}
