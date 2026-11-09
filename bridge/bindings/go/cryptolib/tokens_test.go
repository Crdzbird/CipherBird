package cryptolib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tokenVectorsDir = "../../../../tests/vectors/tokens"

func tokenAvailable(t *testing.T, format string) bool {
	t.Helper()
	formats, err := TokenFormats()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range formats {
		if f.Format == format {
			return f.Available
		}
	}
	t.Fatalf("%s is not in the table", format)
	return false
}

func TestTokenFormatsTable(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	formats, err := TokenFormats()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]TokenFormat{
		"v4.local":   {Format: "v4.local", Purpose: "local", Standard: "PASETO v4", KeyBytes: 32, MaxInputBytes: 1 << 26},
		"cb1.local":  {Format: "cb1.local", Purpose: "local", Standard: "library-native", KeyBytes: 32, MaxInputBytes: 1 << 26},
		"cb1.public": {Format: "cb1.public", Purpose: "public", Standard: "library-native", PublicKeyBytes: 1984, SecretKeyBytes: 4096, SignatureBytes: 3373, MaxInputBytes: 1 << 26},
	}
	if len(formats) != len(want) {
		t.Fatalf("got %d formats", len(formats))
	}
	for _, f := range formats {
		w, ok := want[f.Format]
		if !ok {
			t.Fatalf("unexpected format %q", f.Format)
		}
		w.Available = f.Available
		if f != w {
			t.Fatalf("%s: got %+v want %+v", f.Format, f, w)
		}
		if f.Available != (TokenIssueLen(f.Format, 1, 0) != 0) {
			t.Fatalf("%s: available %v but issue len %d", f.Format, f.Available, TokenIssueLen(f.Format, 1, 0))
		}
	}
	if !tokenAvailable(t, "v4.local") {
		t.Fatal("v4.local is in every profile")
	}
}

func TestTokenUnknownAndUnavailableFormats(t *testing.T) {
	if _, err := TokenIssue("v9.local", counting(32, 1), []byte("m"), nil, nil); !errors.Is(err, ErrTokenFormat) {
		t.Fatalf("unknown format: %v", err)
	}
	if _, err := TokenAccept("v9.local", "v9.local.AAAA", counting(32, 1), nil, nil); !errors.Is(err, ErrTokenFormat) {
		t.Fatalf("unknown format accept: %v", err)
	}
	if _, err := TokenKeygen("v4.secret"); !errors.Is(err, ErrTokenFormat) {
		t.Fatalf("unknown format keygen: %v", err)
	}
	if TokenIssueLen("v9.local", 1, 0) != 0 || TokenAcceptCap("v9.local", 100) != 0 {
		t.Fatal("unknown formats have no sizes")
	}
	formats, _ := TokenFormats()
	for _, f := range formats {
		if f.Available {
			continue
		}
		if _, err := TokenIssue(f.Format, counting(32, 1), []byte("m"), nil, nil); !errors.Is(err, ErrPasetoUnavailable) {
			t.Fatalf("%s issue: %v", f.Format, err)
		}
		if _, err := TokenKeygen(f.Format); !errors.Is(err, ErrPasetoUnavailable) {
			t.Fatalf("%s keygen: %v", f.Format, err)
		}
	}
}

func TestTokenRoundTripPerFormat(t *testing.T) {
	formats, _ := TokenFormats()
	for _, f := range formats {
		if !f.Available {
			continue
		}
		k, err := TokenKeygen(f.Format)
		if err != nil {
			t.Fatal(err)
		}
		acceptKey := k.Secret
		if f.Purpose == "public" {
			if len(k.Secret) != f.SecretKeyBytes || len(k.Public) != f.PublicKeyBytes {
				t.Fatalf("%s: pair sizes %d %d", f.Format, len(k.Secret), len(k.Public))
			}
			acceptKey = k.Public
		} else if len(k.Secret) != f.KeyBytes || k.Public != nil {
			t.Fatalf("%s: key sizes %d %d", f.Format, len(k.Secret), len(k.Public))
		}
		m := []byte(`{"sub":"alice","exp":"2030-01-01T00:00:00Z"}`)
		footer, implicit := []byte(`{"kid":"k1"}`), []byte("audience")
		tok, err := TokenIssue(f.Format, k.Secret, m, footer, implicit)
		if err != nil {
			t.Fatalf("%s issue: %v", f.Format, err)
		}
		if !strings.HasPrefix(tok, f.Format+".") || len(tok) != TokenIssueLen(f.Format, len(m), len(footer)) {
			t.Fatalf("%s: shape %q", f.Format, tok[:20])
		}
		got, err := TokenAccept(f.Format, tok, acceptKey, footer, implicit)
		if err != nil || !bytes.Equal(got, m) {
			t.Fatalf("%s accept: %v %q", f.Format, err, got)
		}
		out := make([]byte, TokenAcceptCap(f.Format, len(tok)))
		n, err := TokenAcceptTo(out, f.Format, tok, acceptKey, footer, implicit)
		if err != nil || !bytes.Equal(out[:n], m) {
			t.Fatalf("%s accept to: %v", f.Format, err)
		}
		if _, err := TokenAccept(f.Format, tok, acceptKey, []byte(`{"kid":"k2"}`), implicit); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("%s footer: %v", f.Format, err)
		}
		if _, err := TokenAccept(f.Format, tok, acceptKey, footer, nil); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("%s implicit: %v", f.Format, err)
		}
		bad := []byte(tok)
		if bad[len(bad)-1] == 'A' {
			bad[len(bad)-1] = 'B'
		} else {
			bad[len(bad)-1] = 'A'
		}
		if _, err := TokenAccept(f.Format, string(bad), acceptKey, footer, implicit); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("%s tamper: %v", f.Format, err)
		}
		other, _ := TokenKeygen(f.Format)
		otherKey := other.Secret
		if f.Purpose == "public" {
			otherKey = other.Public
		}
		if _, err := TokenAccept(f.Format, tok, otherKey, footer, implicit); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("%s wrong key: %v", f.Format, err)
		}
		if _, err := TokenIssue(f.Format, k.Secret[:len(k.Secret)-1], m, nil, nil); !errors.Is(err, ErrPasetoArgument) {
			t.Fatalf("%s short key: %v", f.Format, err)
		}
		if TokenPeekFormat(tok) != f.Format {
			t.Fatalf("%s peek format: %q", f.Format, TokenPeekFormat(tok))
		}
		pf, err := TokenPeekFooter(tok)
		if err != nil || !bytes.Equal(pf, footer) {
			t.Fatalf("%s peek footer: %v %q", f.Format, err, pf)
		}
		empty, err := TokenIssue(f.Format, k.Secret, nil, nil, nil)
		if err != nil || strings.Count(empty, ".") != 2 {
			t.Fatalf("%s empty: %v %q", f.Format, err, empty)
		}
		if pf, err := TokenPeekFooter(empty); err != nil || pf != nil {
			t.Fatalf("%s no footer: %v %v", f.Format, err, pf)
		}
		if got, err := TokenAccept(f.Format, empty, acceptKey, nil, nil); err != nil || len(got) != 0 {
			t.Fatalf("%s empty accept: %v", f.Format, err)
		}
	}
}

func TestTokenHeaderNeverChoosesTheFormat(t *testing.T) {
	k, _ := TokenKeygen("v4.local")
	v4, err := TokenIssue("v4.local", k.Secret, []byte("m"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	relabelled := "cb1.local." + v4[len("v4.local."):]
	if _, err := TokenAccept("v4.local", relabelled, k.Secret, nil, nil); !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("relabelled: %v", err)
	}
	if tokenAvailable(t, "cb1.local") {
		cb1, _ := TokenIssue("cb1.local", k.Secret, []byte("m"), nil, nil)
		if _, err := TokenAccept("v4.local", cb1, k.Secret, nil, nil); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("cb1 as v4: %v", err)
		}
		if _, err := TokenAccept("cb1.local", v4, k.Secret, nil, nil); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("v4 as cb1: %v", err)
		}
	}
	if TokenPeekFormat("v9.public.abc") != "v9.public" || TokenPeekFormat("v4.secret.abc") != "" || TokenPeekFormat("") != "" {
		t.Fatal("peek format shape")
	}
	if _, err := TokenPeekFooter("v4.local.abc.a=b"); !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("bad footer: %v", err)
	}
	if pf, err := TokenPeekFooter("v4.local.abc.a2lk"); err != nil || string(pf) != "kid" {
		t.Fatalf("kid footer: %v %q", err, pf)
	}
}

func TestTokenPerFormatFunctionsAgree(t *testing.T) {
	k, _ := TokenKeygen("v4.local")
	m := []byte(`{"data":"x"}`)
	tok, err := PasetoV4LocalEncrypt(k.Secret, m, []byte("f"), []byte("i"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := TokenAccept("v4.local", tok, k.Secret, []byte("f"), []byte("i")); err != nil || !bytes.Equal(got, m) {
		t.Fatalf("generic accepts the v4 function's token: %v", err)
	}
	gen, _ := TokenIssue("v4.local", k.Secret, m, []byte("f"), []byte("i"))
	if got, err := PasetoV4LocalDecrypt(gen, k.Secret, []byte("f"), []byte("i")); err != nil || !bytes.Equal(got, m) {
		t.Fatalf("the v4 function accepts the generic token: %v", err)
	}
	if tokenAvailable(t, "cb1.public") {
		kp, _ := TokenKeygen("cb1.public")
		signed, _ := Cb1PublicSign(kp.Secret, m, nil, nil)
		if got, err := TokenAccept("cb1.public", signed, kp.Public, nil, nil); err != nil || !bytes.Equal(got, m) {
			t.Fatalf("generic verifies the cb1 function's token: %v", err)
		}
	}
}

type tokenVectorFile struct {
	Format string `json:"format"`
	Cases  []struct {
		Name       string `json:"name"`
		ExpectFail bool   `json:"expect-fail"`
		Key        string `json:"key"`
		PublicKey  string `json:"public-key"`
		SecretKey  string `json:"secret-key"`
		Token      string `json:"token"`
		Payload    string `json:"payload"`
		Footer     string `json:"footer"`
		Implicit   string `json:"implicit-assertion"`
	} `json:"cases"`
}

func TestTokenCommonVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(tokenVectorsDir, "*.json"))
	if err != nil || len(files) < 3 {
		t.Skipf("token vectors not present: %v (%d files)", err, len(files))
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var file tokenVectorFile
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		if file.Format == "" || len(file.Cases) == 0 {
			t.Fatalf("%s: empty", path)
		}
		if !tokenAvailable(t, file.Format) {
			t.Logf("%s: not in this profile, skipped", file.Format)
			continue
		}
		public := strings.HasSuffix(file.Format, ".public")
		pass, fail := 0, 0
		for _, c := range file.Cases {
			keyHex := c.Key
			if public {
				keyHex = c.PublicKey
			}
			if keyHex == "" {
				if !c.ExpectFail {
					t.Fatalf("%s %s: no key", file.Format, c.Name)
				}
				fail++
				continue
			}
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := TokenAccept(file.Format, c.Token, key, []byte(c.Footer), []byte(c.Implicit))
			if c.ExpectFail {
				if !errors.Is(err, ErrPasetoInvalid) || got != nil {
					t.Fatalf("%s %s: expected invalid, got %v", file.Format, c.Name, err)
				}
				fail++
				continue
			}
			if err != nil || string(got) != c.Payload {
				t.Fatalf("%s %s: %v %q", file.Format, c.Name, err, got)
			}
			if TokenPeekFormat(c.Token) != file.Format {
				t.Fatalf("%s %s: peek format", file.Format, c.Name)
			}
			pf, err := TokenPeekFooter(c.Token)
			if err != nil || string(pf) != c.Footer {
				t.Fatalf("%s %s: peek footer %v %q", file.Format, c.Name, err, pf)
			}
			if public {
				sk, _ := hex.DecodeString(c.SecretKey)
				again, err := TokenIssue(file.Format, sk, []byte(c.Payload), []byte(c.Footer), []byte(c.Implicit))
				if err != nil {
					t.Fatalf("%s %s: re-issue %v", file.Format, c.Name, err)
				}
				if _, err := TokenAccept(file.Format, again, key, []byte(c.Footer), []byte(c.Implicit)); err != nil {
					t.Fatalf("%s %s: re-issued token %v", file.Format, c.Name, err)
				}
			}
			pass++
		}
		t.Logf("%s: %d accepted, %d rejected as expected", file.Format, pass, fail)
	}
}
