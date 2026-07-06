package detect

import (
	"strings"
	"testing"
)

// The classifier's contract: real secrets alert, documentation examples and
// masked values never do.
func TestClassifierTPFPTable(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
		kind string
	}{
		// true positives
		{"leaked key aws_access_key_id=AKIA4X7GH2QPLM9WTRV3", true, "aws_key"},
		{"dsn=postgres://svc:p4ssw0rd!x@db-01:5432/prod", true, "db_password"},
		{"stripe_secret=sk_live_a8B3kQ9zL2mN4pR7sT1vW6xY", true, "api_secret"},
		{"dumping cfg: api_key=9f8E7d6C5b4A3210fedcba98", true, "api_secret"},
		{"-----BEGIN RSA PRIVATE KEY-----", true, "private_key"},
		{"customer ssn 545-12-3456 on file", true, "ssn"},
		{"card on record 4556737586899855", true, "card"},

		// documentation examples / placeholders / masked values
		{"docs example: aws_access_key_id=AKIAIOSFODNN7EXAMPLE", false, ""},
		{"config template loaded, api_key=XXXX-XXXX-PLACEHOLDER", false, ""},
		{"sanitized connection string: password=<redacted>", false, ""},
		{"sample payload uses card 4111 1111 1111 1111 (test number)", false, ""},
		{"tutorial snippet: export STRIPE_KEY=sk_test_EXAMPLEEXAMPLEEXAMPLE", false, ""},
		{"masked secret: token=************", false, ""},
		{"set password=changeme then rotate", false, ""},
		{"example ssn is 123-45-6789", false, ""},
		{"invalid ssn 000-12-3456 rejected", false, ""},
		{"luhn-invalid number 4556737586899856 ignored", false, ""},

		// ordinary log lines
		{"request completed in 42ms", false, ""},
		{"GET /api/v1/items/1042 200", false, ""},
		{"Accepted publickey for zoe from 10.2.3.4 port 51234", false, ""},
		{"outbound transfer 123456789 bytes", false, ""},
	}
	for _, c := range cases {
		got := ClassifyMessage(c.msg)
		if c.want && len(got) == 0 {
			t.Errorf("MISSED real secret: %q", c.msg)
		}
		if !c.want && len(got) > 0 {
			t.Errorf("FALSE POSITIVE on %q: %+v", c.msg, got)
		}
		if c.want && len(got) > 0 && c.kind != "" && got[0].Kind != c.kind {
			t.Errorf("wrong kind for %q: want %s got %s", c.msg, c.kind, got[0].Kind)
		}
	}
}

func TestRedactMessageMasksSecrets(t *testing.T) {
	in := "key aws_access_key_id=AKIA4X7GH2QPLM9WTRV3 and dsn=postgres://svc:p4ssw0rd!x@db-01/prod"
	out := RedactMessage(in)
	for _, leak := range []string{"AKIA4X7GH2QPLM9WTRV3", "p4ssw0rd!x"} {
		if strings.Contains(out, leak) {
			t.Fatalf("redaction leaked %q: %s", leak, out)
		}
	}
	// examples must survive untouched
	ex := "docs example: aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
	if RedactMessage(ex) != ex {
		t.Fatalf("redaction mangled a documentation example: %s", RedactMessage(ex))
	}
}
