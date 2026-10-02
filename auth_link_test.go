package main

import "testing"

func TestAuthLinkToken(t *testing.T) {
    tok, err := newAuthLinkToken()
    if err != nil {
        t.Fatalf("newAuthLinkToken: %v", err)
    }
    if !isAuthLinkToken(tok) {
        t.Fatalf("fresh token rejected: %q", tok)
    }
    tok2, _ := newAuthLinkToken()
    if tok == tok2 {
        t.Fatalf("two tokens identical")
    }
    for _, bad := range []string{"", "abc", tok[:47], tok + "0", "zz" + tok[2:]} {
        if isAuthLinkToken(bad) {
            t.Errorf("accepted bad token %q", bad)
        }
    }
    if got := authLinkURL(tok); got != "https://astrolytix.com/login/?t="+tok {
        t.Errorf("authLinkURL = %q", got)
    }
    if authLinkURL("") != "" {
        t.Errorf("empty token must give no link")
    }
}
