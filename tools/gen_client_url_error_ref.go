package http_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGoishRef(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/auth", nil)
	req.RequestURI = "/auth"
	_, err := ts.Client().Do(req)
	msg := ""
	if err != nil {
		msg = strings.ReplaceAll(err.Error(), ts.URL, "URL")
	}
	fmt.Printf("requesturi-set err=%q\n", msg)
}
