package http_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

// A cookie set by one host must not follow a redirect to a DIFFERENT
// host. "localhost" and "127.0.0.1" are different hosts for cookie
// purposes even though both resolve here.
func TestGoishRef(t *testing.T) {
	lnB, _ := net.Listen("tcp", "127.0.0.1:0")
	portB := lnB.Addr().(*net.TCPAddr).Port
	gotB := make(chan string, 4)
	srvB := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotB <- r.Header.Get("Cookie")
			fmt.Fprint(w, "B")
		})}
	go srvB.Serve(lnB)
	defer srvB.Close()

	lnA, _ := net.Listen("tcp", "127.0.0.1:0")
	portA := lnA.Addr().(*net.TCPAddr).Port
	srvA := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/set":
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "secret", Path: "/"})
				fmt.Fprint(w, "set")
			case "/same":
				// Redirect to the SAME host, different path.
				http.Redirect(w, r, "/echo", http.StatusFound)
			case "/echo":
				gotB <- "A-echo:" + r.Header.Get("Cookie")
				fmt.Fprint(w, "A")
			case "/cross":
				// Redirect to a DIFFERENT host (127.0.0.1 vs localhost).
				http.Redirect(w, r, fmt.Sprintf("http://127.0.0.1:%d/", portB), http.StatusFound)
			}
		})}
	go srvA.Serve(lnA)
	defer srvA.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	base := fmt.Sprintf("http://localhost:%d", portA)

	resp, err := c.Get(base + "/set")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fmt.Printf("after-set        jar-has-sid=%v\n",
		strings.Contains(fmt.Sprint(jar.Cookies(resp.Request.URL)), "sid"))

	resp, _ = c.Get(base + "/same")
	resp.Body.Close()
	fmt.Printf("same-host-hop    cookie=%q\n", <-gotB)

	resp, _ = c.Get(base + "/cross")
	resp.Body.Close()
	fmt.Printf("cross-host-hop   cookie=%q\n", <-gotB)
}
