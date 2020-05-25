// Binary breakglass is a wrapper around SSH, starting breakglass on the
// destination gokrazy installation <hostname> first.
//
// Example:
//   breakglass gokrazy
//   breakglass -debug_tarball_pattern=$HOME/gokrazy/debug-\${GOARCH}.tar gokrazy
package main

import (
	"archive/tar"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type bg struct {
	// config
	hostname     string
	pw           string
	forceRestart bool

	// state
	GOARCH string
}

func (bg *bg) startBreakglass() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Jar: jar}
	urlPrefix := "http://gokrazy:" + bg.pw + "@" + bg.hostname
	form, err := client.Get(urlPrefix + "/status?path=/user/breakglass")
	if err != nil {
		return err
	}
	if form.StatusCode == http.StatusNotFound {
		fmt.Fprintf(os.Stderr, "Hint: have you installed Go package github.com/gokrazy/breakglass on your gokrazy installation %q?\n", bg.hostname)
	}
	if got, want := form.StatusCode, http.StatusOK; got != want {
		b, _ := ioutil.ReadAll(form.Body)
		return fmt.Errorf("starting breakglass: unexpected HTTP status: got %v (%s), want %v",
			form.Status,
			strings.TrimSpace(string(b)),
			want)
	}
	var xsrfToken string
	for _, c := range form.Cookies() {
		if c.Name != "gokrazy_xsrf" {
			continue
		}
		xsrfToken = c.Value
		break
	}
	if xsrfToken == "" {
		return fmt.Errorf("no gokrazy_xsrf cookie received")
	}

	bg.GOARCH = form.Header.Get("X-Gokrazy-Goarch")

	if form.Header.Get("X-Gokrazy-Status") == "started" && !bg.forceRestart {
		return nil // breakglass already running
	}

	resp, err := client.Post(urlPrefix+"/restart?path=/user/breakglass&xsrftoken="+xsrfToken, "", nil)
	if err != nil {
		return err
	}
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		return fmt.Errorf("restarting breakglass: unexpected HTTP status code: got %d, want %d", got, want)
	}
	return nil
}

func pollPort(ctx context.Context, hostname, port string) error {
	var d net.Dialer
	for ctx.Err() == nil {
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(hostname, port))
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		conn.Close()
		return nil
	}
	return ctx.Err()
}

func (bg *bg) uploadDebugTarball(debugTarballPattern string) error {
	if debugTarballPattern == "" {
		return nil // nothing to do
	}
	debugTarball := strings.ReplaceAll(
		debugTarballPattern,
		"${GOARCH}",
		bg.GOARCH)
	st, err := os.Stat(debugTarball)
	if err != nil {
		return err
	}
	var contents []string
	f, err := os.Open(debugTarball)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // end of archive
		}
		if err != nil {
			return err
		}
		contents = append(contents, fmt.Sprintf("%s (%v bytes)", hdr.Name, hdr.Size))
	}
	log.Printf("uploading debug tarball:\n\t%s\n\t(last modified: %v, %v ago)\n\t\t%s",
		debugTarball,
		st.ModTime().Format("2006-01-02 15:04:05 -0700"),
		time.Since(st.ModTime()).Round(1*time.Second),
		strings.Join(contents, "\n\t\t"))

	scp := exec.Command("scp", debugTarball, bg.hostname+":")
	scp.Stderr = os.Stderr
	if err := scp.Run(); err != nil {
		return fmt.Errorf("%v: %v", scp.Args, err)
	}
	return nil
}

func breakglass() error {
	var (
		forceRestart = flag.Bool(
			"force_restart",
			false,
			"restart breakglass if it is already running")

		debugTarballPattern = flag.String(
			"debug_tarball_pattern",
			"",
			"If non-empty, a pattern resulting in the path to a debug.tar archive that should be copied to breakglass before starting a shell. This can be used to make additional tools available for debugging. All occurrences of ${GOARCH} will be replaced with the runtime.GOARCH of the remote gokrazy installation.")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "  breakglass gokrazy\n")
		fmt.Fprintf(os.Stderr, "  breakglass -debug_tarball_pattern=$HOME/gokrazy/debug-\\${GOARCH}.tar gokrazy\n")

		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatalf("syntax: breakglass <hostname> [command]")
	}
	hostname := flag.Arg(0)

	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	b, err := ioutil.ReadFile(filepath.Join(dir, "gokrazy", "http-password.txt"))
	if err != nil {
		return err
	}
	pw := strings.TrimSpace(string(b))
	bg := &bg{
		hostname:     hostname,
		pw:           pw,
		forceRestart: *forceRestart,
	}

	log.Printf("checking breakglass status on gokrazy installation %q", hostname)
	if err := bg.startBreakglass(); err != nil {
		return err
	}

	time.Sleep(250 * time.Millisecond) // give gokrazy some time to restart

	log.Printf("polling SSH port to become available")
	ctx, canc := context.WithTimeout(context.Background(), 2*time.Second)
	defer canc()
	if err := pollPort(ctx, hostname, "ssh"); err != nil {
		return err
	}

	if err := bg.uploadDebugTarball(*debugTarballPattern); err != nil {
		return err
	}

	ssh := exec.Command("ssh", hostname)
	if args := flag.Args()[1:]; len(args) > 0 {
		ssh.Args = append(ssh.Args, args...)
	}
	log.Printf("%v", ssh.Args)
	ssh.Stdin = os.Stdin
	ssh.Stdout = os.Stdout
	ssh.Stderr = os.Stderr
	if err := ssh.Run(); err != nil {
		return fmt.Errorf("%v: %v", ssh.Args, err)
	}

	return nil
}

func main() {
	if err := breakglass(); err != nil {
		log.Fatal(err)
	}
}
