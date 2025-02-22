// breakglass is a SSH/SCP server which unpacks received tar archives
// and allows to run commands in the unpacked archive.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/gokrazy/gokrazy"

	"golang.org/x/crypto/ssh"
)

var (
	authorizedKeysPath = flag.String("authorized_keys",
		"/perm/breakglass.authorized_keys",
		"path to an OpenSSH authorized_keys file; if the value is 'ec2', fetch the SSH key(s) from the AWS IMDSv2 metadata")

	hostKeyPath = flag.String("host_key",
		"/perm/breakglass.host_key",
		"path to a PEM-encoded RSA, DSA or ECDSA private key (create using e.g. ssh-keygen -f /perm/breakglass.host_key -N '' -t rsa)")

	port = flag.String("port",
		"22",
		"port for breakglass to listen on")

	enableBanner = flag.Bool("enable_banner",
		true,
		"Adds a banner to greet the user on login")

	forwarding = flag.String("forward",
		"",
		"allow port forwarding. Use `loopback` for loopback interfaces and `private-network` for private networks")
)

func loadAuthorizedKeys(path string) (map[string]bool, error) {
	var b []byte
	var err error
	switch path {
	case "ec2":
		b, err = loadAWSEC2SSHKeys()
	default:
		b, err = ioutil.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool)

	s := bufio.NewScanner(bytes.NewReader(b))
	for lineNum := 1; s.Scan(); lineNum++ {
		if tr := strings.TrimSpace(s.Text()); tr == "" || strings.HasPrefix(tr, "#") {
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(s.Bytes())
		if err != nil {
			return nil, err
		}
		result[string(pubKey.Marshal())] = true
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func loadHostKey(path string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(b)
}

func createHostKey(path string) (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0400)
	if err == nil {
		defer file.Close()

		var pkcs8 []byte
		if pkcs8, err = x509.MarshalPKCS8PrivateKey(key); err == nil {
			err = pem.Encode(file, &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8,
			})
		}
	}
	if err != nil {
		log.Printf("could not save generated host key: %v", err)
	}

	return ssh.NewSignerFromKey(key)
}

func buildTimestamp() (string, error) {
	var statusReply struct {
		BuildTimestamp string `json:"BuildTimestamp"`
	}
	pw, err := os.ReadFile("/etc/gokr-pw.txt")
	if err != nil {
		return "", err
	}
	client := http.DefaultClient
	var req *http.Request
	if conn, err := net.Dial("unix", gokrazy.HTTPUnixSocket); err == nil {
		// Use the Unix domain socket if available.
		conn.Close()
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, "unix", gokrazy.HTTPUnixSocket)
			},
		}
		req, err = http.NewRequest("GET", "http://gokrazy:"+strings.TrimSpace(string(pw))+"@unix/", nil)
	} else {
		// Fallback to TCP.
		port, err := os.ReadFile("/etc/http-port.txt")
		if err != nil {
			return "", err
		}
		req, err = http.NewRequest("GET", "http://gokrazy:"+strings.TrimSpace(string(pw))+"@localhost:"+strings.TrimSpace(string(port))+"/", nil)
	}
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		b, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected HTTP status code: got %v, want %v (body: %s)", resp.Status, want, strings.TrimSpace(string(b)))
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(b, &statusReply); err != nil {
		return "", err
	}
	return statusReply.BuildTimestamp, nil
}

var motd string

func initMOTD() error {
	if !*enableBanner {
		return nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("os.Hostname(): %v", err)
		hostname = "gokrazy"
	}
	const maxSpace = "                 "
	if len(hostname) > len(maxSpace) {
		hostname = hostname[:len(maxSpace)]
	}
	hostname += `"`
	if padding := len(maxSpace) - len(hostname); padding > 0 {
		hostname += strings.Repeat(" ", padding)
	}

	buildTimestamp, err := buildTimestamp()
	if err != nil {
		return err
	}

	motd = fmt.Sprintf(`              __                           
 .-----.-----|  |--.----.---.-.-----.--.--.
 |  _  |  _  |    <|   _|  _  |-- __|  |  |
 |___  |_____|__|__|__| |___._|_____|___  |
 |_____|  host:  "%s |_____|
          model: %s
          build: %s
`,
		hostname,
		gokrazy.Model(),
		buildTimestamp)
	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	gokrazy.DontStartOnBoot()

	authorizedKeys, err := loadAuthorizedKeys(*authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("see https://github.com/gokrazy/breakglass#installation")
		}
		log.Fatal(err)
	}

	if err := initMOTD(); err != nil {
		log.Print(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeys[string(pubKey.Marshal())] {
				log.Printf("user %q successfully authorized from remote addr %s", conn.User(), conn.RemoteAddr())
				return nil, nil
			}
			return nil, fmt.Errorf("public key not found in %s", *authorizedKeysPath)
		},
	}

	signer, err := loadHostKey(*hostKeyPath)
	if err != nil {
		// create host key
		if os.IsNotExist(err) {
			log.Println("host key not found, creating initial host key")
			signer, err = createHostKey(*hostKeyPath)
			if err != nil {
				err = fmt.Errorf("could not create host key: %w", err)
			}
		}

		if err != nil {
			log.Fatal(err)
		}
	}
	config.AddHostKey(signer)

	unpackDir, err := ioutil.TempDir("", "breakglass")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(unpackDir)

	// This tmpfs mount ensures that our temp directory is mounted
	// without NOEXEC and that we have plenty of space for payload.
	// It will be cleaned up on process exit because each gokrazy
	// process uses a non-shared mount namespace.
	if err := syscall.Mount("tmpfs", unpackDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_RELATIME, "size=500M"); err != nil {
		log.Fatalf("tmpfs on %s: %v", unpackDir, err)
	}

	if err := os.Chdir(unpackDir); err != nil {
		log.Fatal(err)
	}

	if err := os.Setenv("PATH", unpackDir+":"+os.Getenv("PATH")); err != nil {
		log.Fatal(err)
	}

	accept := func(listener net.Listener) {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}

			go func(conn net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					log.Printf("handshake: %v", err)
					return
				}

				// discard all out of band requests
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					handleChannel(newChannel)
				}
			}(conn)
		}
	}

	addrs, err := gokrazy.PrivateInterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range addrs {
		hostport := net.JoinHostPort(addr, *port)
		listener, err := net.Listen("tcp", hostport)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("listening on %s\n", hostport)
		go accept(listener)
	}

	fmt.Printf("host key fingerprint: %s\n", ssh.FingerprintSHA256(signer.PublicKey()))

	select {}
}
