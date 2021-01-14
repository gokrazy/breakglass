// breakglass is a SSH/SCP server which unpacks received tar archives
// and allows to run commands in the unpacked archive.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/gokrazy/gokrazy"

	"golang.org/x/crypto/ssh"
)

var (
	authorizedKeysPath = flag.String("authorized_keys",
		"/perm/breakglass.authorized_keys",
		"path to an OpenSSH authorized_keys file")

	hostKeyPath = flag.String("host_key",
		"/perm/breakglass.host_key",
		"path to a PEM-encoded RSA, DSA or ECDSA private key (create using e.g. ssh-keygen -f /perm/breakglass.host_key -N '' -t rsa)")

	forwarding = flag.String("forward",
		"",
		"allow port forwarding. Use `local` for device, `remote` for private networks")
)

func loadAuthorizedKeys(path string) (map[string]bool, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool)

	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
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
		if os.IsNotExist(err) {
			log.Printf("see https://github.com/gokrazy/breakglass#installation")
		}
		log.Fatal(err)
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
		hostport := net.JoinHostPort(addr, "22")
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
