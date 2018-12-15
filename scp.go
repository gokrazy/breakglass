package main

import (
	"archive/tar"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type countingWriter int64

func (cw *countingWriter) Write(p []byte) (n int, err error) {
	*cw += countingWriter(len(p))
	return len(p), nil
}

func scpSink(channel ssh.Channel, req *ssh.Request, cmdline []string) error {
	scpFlags := flag.NewFlagSet("scp", flag.ContinueOnError)
	sink := scpFlags.Bool("t", false, "sink (to)")
	if err := scpFlags.Parse(cmdline[1:]); err != nil {
		return err
	}
	if !*sink {
		return fmt.Errorf("expected -t")
	}

	// Tell the remote end we’re ready to receive data.
	if _, err := channel.Write([]byte{0x00}); err != nil {
		return err
	}

	buf := make([]byte, 1024)
	for {
		n, err := channel.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		msg := buf[:n]

		// Acknowledge receipt of the control message
		if _, err := channel.Write([]byte{0x00}); err != nil {
			return err
		}

		if msg[0] == 'C' {
			msgstr := strings.TrimSpace(string(msg))
			parts := strings.Split(msgstr, " ")
			if got, want := len(parts), 3; got != want {
				return fmt.Errorf("invalid number of space-separated tokens in control message %q: got %d, want %d", msgstr, got, want)
			}
			size, err := strconv.ParseInt(parts[1], 0, 64)
			if err != nil {
				return err
			}

			// Retrieve file contents
			var cw countingWriter
			tr := tar.NewReader(io.TeeReader(channel, &cw))
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}

				log.Printf("extracting %q", h.Name)
				if err := os.MkdirAll(filepath.Dir(h.Name), 0700); err != nil {
					return err
				}
				if strings.HasSuffix(h.Name, "/") {
					continue // directory, don’t try to OpenFile() it
				}
				mode := h.FileInfo().Mode() & os.ModePerm
				out, err := os.OpenFile(h.Name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
				if err != nil {
					return err
				}
				if _, err := io.Copy(out, tr); err != nil {
					out.Close()
					return err
				}
				if err := out.Close(); err != nil {
					return err
				}
			}

			if rest := size - int64(cw); rest > 0 {
				buf := make([]byte, rest)
				if _, err := channel.Read(buf); err != nil {
					return err
				}
			}

			// Read status byte after transfer
			buf := make([]byte, 1)
			if _, err := channel.Read(buf); err != nil {
				return err
			}

			// Acknowledge file transfer
			if _, err := channel.Write([]byte{0x00}); err != nil {
				return err
			}
		}
	}

	exitStatus := make([]byte, 4)
	exitStatus[3] = 0
	if _, err := channel.SendRequest("exit-status", false, exitStatus); err != nil {
		return err
	}
	channel.Close()
	req.Reply(true, nil)
	return nil
}
