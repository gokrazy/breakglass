package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/shlex"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

func handleChannel(newChan ssh.NewChannel) {
	switch t := newChan.ChannelType(); t {
	case "session":
		handleSession(newChan)
	case "direct-tcpip":
		handleTCPIP(newChan)
	default:
		newChan.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %q", t))
		return
	}
}

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func forwardingAllowed(addr string, port uint32) bool {
	return addr == "localhost"
}

func handleTCPIP(newChan ssh.NewChannel) {
	d := localForwardChannelData{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if !forwardingAllowed(d.DestAddr, d.DestPort) {
		newChan.Reject(ssh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}

func handleSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func(channel ssh.Channel, requests <-chan *ssh.Request) {
		ctx, canc := context.WithCancel(context.Background())
		defer canc()
		s := session{channel: channel}
		for req := range requests {
			if err := s.request(ctx, req); err != nil {
				log.Printf("request(%q): %v", req.Type, err)
				errmsg := []byte(err.Error())
				// Append a trailing newline; the error message is
				// displayed as-is by ssh(1).
				if errmsg[len(errmsg)-1] != '\n' {
					errmsg = append(errmsg, '\n')
				}
				req.Reply(false, errmsg)
				channel.Write(errmsg)
				channel.Close()
			}
		}
		log.Printf("requests exhausted")
	}(channel, requests)
}

func expandPath(env []string) []string {
	pwd, err := os.Getwd()
	if err != nil {
		return env
	}
	found := false
	for idx, val := range env {
		parts := strings.Split(val, "=")
		if len(parts) < 2 {
			continue // malformed entry
		}
		key := parts[0]
		if key != "PATH" {
			continue
		}
		val := strings.Join(parts[1:], "=")
		env[idx] = fmt.Sprintf("%s=%s:%s", key, pwd, val)
		found = true
	}
	if !found {
		const busyboxDefaultPATH = "/sbin:/usr/sbin:/bin:/usr/bin"
		env = append(env, fmt.Sprintf("PATH=%s:%s", pwd, busyboxDefaultPATH))
	}
	return env
}

type session struct {
	env     []string
	ptyf    *os.File
	ttyf    *os.File
	channel ssh.Channel
}

// ptyreq is a Pseudo-Terminal request as per RFC4254 6.2.
type ptyreq struct {
	TERM            string // e.g. vt100
	WidthCharacters uint32
	HeightRows      uint32
	WidthPixels     uint32
	HeightPixels    uint32
	Modes           string
}

// windowchange is a Window Dimension Change as per RFC4254 6.7.
type windowchange struct {
	WidthColumns uint32
	HeightRows   uint32
	WidthPixels  uint32
	HeightPixels uint32
}

// env is a Environment Variable request as per RFC4254 6.4.
type env struct {
	VariableName  string
	VariableValue string
}

// execR is a Command request as per RFC4254 6.5.
type execR struct {
	Command string
}

func findShell() string {
	if path, err := exec.LookPath("sh"); err == nil {
		return path
	}
	const wellKnownSerialShell = "/tmp/serial-busybox/ash"
	if _, err := os.Stat(wellKnownSerialShell); err == nil {
		return wellKnownSerialShell
	}
	return ""
}

func (s *session) request(ctx context.Context, req *ssh.Request) error {
	switch req.Type {
	case "pty-req":
		var r ptyreq
		if err := ssh.Unmarshal(req.Payload, &r); err != nil {
			return err
		}

		var err error
		s.ptyf, s.ttyf, err = pty.Open()
		if err != nil {
			return err
		}

		SetWinsize(s.ptyf.Fd(), r.WidthCharacters, r.HeightRows)
		// Responding true (OK) here will let the client
		// know we have a pty ready for input
		req.Reply(true, nil)

	case "window-change":
		var r windowchange
		if err := ssh.Unmarshal(req.Payload, &r); err != nil {
			return err
		}

		SetWinsize(s.ptyf.Fd(), r.WidthColumns, r.HeightRows)

	case "env":
		var r env
		if err := ssh.Unmarshal(req.Payload, &r); err != nil {
			return err
		}

		s.env = append(s.env, fmt.Sprintf("%s=%s", r.VariableName, r.VariableValue))

	case "shell":
		req.Payload = []byte("\x00\x00\x00\x02sh")
		fallthrough

	case "exec":
		var r execR
		if err := ssh.Unmarshal(req.Payload, &r); err != nil {
			return err
		}

		cmdline, err := shlex.Split(r.Command)
		if err != nil {
			return err
		}

		if cmdline[0] == "scp" {
			return scpSink(s.channel, req, cmdline)
		}

		var cmd *exec.Cmd
		if shell := findShell(); shell != "" {
			cmd = exec.CommandContext(ctx, shell, "-c", r.Command)
		} else {
			cmd = exec.CommandContext(ctx, cmdline[0], cmdline[1:]...)
		}
		log.Printf("Starting cmd %q", cmd.Args)
		cmd.Env = expandPath(s.env)
		cmd.SysProcAttr = &syscall.SysProcAttr{}

		if s.ttyf == nil {
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return err
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return err
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return err
			}
			cmd.SysProcAttr.Setsid = true

			if err := cmd.Start(); err != nil {
				return err
			}

			req.Reply(true, nil)

			go io.Copy(s.channel, stdout)
			go io.Copy(s.channel.Stderr(), stderr)
			go func() {
				io.Copy(stdin, s.channel)
				stdin.Close()
			}()

			go func() {
				if err := cmd.Wait(); err != nil {
					log.Printf("err: %v", err)
				}
				status := make([]byte, 4)
				if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
					binary.BigEndian.PutUint32(status, uint32(ws.ExitStatus()))
				}

				// See https://tools.ietf.org/html/rfc4254#section-6.10
				if _, err := s.channel.SendRequest("exit-status", false /* wantReply */, status); err != nil {
					log.Printf("err2: %v", err)
				}
				s.channel.Close()
			}()
			return nil
		}

		defer func() {
			s.ttyf.Close()
			s.ttyf = nil
		}()

		cmd.Stdout = s.ttyf
		cmd.Stdin = s.ttyf
		cmd.Stderr = s.ttyf
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Setsid = true

		if err := cmd.Start(); err != nil {
			s.ptyf.Close()
			s.ptyf = nil
			return err
		}

		close := func() {
			s.channel.Close()
			cmd.Process.Wait()
		}

		// pipe session to cmd and vice-versa
		var once sync.Once
		go func() {
			io.Copy(s.channel, s.ptyf)
			once.Do(close)
		}()
		go func() {
			io.Copy(s.ptyf, s.channel)
			once.Do(close)
		}()

		req.Reply(true, nil)

	default:
		return fmt.Errorf("unknown request type: %q", req.Type)
	}

	return nil
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
