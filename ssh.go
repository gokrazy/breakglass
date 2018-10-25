package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/shlex"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %q", t))
		return
	}

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

func stringFromPayload(payload []byte, offset int) (string, int, error) {
	if got, want := len(payload), offset+4; got < want {
		return "", 0, fmt.Errorf("request payload too short: got %d, want >= %d", got, want)
	}
	namelen := binary.BigEndian.Uint32(payload[offset : offset+4])
	if got, want := len(payload), offset+4+int(namelen); got < want {
		return "", 0, fmt.Errorf("request payload too short: got %d, want >= %d", got, want)
	}
	name := payload[offset+4 : offset+4+int(namelen)]
	return string(name), offset + 4 + int(namelen), nil
}

func (s *session) request(ctx context.Context, req *ssh.Request) error {
	switch req.Type {
	case "pty-req":
		var err error
		s.ptyf, s.ttyf, err = pty.Open()
		if err != nil {
			return err
		}
		_, next, err := stringFromPayload(req.Payload, 0)
		if err != nil {
			return err
		}
		if got, want := len(req.Payload), next+4+4; got < want {
			return fmt.Errorf("request payload too short: got %d, want >= %d", got, want)
		}

		w, h := parseDims(req.Payload[next:])
		SetWinsize(s.ptyf.Fd(), w, h)
		// Responding true (OK) here will let the client
		// know we have a pty ready for input
		req.Reply(true, nil)

	case "window-change":
		w, h := parseDims(req.Payload)
		SetWinsize(s.ptyf.Fd(), w, h)

	case "env":
		name, next, err := stringFromPayload(req.Payload, 0)
		if err != nil {
			return err
		}

		value, _, err := stringFromPayload(req.Payload, next)
		if err != nil {
			return err
		}

		s.env = append(s.env, fmt.Sprintf("%s=%s", name, value))

	case "shell":
		req.Payload = []byte("\x00\x00\x00\x00sh")
		fallthrough

	case "exec":
		if got, want := len(req.Payload), 4; got < want {
			return fmt.Errorf("exec request payload too short: got %d, want >= %d", got, want)
		}

		cmdline, err := shlex.Split(string(req.Payload[4:]))
		if err != nil {
			return err
		}

		if cmdline[0] == "scp" {
			return scpSink(s.channel, req, cmdline)
		}

		var cmd *exec.Cmd
		if _, err := exec.LookPath("sh"); err == nil {
			cmd = exec.CommandContext(ctx, "sh", "-c", string(req.Payload[4:]))
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

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
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
