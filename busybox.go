package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const wellKnownBusybox = "/usr/local/bin/busybox"

// mountBin bind-mounts /bin to a tmpfs.
func mountBin() error {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		mountpoint := parts[4]
		log.Printf("Found mountpoint %q", parts[4])
		if mountpoint == "/bin" {
			log.Printf("/bin file system already mounted, nothing to do")
			return nil
		}
	}

	if err := syscall.Mount("tmpfs", "/bin", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mounting tmpfs on /bin: %v", err)
	}

	return nil
}

func installBusybox() error {
	// /bin is read-only by default, so mount a tmpfs over it
	if err := mountBin(); err != nil {
		return err
	}

	install := exec.Command(wellKnownBusybox, "--install", "-s", "/bin")
	install.Stdout = os.Stdout
	install.Stderr = os.Stderr
	if err := install.Run(); err != nil {
		return fmt.Errorf("%v: %v", install.Args, err)
	}
	return nil
}
