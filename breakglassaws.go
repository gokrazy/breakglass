// Code for interacting with AWS EC2.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// getEC2MetadataToken returns an IMDSv2 token from the AWS EC2 metadata
// server. This is needed for subsequent metadata requests, at least when
// the VM was created in IMDSv2-required mode, as is common.
//
// See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
func getEC2MetadataToken() (string, error) {
	req, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	req.Header.Add("X-aws-ec2-metadata-token-ttl-seconds", "300")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get metadata token: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("failed to get metadata token: %v", res.Status)
	}
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata token: %w", err)
	}
	return strings.TrimSpace(string(all)), nil
}

// loadAWSEC2SSHKeys returns 1 or more SSH public keys from the AWS
// EC2 metadata server and returns them concatenanted, one per line,
// as if they were all together in an ~/.ssh/authorized_keys file.
//
// See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#instance-metadata-ex-5
func loadAWSEC2SSHKeys() ([]byte, error) {
	token, err := getEC2MetadataToken()
	if err != nil {
		return nil, err
	}
	var authorizedKeys bytes.Buffer
	getKeyIndex := func(idx int) error {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://169.254.169.254/latest/meta-data/public-keys/%d/openssh-key", idx), nil)
		req.Header.Add("X-aws-ec2-metadata-token", token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return errors.New(res.Status)
		}
		all, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		// Write out a ~/.ssh/authorized_keys -looking file,
		// with each key on its own line.
		fmt.Fprintf(&authorizedKeys, "%s\n", bytes.TrimSpace(all))
		return nil
	}
	for i := 0; ; i++ {
		err := getKeyIndex(i)
		if err == nil {
			continue
		}
		if i == 0 {
			// We expect at least one SSH key (index 0) if the
			// use requested this mode, so return an error if the
			// first one fails.
			return nil, err
		}
		// But on subsequent errors, just assume we've hit the end.
		// This is a little lazy.
		break
	}
	return authorizedKeys.Bytes(), nil
}
