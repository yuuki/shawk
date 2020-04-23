package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/yuuki/shawk/version"
)

func TestRun_version(t *testing.T) {
	outStream, errStream := new(bytes.Buffer), new(bytes.Buffer)
	cli := &CLI{outStream: outStream, errStream: errStream}
	args := strings.Split("shawk version", " ")

	status := cli.Run(args)
	if status != 0 {
		t.Errorf("expected %d to eq %d", status, exitCodeOK)
	}

	expected := fmt.Sprintf("shawk version %s", version.GetVersion())
	if !strings.Contains(errStream.String(), expected) {
		t.Errorf("expected %q to contain %q", expected, errStream.String())
	}
}

func TestRun_parseError(t *testing.T) {
	outStream, errStream := new(bytes.Buffer), new(bytes.Buffer)
	cli := &CLI{outStream: outStream, errStream: errStream}
	args := strings.Split("shawk --nonexistent", " ")

	status := cli.Run(args)
	if status != exitCodeErr {
		t.Errorf("expected %d to eq %d", status, exitCodeErr)
	}

	expected := "Usage: shawk"
	if !strings.Contains(errStream.String(), expected) {
		t.Errorf("expected %q to contain %q", expected, errStream.String())
	}
}

func TestRun_noCommandError(t *testing.T) {
	outStream, errStream := new(bytes.Buffer), new(bytes.Buffer)
	cli := &CLI{outStream: outStream, errStream: errStream}
	args := strings.Split("shawk nonexistent", " ")

	status := cli.Run(args)
	if status != exitCodeErr {
		t.Errorf("expected %d to eq %d", status, exitCodeErr)
	}

	expected := "No such sub command"
	if !strings.Contains(errStream.String(), expected) {
		t.Errorf("expected %q to contain %q", expected, errStream.String())
	}
}

func TestRun_lookError(t *testing.T) {
	outStream, errStream := new(bytes.Buffer), new(bytes.Buffer)
	cli := &CLI{outStream: outStream, errStream: errStream}
	args := strings.Split("shawk look --depth 100", " ")

	status := cli.Run(args)
	if status != exitCodeErr {
		t.Errorf("expected %d to eq %d", status, exitCodeErr)
	}

	expected := "depth must be 0 < depth"
	if !strings.Contains(errStream.String(), expected) {
		t.Errorf("expected %q to contain %q", expected, errStream.String())
	}
}
