package logging

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	var logger = New("tag")
	if logger.tag != "tag" {
		t.Errorf("tag should be tag but %v", logger.tag)
	}
}

func TestSetLogLevel(t *testing.T) {
	SetLogLevel(INFO)
	if logLv != INFO {
		t.Errorf("tag should be tag but %v", logLv.String())
	}
}

func TestLogf(t *testing.T) {
	SetLogLevel(TRACE)

	w := new(bytes.Buffer)
	SetOutput(w)

	var logger = New("tag")

	logger.Fatalf("This is critical log: %v", time.Now())
	expected := "This is critical log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Errorf("This is error log: %v", time.Now())
	expected = "This is error log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Warningf("This is warning log: %v", time.Now())
	expected = "This is warning log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Infof("This is info log: %v", time.Now())
	expected = "This is info log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Infof("This is debug log: %v", time.Now())
	expected = "This is debug log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Tracef("This is trace log: %v", time.Now())
	expected = "This is trace log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}
}

func TestInfof(t *testing.T) {
	SetLogLevel(INFO)

	w := new(bytes.Buffer)
	SetOutput(w)

	var logger = New("tag")

	logger.Fatalf("This is critical log: %v", time.Now())
	expected := "This is critical log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Errorf("This is error log: %v", time.Now())
	expected = "This is error log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Warningf("This is warning log: %v", time.Now())
	expected = "This is warning log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Infof("This is info log: %v", time.Now())
	expected = "This is info log"
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Infof("This is debug log: %v", time.Now())
	expected = ""
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}

	logger.Tracef("This is trace log: %v", time.Now())
	expected = ""
	if !strings.Contains(w.String(), expected) {
		t.Errorf("expected %q to eq %q", w.String(), expected)
	}
}
