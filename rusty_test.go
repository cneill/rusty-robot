package main

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	//"github.com/codegangsta/cli"
)

func assertEqual(t *testing.T, expected interface{}, received interface{}) {
	if expected != received {
		fmt.Printf("\nEXPECTED: %v\nRECEIVED: %v\n\n", expected, received)
		t.Fail()
	}
}

func assertContains(t *testing.T, stack map[string]bool, needle string) {
	for key, _ := range stack {
		if needle == key {
			return
		}
	}
	fmt.Printf("\nDIDN'T FIND %v IN %v\n\n", needle, stack)
	t.Fail()
}

// Test config file parsing

var test_conf_args = []string{os.Args[0], "-C", "./tests/test-rusty.rc", "test"}

func TestHostConfParsing(t *testing.T) {
	expected := "irc.freenode.net"
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.Host)
}

func TestPortConfParsing(t *testing.T) {
	expected := 6697
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.Port)
}

func TestNickConfParsing(t *testing.T) {
	expected := "rusty42"
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.Nick)
}

func TestChannelConfParsing(t *testing.T) {
	expected := "#inventropy"
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.Channel)
}

func TestOwnerConfParsing(t *testing.T) {
	expected := "bluffinpuffin"
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.Owner)
}

func TestGooglAPIKeyConfParsing(t *testing.T) {
	expected := "TEST_GOOGL_API_KEY"
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.GooglAPIKey)
}

func TestVTAPIKeyConfParsing(t *testing.T) {
	expected := "TEST_VT_API_KEY"
	SetupApp(test_conf_args)
	assertEqual(t, expected, RC.VTAPIKey)
}

func TestOpConfParsing(t *testing.T) {
	expected := "test-op"
	SetupApp(test_conf_args)
	assertContains(t, RC.Ops, expected)
}

func TestMockingConfParsing(t *testing.T) {
	expected := "test-mock"
	SetupApp(test_conf_args)
	assertContains(t, RC.Mocking, expected)
}

func TestAuthedConfParsing(t *testing.T) {
	expected := "test-authed"
	SetupApp(test_conf_args)
	assertContains(t, RC.Authed, expected)
}

// Test cli arg parsing

func TestHostArgParsing(t *testing.T) {
	expected := "irc.derpderp.net"
	SetupApp([]string{os.Args[0], "-C", "/dev/null", "test", "--host", expected})
	assertEqual(t, expected, RC.Host)
}

func TestPortArgParsing(t *testing.T) {
	expected := "7777"
	SetupApp([]string{os.Args[0], "-C", "/dev/null", "test", "--port", expected})
	assertEqual(t, expected, strconv.Itoa(RC.Port))
}

func TestNickArgParsing(t *testing.T) {
	expected := "test-nick"
	SetupApp([]string{os.Args[0], "-C", "/dev/null", "test", "--nick", expected})
	assertEqual(t, expected, RC.Nick)
}

func TestChannelArgParsing(t *testing.T) {
	expected := "#test-channel"
	SetupApp([]string{os.Args[0], "-C", "/dev/null", "test", "--channel", expected})
	assertEqual(t, expected, RC.Channel)
}
