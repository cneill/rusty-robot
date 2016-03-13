package main

import (
	"testing"

	//"github.com/codegangsta/cli"
)

func TestHostArgParsing(t *testing.T) {
	test_args := []string{"run", "-h", "irc.derpderp.net"}
	ParseArgs(test_args)
	if RC.Host != "irc.derpderp.net" {
		t.Fail()
	}
}
