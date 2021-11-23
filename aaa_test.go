package aaa

import "testing"

func TestDebug_Print(t *testing.T) {
	Print("aaa\n")
}

func TestDebug_Printf(t *testing.T) {
	Printf("%s\n", "aaa")
}

func TestDebug_Println(t *testing.T) {
	Println("aaa")
}
