package aaa

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	logFilepath = "/tmp/debug.txt"
)

var ch = make(chan string, 1024)

func init() {
	go func() {
		f, err := os.OpenFile(logFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		for line := range ch {
			if _, err := fmt.Fprint(f, line); err != nil {
				panic(err)
			}
		}
	}()
}

func Print(a ...interface{}) {
	pid := os.Getpid()
	goid := getGoId()
	_, file, line, _ := runtime.Caller(1)

	buf := bytes.NewBuffer(make([]byte, 0))
	fmt.Fprintf(buf, "[%s %d:%d %s:%d] ",
		time.Now().Format("2006-01-02 15:04:05.000000"), pid, goid, chopPath(file), line)
	fmt.Fprint(buf, a...)

	ch <- buf.String()
}

func Printf(format string, a ...interface{}) {
	pid := os.Getpid()
	goid := getGoId()
	_, file, line, _ := runtime.Caller(1)

	buf := bytes.NewBuffer(make([]byte, 0))
	fmt.Fprintf(buf, "[%s %d:%d %s:%d] ",
		time.Now().Format("2006-01-02 15:04:05.000000"), pid, goid, chopPath(file), line)
	fmt.Fprintf(buf, format, a...)

	ch <- buf.String()
}

func Println(a ...interface{}) {
	pid := os.Getpid()
	goid := getGoId()
	_, file, line, _ := runtime.Caller(1)

	buf := bytes.NewBuffer(make([]byte, 0))
	fmt.Fprintf(buf, "[%s %d:%d %s:%d] ",
		time.Now().Format("2006-01-02 15:04:05.000000"), pid, goid, chopPath(file), line)
	fmt.Fprintln(buf, a...)

	ch <- buf.String()
}

func chopPath(original string) string {
	i := strings.LastIndex(original, "src/")
	if i == -1 {
		return original
	} else {
		return original[i+4:]
	}
}

func getGoId() int64 {
	var buf [64]byte
	length := runtime.Stack(buf[:], false)
	stack := buf[:length]
	stack = stack[len("goroutine "):]
	stack = stack[:bytes.IndexByte(stack, ' ')]
	goid, _ := strconv.ParseInt(string(stack), 10, 64)
	return goid
}
