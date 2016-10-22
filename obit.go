package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	//"github.com/golang/sys/windows"
)

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	isWindow                 = user32.NewProc("IsWindow")
	enumWindows              = user32.NewProc("EnumWindows")
	getWindowText            = user32.NewProc("GetWindowTextW")
	getWindowTextLength      = user32.NewProc("GetWindowTextLengthW")
	getWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")

	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	//-> use windows.XXX
)

const (
	INFINITE    = 0xFFFFFFFF
	SYNCHRONIZE = 0x00100000

	TH32CS_SNAPPROCESS = 0x00000002
)

func ListParentProcesses() ([]int, error) {
	p2pp := make(map[uint32]uint32) //pid -> parent of pid

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	pe := windows.ProcessEntry32{}
	pe.Size = uint32(unsafe.Sizeof(pe))
	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		return nil, err
	}
	for {
		p2pp[pe.ProcessID] = pe.ParentProcessID
		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}
	windows.CloseHandle(snapshot)

	list := make([]int, 0, 2)

	curr := syscall.Getpid()
	list = append(list, curr)
	for {
		list = append(list, curr)

		if curru32, ok := p2pp[uint32(curr)]; ok {
			curr = int(curru32)
		} else {
			break
		}
	}

	return list, nil
}

func main() {
	var verbose bool
	var target string
	var wait uint32
	var format string

	var targetFlag string
	var waitFlag int
	var formatFlag string
	flag.BoolVar(&verbose, "v", false, "Verbose output to stderr.")
	flag.StringVar(&targetFlag, "t", "", "Title of the target window. sub-match for each space-separated words.")
	flag.IntVar(&waitFlag, "w", -1, "Wait in milliseconds. (negative is INFINITE)")
	flag.StringVar(&formatFlag, "f", "{PID} {TITLE}", "Format of stdout (default to '{PID} {TITLE}')")

	flag.Parse()

	if targetFlag == "" {
		fmt.Fprintf(os.Stderr, "-t is required.\n")
		os.Exit(-1)
	} else {
		target = targetFlag
	}
	if waitFlag < 0 {
		wait = INFINITE
	} else {
		wait = uint32(waitFlag)
	}
	format = formatFlag

	ignoreList, err := ListParentProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list processes: %v\n", err)
		os.Exit(-1)
	}
	if verbose {
		for _, elem := range ignoreList {
			fmt.Fprintf(os.Stderr, "ignore: %v\n", elem)
		}
	}

	cb := syscall.NewCallback(func(hwnd syscall.Handle, lparam uintptr) uintptr {
		b, _, _ := isWindow.Call(uintptr(hwnd))
		if b == 0 {
			return 1
		}

		len, _, _ := getWindowTextLength.Call(uintptr(hwnd))
		if len == 0 {
			return 1
		}
		len++
		buff := make([]uint16, len)
		getWindowText.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&buff[0])),
			uintptr(len),
		)
		title := syscall.UTF16ToString(buff)

		if !strings.Contains(title, target) {
			return 1
		}

		var processID uintptr
		getWindowThreadProcessId.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&processID)),
		)

		// skip its self and its parents
		for _, elem := range ignoreList {
			if elem == int(processID) {
				return 1
			}
		}

		hProcess, err := windows.OpenProcess(
			SYNCHRONIZE,
			false,
			uint32(processID),
		)
		if err != nil {
			return 1
		}
		if hProcess != 0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "'%v' -> %v -> %v\n", title, processID, hProcess)
			}
			windows.WaitForSingleObject(
				hProcess,
				wait,
			)
			windows.CloseHandle(hProcess)

			out := format
			out = strings.Replace(out, "{PID}", fmt.Sprintf("%v", processID), -1)
			out = strings.Replace(out, "{TITLE}", title, -1)
			fmt.Fprintln(os.Stdout, out)
		}

		return 1
	})

	a, _, _ := enumWindows.Call(cb, 0)
	if a == 0 {
		fmt.Fprintf(os.Stderr, "USER32.EnumWindows returned FALSE")
		os.Exit(-1)
	}
}
