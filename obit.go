package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	//"github.com/golang/sys/windows"
)

type (
	Process struct {
		ID       uint32
		Name     string
		ParentID uint32
	}
	ProcessSet map[uint32]*Process // pid -> &Process{} of pid

	Window struct {
		Process *Process
		Title   string
	}
	ProcessWndMap map[uint32][]*Window // pid -> &Window{}
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

func ListProcesses() (ProcessSet, error) {
	set := make(ProcessSet)

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
		set[pe.ProcessID] = &Process{ID: pe.ProcessID, ParentID: pe.ParentProcessID, Name: syscall.UTF16ToString(pe.ExeFile[:])}

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}
	windows.CloseHandle(snapshot)

	return set, nil
}

func ListParentProcesses(all ProcessSet) ProcessSet {

	set := make(ProcessSet)

	var curr uint32 = uint32(syscall.Getpid())
	for {
		p, found := all[curr]
		if !found {
			break
		}

		set[curr] = p
		curr = p.ParentID
	}

	return set
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
	flag.StringVar(&formatFlag, "f", "{TITLE}({PROCESS})", "Format of stdout (default to '{TITLE}({PROCESS})')")

	flag.Parse()

	if targetFlag == "" {
		if flag.NArg() > 0 {
			target = strings.Join(flag.Args()[1:], " ")
		} else {
			fmt.Fprintf(os.Stderr, "-t is required.\n")
			os.Exit(-1)
		}
	} else {
		target = targetFlag
	}
	if waitFlag < 0 {
		wait = INFINITE
	} else {
		wait = uint32(waitFlag)
	}
	format = formatFlag

	// start listing

	allProcesses, err := ListProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list processes: %v\n", err)
		os.Exit(-1)
	}

	ignoredProcesses := ListParentProcesses(allProcesses)
	if verbose {
		for _, p := range ignoredProcesses {
			fmt.Fprintf(os.Stderr, "ignore: %v\n", p)
		}
	}

	//

	targetProcesseSet := make(ProcessSet)
	targetWindowMap := make(ProcessWndMap)

	// enum target processes

	for _, p := range allProcesses {
		matched := true
		for _, w := range strings.Split(target, " ") {
			if !strings.Contains(strings.ToUpper(p.Name), strings.ToUpper(w)) {
				matched = false
				break
			}
		}

		if matched {
			targetProcesseSet[p.ID] = p
		}
	}

	// enum windows and wait it if needed

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

		for _, w := range strings.Split(target, " ") {
			if !strings.Contains(strings.ToUpper(title), strings.ToUpper(w)) {
				return 1
			}
		}

		var processID uintptr
		getWindowThreadProcessId.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&processID)),
		)

		// skip its self and its parents
		if _, found := ignoredProcesses[uint32(processID)]; found {
			return 1
		}

		// add to targetProcesseSet

		if p, found := allProcesses[uint32(processID)]; found {
			targetProcesseSet[p.ID] = p

			if _, found := targetWindowMap[p.ID]; !found {
				targetWindowMap[p.ID] = make([]*Window, 0, 1)
			}
			targetWindowMap[p.ID] = append(targetWindowMap[p.ID], &Window{Process: p, Title: title})
		}

		return 1
	})

	a, _, _ := enumWindows.Call(cb, 0)
	if a == 0 {
		fmt.Fprintf(os.Stderr, "USER32.EnumWindows returned FALSE")
		os.Exit(-1)
	}

	wg := sync.WaitGroup{}

	for processID, p := range targetProcesseSet {
		wg.Add(1)
		go func(processID uint32, p *Process) {
			hProcess, err := windows.OpenProcess(
				SYNCHRONIZE,
				false,
				processID,
			)
			if err != nil {
				//continue
				wg.Done()
				return
			}
			if hProcess != 0 {
				if verbose {
					if w, found := targetWindowMap[processID]; found {
						fmt.Fprintf(os.Stderr, "'%v' -> '%v' -> %v\n", w[0].Title, p.Name, processID)
					} else {
						fmt.Fprintf(os.Stderr, "'%v' -> %v\n", p.Name, processID)
					}
				}
				windows.WaitForSingleObject(
					hProcess,
					wait,
				)
				windows.CloseHandle(hProcess)

				out := format
				out = strings.Replace(out, "{PID}", fmt.Sprintf("%v", processID), -1)
				out = strings.Replace(out, "{PROCESS}", p.Name, -1)
				if strings.Contains(out, "{TITLE}") {
					if w, found := targetWindowMap[processID]; found {
						out = strings.Replace(out, "{TITLE}", w[0].Title, -1)
					} else {
						out = strings.Replace(out, "{TITLE}", "", -1)
					}
				}
				//out = strings.Replace(out, "{PROCESS}", , -1)
				fmt.Fprintln(os.Stdout, out)

				wg.Done()
			}
		}(processID, p)
	}
	wg.Wait()
}
