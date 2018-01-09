package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"bitbucket.org/shu/gli"
	"bitbucket.org/shu/rog"
	"golang.org/x/sys/windows"
	//"github.com/golang/sys/windows"
)

type (
	Process struct {
		ID       uint32
		Name     string
		ParentID uint32
	}
	ProcessDict map[uint32]*Process // pid -> &Process{} of pid

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

	verbose = rog.Discard
)

const (
	INFINITE     = 0xFFFFFFFF
	SYNCHRONIZE  = 0x00100000
	WAIT_TIMEOUT = 0x00000102

	TH32CS_SNAPPROCESS = 0x00000002
)

func ListWindows(names []string, allProcs ProcessDict) ([]*Window, error) {
	var wins []*Window

	cb := syscall.NewCallback(func(hwnd syscall.Handle, lparam uintptr) uintptr {
		b, _, _ := isWindow.Call(uintptr(hwnd))
		if b == 0 {
			return 1
		}

		tlen, _, _ := getWindowTextLength.Call(uintptr(hwnd))
		if tlen == 0 {
			return 1
		}
		tlen++
		buff := make([]uint16, tlen)
		getWindowText.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&buff[0])),
			uintptr(tlen),
		)
		title := syscall.UTF16ToString(buff)

		matches := false
		if len(names) == 0 {
			matches = true
		} else {
			if testMatch(title, names) {
				matches = true
			}
		}
		if !matches {
			return 1
		}

		var processID uintptr
		getWindowThreadProcessId.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&processID)),
		)

		p, found := allProcs[uint32(processID)]
		if !found {
			p = nil
		}
		wins = append(wins, &Window{Process: p, Title: title})

		return 1
	})

	a, _, _ := enumWindows.Call(cb, 0)
	if a == 0 {
		return nil, fmt.Errorf("USER32.EnumWindows returned FALSE")
	}

	return wins, nil
}

func MakeProcessDict(procs []*Process) ProcessDict {
	dict := make(ProcessDict)

	for _, p := range procs {
		dict[p.ID] = p
	}

	return dict
}

func ListProcesses(names []string) ([]*Process, error) {
	var procs []*Process

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
		p := &Process{ID: pe.ProcessID, ParentID: pe.ParentProcessID, Name: syscall.UTF16ToString(pe.ExeFile[:])}

		matches := false
		if len(names) == 0 {
			matches = true
		} else {
			if testMatch(p.Name, names) {
				matches = true
			}
		}
		if matches {
			procs = append(procs, p)
		}

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}
	windows.CloseHandle(snapshot)

	return procs, nil
}

func ListParentProcesseDict(all ProcessDict) ProcessDict {
	dict := make(ProcessDict)

	var curr uint32 = uint32(syscall.Getpid())
	for {
		p, found := all[curr]
		if !found {
			break
		}

		dict[curr] = p
		curr = p.ParentID
	}

	return dict
}

func testMatch(tgt string, names []string) bool {
	for _, name := range names {
		if strings.Contains(strings.ToUpper(tgt), strings.ToUpper(name)) {
			return true
		}
	}
	return false
}

func (w *Window) Format(format string) string {
	output := format
	if w.Process == nil {
		output = strings.Replace(output, "{PID}", "", -1)
		output = strings.Replace(output, "{PROCESS}", "", -1)
	} else {
		output = strings.Replace(output, "{PID}", fmt.Sprintf("%d", w.Process.ID), -1)
		output = strings.Replace(output, "{PROCESS}", w.Process.Name, -1)
	}
	output = strings.Replace(output, "{TITLE}", w.Title, -1)
	return output
}

func (p *Process) Format(format string) string {
	output := format
	output = strings.Replace(output, "{PID}", fmt.Sprintf("%d", p.ID), -1)
	output = strings.Replace(output, "{PROCESS}", p.Name, -1)
	output = strings.Replace(output, "{TITLE}", "", -1)
	return output
}

func main() {
	app := gli.New(&globalCmd{})
	app.Name = "obit"
	app.Desc = "obituary notifier via stdout"
	app.Version = "0.2.0"
	app.Usage = `obit {window title or process name, waited for its end}`
	app.Copyright = "(C) 2017 Shuhei Kubota"

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(-1)
	}
}

type globalCmd struct {
	Verbose bool `help:"verbose output to stderr"`

	Target string `cli:"target, t"  default:"wp"  help:"target: 'w' for windows, 'p' for processes"`
	Format string `cli:"format, f"  default:"{TITLE}({PROCESS})"  help:"format of stdout"`

	Timeout int  `default:"-1"  help:"timeout in milliseconds (negative is INFINITE)"`
	Last    bool `cli:"last, l"  help:"output to stdout only when all processes exit, without process info"`
}

/*
func list(c *cli.Context) error {
	var wins []*Window
	var procs []*Process
	var err error

	names := c.Args()
	if len(names) == 0 {
		names = nil
	}

	var procDict ProcessDict
	{
		allProcs, err := ListProcesses(nil)
		if err != nil {
			return fmt.Errorf("failed to list processes: %v", err)
		}
		procDict = MakeProcessDict(allProcs)
	}

	if strings.Contains(g.Target, "w") {
		wins, err = ListWindows(names, procDict)
		if err != nil {
			return fmt.Errorf("failed to list windows (%q): %v", names, err)
		}
		///log.Printf("%#v", wins)
		sort.Slice(wins, func(i, j int) bool {
			// sort by Process.Name, Title
			w1 := wins[i]
			w2 := wins[j]
			if w1.Process == nil {
				return true
			} else if w2.Process == nil {
				return false
			} else if w1.Process.Name < w2.Process.Name {
				return true
			} else if w1.Process.Name > w2.Process.Name {
				return false
			} else {
				return w1.Title < w2.Title
			}
		})

	}
	if strings.Contains(g.Target, "p") {
		procs, err = ListProcesses(names)
		if err != nil {
			return fmt.Errorf("failed to list processes: %v", err)
		}
		sort.Slice(procs, func(i, j int) bool {
			// sort by Name
			return procs[i].Name < procs[j].Name
		})
	}

	if len(wins)+len(procs) == 0 {
		if g.Verbose {
			fmt.Printf("no result for %q\n", names)
		}
		return nil
	}

	// output merging wins and procs
	var wi int
	var pi int
	for {
		if wi >= len(wins) && pi >= len(procs) {
			break
		}

		// proc1
		// proc1 window1
		// proc1 window2
		// proc2 window1
		// proc3

		var win *Window
		if wi < len(wins) {
			win = wins[wi]
		}
		var proc *Process
		if pi < len(procs) {
			proc = procs[pi]
		}

		procOutput := true // false for window output

		if proc != nil {
			if win == nil || win.Process == nil {
				procOutput = true
			} else {
				if proc.Name <= win.Process.Name {
					procOutput = true
				} else {
					procOutput = false
				}
			}
		} else {
			procOutput = false
		}

		if procOutput && proc == nil || !procOutput && win == nil {
			break
		}

		var output string
		///log.Printf("%v for %#v", procOutput, win)
		if procOutput {
			output = proc.Format(g.Format)
			pi++
		} else {
			output = win.Format(g.Format)
			wi++
		}

		fmt.Printf("%s\n", output)
	}

	return nil
}
*/

func (g globalCmd) Run(args []string) error {
	var wins []*Window
	var procs []*Process
	var err error

	names := args
	if len(names) == 0 {
		names = nil
	}

	var allProcs ProcessDict
	{
		a, err := ListProcesses(nil)
		if err != nil {
			return fmt.Errorf("failed to list processes: %v", err)
		}
		allProcs = MakeProcessDict(a)
	}

	if strings.Contains(g.Target, "w") {
		wins, err = ListWindows(names, allProcs)
		if err != nil {
			return fmt.Errorf("failed to list windows (%q): %v", names, err)
		}
	}

	if strings.Contains(g.Target, "p") {
		procs, err = ListProcesses(names)
		if err != nil {
			return fmt.Errorf("failed to list processes: %v", err)
		}
	}

	if len(wins)+len(procs) == 0 {
		if g.Verbose {
			fmt.Printf("no result for %q\n", names)
		}
		return nil
	}

	targetProcessDict := make(ProcessDict)
	for _, p := range procs {
		targetProcessDict[p.ID] = p
	}
	for _, w := range wins {
		if w.Process == nil {
			continue
		}
		targetProcessDict[w.Process.ID] = w.Process
	}

	ignoredProcesseDict := ListParentProcesseDict(allProcs)

	if g.Verbose {
		verbose.Printf("%d Windows\n", len(wins))
		verbose.Printf("%d Processes\n", len(procs))

		verbose.Printf("target windows:\n")
		for _, v := range wins {
			verbose.Printf("  %s\n", v.Format(g.Format))
		}
		verbose.Printf("target processes:\n")
		for _, v := range procs {
			verbose.Printf("  %s\n", v.Format(g.Format))
		}

		verbose.Printf("ignored processes (%v):\n", uint32(syscall.Getpid()))
		for _, v := range ignoredProcesseDict {
			verbose.Printf("  %s\n", v.Format(g.Format))
		}

		if g.Last {
			verbose.Printf("output to stdout is going to do at last\n")
		}
	}

	for k, _ := range ignoredProcesseDict {
		delete(targetProcessDict, k)
	}

	if len(targetProcessDict) == 0 {
		if g.Verbose {
			fmt.Printf("no result for %q\n", names)
		}
		return nil
	}

	wg := sync.WaitGroup{}
	for pid, p := range targetProcessDict {
		verbose.Printf("waiting for %s\n", p.Format(g.Format))

		wg.Add(1)
		go func(pid uint32, p *Process) {
			hProcess, err := windows.OpenProcess(
				SYNCHRONIZE,
				false,
				pid,
			)
			if err != nil {
				//continue
				wg.Done()
				fmt.Fprintf(os.Stderr, "failed to wait for %v: %v\n", p.Format(g.Format), err)
				return
			}
			if hProcess != 0 {
				event, _ := windows.WaitForSingleObject(
					hProcess,
					uint32(g.Timeout),
				)
				windows.CloseHandle(hProcess)

				if event == WAIT_TIMEOUT {
					verbose.Printf("timed out: %s\n", p.Format(g.Format))
				} else {
					// output window info
					if strings.Contains(g.Target, "w") {
						for _, w := range wins {
							if w.Process == nil || w.Process.ID != pid {
								continue
							}

							if !testMatch(w.Title, names) {
								continue
							}

							if !g.Last {
								fmt.Fprintf(os.Stdout, "%s\n", w.Format(g.Format))
							}
						}
					}

					// output process info
					if strings.Contains(g.Target, "p") {
						if !g.Last {
							if testMatch(p.Name, names) {
								fmt.Fprintf(os.Stdout, "%s\n", p.Format(g.Format))
							}
						}
					}
				}

				wg.Done()
			}
		}(pid, p)
	}
	wg.Wait()

	if g.Last {
		fmt.Fprintf(os.Stdout, "All processes exited: %q\n", names)
	}

	return nil
}

func (g globalCmd) Before() {
	if g.Verbose {
		verbose = rog.New(os.Stderr, "", 0)
	}
}
