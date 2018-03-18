package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"bitbucket.org/shu/clise"
	"bitbucket.org/shu/elapsed"
	"bitbucket.org/shu/gli"
	"bitbucket.org/shu/rog"
	"golang.org/x/sys/windows"
	//"github.com/golang/sys/windows"
)

type (
	process struct {
		ID       uint32
		ParentID uint32
		Name     string
	}
	processDict map[uint32]*process // pid -> &Process{} of pid

	window struct {
		Process *process
		Title   string
		Handle  windows.Handle
	}
)

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	getWindow                = user32.NewProc("GetWindow")
	isWindow                 = user32.NewProc("IsWindow")
	enumWindows              = user32.NewProc("EnumWindows")
	getWindowText            = user32.NewProc("GetWindowTextW")
	getWindowTextLength      = user32.NewProc("GetWindowTextLengthW")
	getWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")

	verbose = rog.Discard
	stdout  = rog.New(os.Stdout, "", 0)
	stderr  = rog.New(os.Stderr, "", 0)
)

const (
	winInfinite    = 0xFFFFFFFF
	winSynchronize = 0x00100000
	winWaitTimeout = 0x00000102

	winGWEnabledPopup = 6
)

func listWindows(names []string, allProcs processDict) ([]*window, error) {
	var wins []*window

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
			tlen,
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
		wins = append(wins, &window{Process: p, Title: title, Handle: windows.Handle(hwnd)})

		return 1
	})

	a, _, _ := enumWindows.Call(cb, 0)
	if a == 0 {
		return nil, fmt.Errorf("USER32.EnumWindows returned FALSE")
	}

	return wins, nil
}

func makeProcessDict(procs []*process) processDict {
	dict := make(processDict)

	for _, p := range procs {
		dict[p.ID] = p
	}

	return dict
}

func listProcesses(names []string) ([]*process, error) {
	var procs []*process

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
		p := &process{ID: pe.ProcessID, ParentID: pe.ParentProcessID, Name: syscall.UTF16ToString(pe.ExeFile[:])}

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

func listParentProcesseDict(all processDict) processDict {
	dict := make(processDict)

	var curr = uint32(syscall.Getpid())
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

func (w *window) format(format string) string {
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

func (p *process) Format(format string) string {
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
	app.Version = "0.3.0"
	app.Usage = `obit [--popup] {window title or process name, waited for its end}`
	app.Copyright = "(C) 2017 Shuhei Kubota"

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(-1)
	}
}

type globalCmd struct {
	Popup bool `help:"do not wait for obituary, but do for the window have a popup window"`

	Target string `cli:"target, t"  default:"wp"  help:"target: 'w' for windows, 'p' for processes"`
	Last   bool   `cli:"last, l"  help:"output to stdout only when all processes exit, without process info"`

	Timeout int `default:"-1"  help:"timeout in milliseconds (negative is INFINITE)"`

	Format string `cli:"format, f"  default:"{TITLE}({PROCESS})"  help:"format of stdout"`

	Verbose bool `help:"verbose output to stderr"`
}

func (g *globalCmd) Init() {
	if g.Timeout == -1 {
		g.Timeout = winInfinite
	}
}

// this func does not close hProcess
func waitForProcessEnd(hProcess windows.Handle, timeout int) (timedout bool) {
	event, err := windows.WaitForSingleObject(
		hProcess,
		uint32(timeout),
	)
	if err != nil {
		return false
	}

	return event == winWaitTimeout
}

func waitForWindowPopup(hWindow windows.Handle, timeout int) (timedout bool) {
	e := elapsed.Start()
	for {
		b, _, _ := isWindow.Call(uintptr(hWindow))
		if b == 0 {
			return false
		}

		p, _, _ := getWindow.Call(uintptr(hWindow), winGWEnabledPopup)
		if p != 0 && p != uintptr(hWindow) {
			verbose.Printf("p=%v, hWindow=%v\n", p, hWindow)
			break
		}

		if timeout > 0 && timeout < int(e.Elapsed()) {
			return true
		}

		time.Sleep(20 * time.Millisecond)
	}

	return false
}

func (g globalCmd) Run(args []string) error {
	var wins []*window
	var procs []*process
	var err error

	names := args
	if len(names) == 0 {
		return fmt.Errorf("specify window title or process name, waited for its end")
	}

	var allProcs processDict
	{
		a, aerr := listProcesses(nil)
		if aerr != nil {
			return fmt.Errorf("failed to list processes: %v", aerr)
		}
		allProcs = makeProcessDict(a)
	}

	if strings.Contains(g.Target, "w") {
		wins, err = listWindows(names, allProcs)
		if err != nil {
			return fmt.Errorf("failed to list windows (%q): %v", names, err)
		}
	}

	if strings.Contains(g.Target, "p") {
		procs, err = listProcesses(names)
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

	targetProcessDict := make(processDict)
	for _, p := range procs {
		targetProcessDict[p.ID] = p
	}
	for _, w := range wins {
		if w.Process == nil {
			continue
		}
		targetProcessDict[w.Process.ID] = w.Process
	}

	ignoredProcesseDict := listParentProcesseDict(allProcs)

	for k := range ignoredProcesseDict {
		delete(targetProcessDict, k)
	}
	clise.Filter(&procs, func(i int) bool {
		id := procs[i].ID
		_, found := ignoredProcesseDict[id]
		return !found
	})
	clise.Filter(&wins, func(i int) bool {
		id := wins[i].Process.ID
		_, found := ignoredProcesseDict[id]
		return !found
	})

	if len(targetProcessDict) == 0 {
		if g.Verbose {
			fmt.Printf("no result for %q\n", names)
		}
		return nil
	}

	if g.Verbose {
		verbose.Printf("%d Windows\n", len(wins))
		if len(wins) != 0 {
			for _, v := range wins {
				verbose.Printf("    %s\n", v.format(g.Format))
			}
		}

		verbose.Printf("%d Processes\n", len(procs))
		if len(procs) != 0 {
			for _, v := range procs {
				verbose.Printf("    %s\n", v.Format(g.Format))
			}
		}

		/*
			verbose.Printf("ignored processes (%v):\n", uint32(syscall.Getpid()))
			for _, v := range ignoredProcesseDict {
				verbose.Printf("  %s\n", v.Format(g.Format))
			}
		*/

		if g.Last {
			verbose.Printf("output to stdout is going to do at last\n")
		}
	}

	if g.Popup {
		return g.runPopupWait(wins, names)
	}
	return g.runProcessWait(targetProcessDict, wins, names)

}

func (g globalCmd) runProcessWait(targetProcessDict processDict, wins []*window, names []string) error {
	wg := sync.WaitGroup{}
	for pid, p := range targetProcessDict {
		verbose.Printf("waiting for %s\n", p.Format(g.Format))

		wg.Add(1)
		go func(pid uint32, p *process) {
			hProcess, err := windows.OpenProcess(
				winSynchronize,
				false,
				pid,
			)
			if err != nil {
				//continue
				wg.Done()
				stderr.Printf("failed to wait for %v: %v\n", p.Format(g.Format), err)
				return
			}
			if hProcess != 0 {
				timedout := waitForProcessEnd(hProcess, g.Timeout)
				windows.CloseHandle(hProcess)

				if timedout {
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
								stdout.Printf("%s\n", w.format(g.Format))
							}
						}
					}

					// output process info
					if strings.Contains(g.Target, "p") {
						if !g.Last {
							if testMatch(p.Name, names) {
								stdout.Printf("%s\n", p.Format(g.Format))
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
		stdout.Printf("All processes exited: %q\n", names)
	}

	return nil
}

func (g globalCmd) runPopupWait(wins []*window, names []string) error {
	anyendChan := make(chan struct{})

	for _, w := range wins {
		verbose.Printf("waiting for %s have popup\n", w.format(g.Format))

		go func(win *window) {
			waitForWindowPopup(win.Handle, -1)
			anyendChan <- struct{}{}
		}(w)
	}

	<-anyendChan

	return nil
}

func (g globalCmd) Before() {
	if g.Verbose {
		verbose = rog.New(os.Stderr, "", 0)
	}
}
