package install

import "os"

// terminalIO is an interactive stdin/stdout pair, usually /dev/tty.
type terminalIO struct {
	in  *os.File
	out *os.File
}

func (t terminalIO) Read(p []byte) (int, error)  { return t.in.Read(p) }
func (t terminalIO) Write(p []byte) (int, error) { return t.out.Write(p) }
func (t terminalIO) Fd() uintptr                 { return t.in.Fd() }

func openTerminalIO() (terminalIO, error) {
	// Must open O_RDWR so the survey library can both read keystrokes and
	// write the prompt/menu to the same fd.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return terminalIO{}, err
	}
	return terminalIO{in: tty, out: tty}, nil
}
