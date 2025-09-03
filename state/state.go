package state

var SCXState State

type State struct {
	CurrentBlock int64
	Key          string
	NodeURL      string
}

func (s *State) InitState() error {
	var err error

	s.ReadConfig()

	return err
}

func (s *State) ReadConfig() {
	// eventually add key handling here

}
