package action

import (
	"dthelper"
	"fmt"
	"resolver"
	"strings"
	"time"
)

const OPTSEP = "#"

var Actions = map[string]Action{}

type ActOpts struct {
	Delay   time.Duration
	Dict    *dthelper.FDict
	Class   uint16
	Type    uint16
	Workers int
	Resolv  *resolver.Resolver
}

type Action interface {
	Name() string
	Description() string
	Exec(domain string, options *ActOpts) error
}

func Get(name string) (Action, error) {
	if mod, ok := Actions[name]; ok {
		return mod, nil
	}
	return nil, fmt.Errorf("unknown action %s, aborted", name)
}

func Register(action Action) error {
	if _, ok := Actions[action.Name()]; ok {
		return fmt.Errorf("action '%s' already exists", action.Name())
	}
	Actions[action.Name()] = action
	return nil
}

func splitActionOptions(hopts string) (mname, soptions string) {
	split := strings.SplitN(hopts, OPTSEP, 2)
	mname = split[0]
	if len(split) > 1 {
		soptions = split[1]
	}
	return
}
