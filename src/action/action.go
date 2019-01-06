package action

import (
	"fmt"
	"resolver"
	"strings"
	"time"
)

const OPTSEP = "#"

var Actions = map[string]Action{}

type Options struct {
	Delay   time.Duration
	Dict    string
	Class   uint16
	Type    uint16
	Workers int
	Resolv  *resolver.Resolver
}

type Action interface {
	Name() string
	Description() string
	Init(soptions string, options *Options) (Action, error)
	Exec(domain string) error
}

func Init(nameopt string, options *Options) (Action, error) {
	name, opt := splitActionOptions(nameopt)
	if mod, ok := Actions[name]; ok {
		return mod.Init(opt, options)
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
