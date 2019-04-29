package action

import (
	"dns/resolver"
	"dthelper"
	"fmt"
	"strings"
	"time"
)

const (
	optSep       = "#"
	errMissingDN = "missing domain name"
	errReqDict   = "dictionary file is required"
	errEmptyDict = "dictionary file is empty"
)

var Actions = map[string]Action{}

type ActOpts struct {
	Delay   time.Duration
	Dict    *dthelper.FDict
	Class   uint16
	Soa     bool
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
	split := strings.SplitN(hopts, optSep, 2)
	mname = split[0]
	if len(split) > 1 {
		soptions = split[1]
	}
	return
}
