// Verify synthetic examples against the original Go/RE2 detector expressions.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type Probe struct {
	ID    string `json:"id"`
	Regex string `json:"regex"`
	Text  string `json:"text"`
}

func main() {
	var probes []Probe
	if err := json.NewDecoder(os.Stdin).Decode(&probes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	compiled := map[string]*regexp.Regexp{}
	results := make([]bool, 0, len(probes))
	for _, probe := range probes {
		rule := compiled[probe.Regex]
		if rule == nil {
			var err error
			rule, err = regexp.Compile(probe.Regex)
			if err != nil {
				fmt.Fprintln(os.Stderr, probe.ID, err)
				os.Exit(1)
			}
			compiled[probe.Regex] = rule
		}
		results = append(results, rule.MatchString(probe.Text))
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
