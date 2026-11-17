package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Set holds every loaded policy version, keyed by agent and version. The
// engine evaluates against the active version; a dry run evaluates against a
// candidate that has not been activated.
type Set struct {
	mu       sync.RWMutex
	versions map[string]map[int]*Policy
	active   map[string]int
}

// NewSet returns an empty set.
func NewSet() *Set {
	return &Set{versions: map[string]map[int]*Policy{}, active: map[string]int{}}
}

// Add stores a policy version. The highest version of an agent becomes its
// active policy unless Activate says otherwise.
func (s *Set) Add(p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.DefaultAction == "" {
		p.DefaultAction = ActionLog
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byVersion := s.versions[p.Agent]
	if byVersion == nil {
		byVersion = map[int]*Policy{}
		s.versions[p.Agent] = byVersion
	}
	if existing, dup := byVersion[p.Version]; dup && !equal(existing, p) {
		return fmt.Errorf("policy: %s v%d is already loaded with different contents", p.Agent, p.Version)
	}
	byVersion[p.Version] = p
	if p.Version > s.active[p.Agent] {
		s.active[p.Agent] = p.Version
	}
	return nil
}

func equal(a, b *Policy) bool {
	return fmt.Sprintf("%#v", a) == fmt.Sprintf("%#v", b)
}

// Activate pins the version an agent's traffic is evaluated against.
func (s *Set) Activate(agent string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[agent][version]; !ok {
		return fmt.Errorf("policy: %s v%d is not loaded", agent, version)
	}
	s.active[agent] = version
	return nil
}

// Active returns the policy an agent's traffic is evaluated against.
func (s *Set) Active(agent string) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.active[agent]
	if !ok {
		return nil, false
	}
	p, ok := s.versions[agent][v]
	return p, ok
}

// Version returns one specific version.
func (s *Set) Version(agent string, version int) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.versions[agent][version]
	return p, ok
}

// Agents lists the agents with a loaded policy.
func (s *Set) Agents() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.versions))
	for a := range s.versions {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Versions lists an agent's loaded versions, ascending.
func (s *Set) Versions(agent string) []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]int, 0, len(s.versions[agent]))
	for v := range s.versions[agent] {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// LoadFile reads one policy file.
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// LoadDir loads every *.yaml and *.yml policy in a directory. It is how the
// engine starts up and how CI validates the policies in the repository.
func LoadDir(dir string) (*Set, error) {
	set := NewSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if err := set.Add(p); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		loaded++
	}
	if loaded == 0 {
		return nil, fmt.Errorf("policy: no policy files in %s", dir)
	}
	return set, nil
}
