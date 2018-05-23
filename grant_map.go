package consulacl

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type GrantMap struct {
	mu     sync.RWMutex
	grants map[string]Grant
}

// Set applies the given grant for the given target
//
// This method overrides potentially existing grants
func (gm *GrantMap) Set(target string, grant Grant) {
	// If we receive a "none" grant we revoke it
	if grant == GrantNone {
		gm.Remove(target)
		return
	}
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.grants == nil {
		gm.grants = make(map[string]Grant, 16)
	}
	gm.grants[target] = grant
}

// Remove removes the grant for the given target
func (gm *GrantMap) Remove(target string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.grants == nil {
		return
	}
	if _, exists := gm.grants[target]; exists {
		delete(gm.grants, target)
	}
}

// Get retrieves the grant for a given target
func (gm *GrantMap) Get(target string) Grant {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.grants[target]
}

// Is checks if the grant for the given target is the same as provided
func (gm *GrantMap) Is(target string, grant Grant) bool {
	g := gm.Get(target)
	return g == grant
}

// Equals checks if the given GrantMap equals another GrantMap
func (gm *GrantMap) Equals(other *GrantMap) bool {
	if other == nil {
		return false
	}

	// Acquire read-lock on both grant maps
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	other.mu.RLock()
	defer other.mu.RUnlock()

	// Short-cut: length mismatch
	if len(gm.grants) != len(other.grants) {
		return false
	}

	// Compare each grant
	for target, grant := range gm.grants {
		if other.grants[target] != grant {
			return false
		}
	}

	return true
}

// Clone creates a copy of the GrantMap
func (gm *GrantMap) Clone() *GrantMap {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	clone := &GrantMap{
		grants: make(map[string]Grant, len(gm.grants)),
	}
	for target, grant := range gm.grants {
		clone.grants[target] = grant
	}

	return clone
}

func (gm *GrantMap) generateRules(typePrefix string) string {
	var rules []string

	gm.mu.RLock()
	defer gm.mu.RUnlock()

	// Sort the targets first
	targets := make([]string, 0, len(gm.grants))
	for target := range gm.grants {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	for _, target := range targets {
		grant := gm.grants[target]

		// Skip "none" grants
		if grant == GrantNone {
			continue
		}

		rules = append(rules, fmt.Sprintf(
			`%s "%s" {
  policy = "%s"
}`, typePrefix, target, grant.String()))
	}

	return strings.Join(rules, "\n")
}
