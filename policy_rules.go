package consulacl

import (
	"fmt"
	"sort"
	"strings"
)

type ruleGenerator interface {
	generateRules(typePrefix string) string
}

// GenerateRules constructs a rules string from the defined policy
func (p *Policy) GenerateRules() string {
	var rules []string
	if p.keyring != GrantNone {
		rules = append(rules, fmt.Sprintf(`keyring = "%s"`, p.keyring.String()))
	}

	if p.operator != GrantNone {
		rules = append(rules, fmt.Sprintf(`operator = "%s"`, p.operator.String()))
	}

	generators := map[string]ruleGenerator{
		"agent":   &p.agent,
		"key":     &p.key,
		"node":    &p.node,
		"service": &p.service,
		"event":   &p.event,
		"query":   &p.query,
		"session": &p.session,
	}

	// Sort type prefixes to get a reproducible output format
	typePrefixes := make([]string, 0, len(generators))
	for typePrefix := range generators {
		typePrefixes = append(typePrefixes, typePrefix)
	}
	sort.Strings(typePrefixes)

	for _, typePrefix := range typePrefixes {
		g := generators[typePrefix]
		if generatorRules := g.generateRules(typePrefix); generatorRules != "" {
			rules = append(rules, generatorRules)
		}
	}

	return strings.Join(rules, "\n")
}
