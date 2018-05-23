package consulacl

import (
	"github.com/hashicorp/consul/acl"
)

// Policy represents a consul ACL policy
type Policy struct {
	agent   GrantMap
	key     GrantMap
	node    GrantMap
	service GrantMap
	session GrantMap
	event   GrantMap
	query   GrantMap

	keyring  Grant
	operator Grant
}

// Equals checks if the policy matches another policy
func (p *Policy) Equals(other *Policy) bool {
	return other != nil &&
		p.keyring == other.keyring &&
		p.operator == other.operator &&
		p.agent.Equals(&other.agent) &&
		p.key.Equals(&other.key) &&
		p.node.Equals(&other.node) &&
		p.service.Equals(&other.service) &&
		p.session.Equals(&other.session) &&
		p.event.Equals(&other.event) &&
		p.query.Equals(&other.query)
}

// SetKeyring configures the keyring grant
func (p *Policy) SetKeyring(grant Grant) {
	p.keyring = grant
}

// GetKeyring retrieves the keyring grant
func (p *Policy) GetKeyring() Grant {
	return p.keyring
}

// SetKeyring configures the operator grant
func (p *Policy) SetOperator(grant Grant) {
	p.operator = grant
}

// GetKeyring retrieves the operator grant
func (p *Policy) GetOperator() Grant {
	return p.operator
}

// Agent returns the agent GrantMap
func (p *Policy) Agent() *GrantMap {
	return &p.agent
}

// Key returns the key GrantMap
func (p *Policy) Key() *GrantMap {
	return &p.key
}

// Node returns the node GrantMap
func (p *Policy) Node() *GrantMap {
	return &p.node
}

// Service returns the service GrantMap
func (p *Policy) Service() *GrantMap {
	return &p.service
}

// Session returns the session GrantMap
func (p *Policy) Session() *GrantMap {
	return &p.session
}

// Event returns the event GrantMap
func (p *Policy) Event() *GrantMap {
	return &p.event
}

// Query returns the query GrantMap
func (p *Policy) Query() *GrantMap {
	return &p.query
}

// Clone creates a copy of the policy
func (p *Policy) Clone() *Policy {
	// Create a new policy and apply the basic keyring and operator grants
	clone := &Policy{
		keyring:  p.keyring,
		operator: p.operator,
	}

	// Create clones of all embedded GrantMap instances
	clone.agent = *p.agent.Clone()
	clone.key = *p.key.Clone()
	clone.node = *p.node.Clone()
	clone.service = *p.service.Clone()
	clone.session = *p.session.Clone()
	clone.event = *p.event.Clone()
	clone.query = *p.query.Clone()

	return clone
}

// NewPolicy constructs a new policy
func NewPolicy() *Policy {
	return &Policy{}
}

// NewPolicy constructs a new policy and fills its state with the state represented by the provided aclPolicy
func NewPolicyFromACLPolicy(aclPolicy *acl.Policy) *Policy {
	p := NewPolicy()

	// Convert keyring and operator grants
	p.keyring = GrantByName(aclPolicy.Keyring)
	p.operator = GrantByName(aclPolicy.Operator)

	for _, policy := range aclPolicy.Agents {
		p.agent.Set(policy.Node, GrantByName(policy.Policy))
	}

	for _, policy := range aclPolicy.Keys {
		p.key.Set(policy.Prefix, GrantByName(policy.Policy))
	}

	for _, policy := range aclPolicy.Nodes {
		p.node.Set(policy.Name, GrantByName(policy.Policy))
	}

	for _, policy := range aclPolicy.Services {
		p.service.Set(policy.Name, GrantByName(policy.Policy))
	}

	for _, policy := range aclPolicy.Sessions {
		p.session.Set(policy.Node, GrantByName(policy.Policy))
	}

	for _, policy := range aclPolicy.Events {
		p.event.Set(policy.Event, GrantByName(policy.Policy))
	}

	for _, policy := range aclPolicy.PreparedQueries {
		p.query.Set(policy.Prefix, GrantByName(policy.Policy))
	}

	return p
}

// NewPolicyFromRules constructs a new policy and fills its state with the state represented by the rules string
func NewPolicyFromRules(rules string) (*Policy, error) {
	// Parse the rules. Sentinel is nil as it is unused except for consul enterprise
	aclPolicy, err := acl.Parse(rules, nil)
	if err != nil {
		return nil, err
	}

	return NewPolicyFromACLPolicy(aclPolicy), nil
}
