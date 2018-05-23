package consulacl

// Grant defines the policy grant type
type Grant uint8

// String returns the string representation of a grant
func (g Grant) String() string {
	typeName, ok := grantNameMap[g]
	if !ok {
		panic("invalid grant type")
	}
	return typeName
}

// GrantByName returns the grant by its specified name
//
// If no grant by the given name could be found GrantNone will be returned
func GrantByName(name string) Grant {
	for g, grantName := range grantNameMap {
		if grantName == name {
			return g
		}
	}

	return GrantNone
}

const (
	// GrantNone is fully virtual and defines that no access should be granted
	GrantNone = iota
	// GrantDeny defines that access should be denied
	GrantDeny
	// GrantList defines that listing is allowed (Consul 1.0+ with acl_enable_key_list policy configured)
	GrantList
	// GrantRead defines that read operations are allowed
	GrantRead
	// GrantWrite defines that write operations are allowed
	GrantWrite

	grantMax
)

var grantNameMap = map[Grant]string{
	GrantNone:  "none",
	GrantDeny:  "deny",
	GrantList:  "list",
	GrantRead:  "read",
	GrantWrite: "write",
}
