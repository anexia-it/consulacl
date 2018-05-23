package consulacl

import (
	"testing"

	"github.com/hashicorp/consul/acl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicy(t *testing.T) {
	p := NewPolicy()
	assert.NotNil(t, p)
}

func TestNewPolicyFromACLPolicy(t *testing.T) {
	aclPolicy := &acl.Policy{
		Agents: []*acl.AgentPolicy{
			{
				Node:   "node0",
				Policy: "read",
			},
			{
				Node:   "node1",
				Policy: "write",
			},
		},
		Keys: []*acl.KeyPolicy{
			{
				Prefix: "key0/",
				Policy: "read",
			},
			{
				Prefix: "key1",
				Policy: "write",
			},
		},
		Nodes: []*acl.NodePolicy{
			{
				Name:   "node0",
				Policy: "read",
			},
			{
				Name:   "node1",
				Policy: "write",
			},
		},
		Services: []*acl.ServicePolicy{
			{
				Name:   "srv0",
				Policy: "read",
			},
			{
				Name:   "srv1",
				Policy: "write",
			},
		},
		Events: []*acl.EventPolicy{
			{
				Event:  "ev0",
				Policy: "read",
			},
			{
				Event:  "ev1",
				Policy: "write",
			},
		},
		PreparedQueries: []*acl.PreparedQueryPolicy{
			{
				Prefix: "query0",
				Policy: "read",
			},
			{
				Prefix: "query1",
				Policy: "write",
			},
		},
		Sessions: []*acl.SessionPolicy{
			{
				Node:   "session0",
				Policy: "read",
			},
			{
				Node:   "session1",
				Policy: "write",
			},
		},
	}

	p := NewPolicyFromACLPolicy(aclPolicy)
	require.NotNil(t, p)
	assert.EqualValues(t, GrantRead, p.agent.Get("node0"))
	assert.EqualValues(t, GrantWrite, p.agent.Get("node1"))
	assert.EqualValues(t, GrantRead, p.key.Get("key0/"))
	assert.EqualValues(t, GrantWrite, p.key.Get("key1"))
	assert.EqualValues(t, GrantRead, p.node.Get("node0"))
	assert.EqualValues(t, GrantWrite, p.node.Get("node1"))
	assert.EqualValues(t, GrantRead, p.service.Get("srv0"))
	assert.EqualValues(t, GrantWrite, p.service.Get("srv1"))
	assert.EqualValues(t, GrantRead, p.event.Get("ev0"))
	assert.EqualValues(t, GrantWrite, p.event.Get("ev1"))
	assert.EqualValues(t, GrantRead, p.query.Get("query0"))
	assert.EqualValues(t, GrantWrite, p.query.Get("query1"))
	assert.EqualValues(t, GrantRead, p.session.Get("session0"))
	assert.EqualValues(t, GrantWrite, p.session.Get("session1"))
}

func TestNewPolicyFromRules(t *testing.T) {
	t.Run("ParseError", func(t *testing.T) {
		rules := `agent = "read"`
		_, expectedError := acl.Parse(rules, nil)
		require.Error(t, expectedError)

		p, err := NewPolicyFromRules(rules)
		assert.EqualError(t, err, expectedError.Error())
		assert.Nil(t, p)
	})

	t.Run("OK", func(t *testing.T) {
		rules := `key "test0" {
		policy = "read"
		}`

		p, err := NewPolicyFromRules(rules)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.True(t, p.key.Is("test0", GrantRead))
	})
}

func TestPolicy_Equals(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		p := &Policy{}
		assert.False(t, p.Equals(nil))
	})

	t.Run("Keyring", func(t *testing.T) {
		p := &Policy{
			keyring: GrantRead,
		}
		other := &Policy{
			keyring: GrantWrite,
		}

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))
		other.keyring = GrantRead
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Operator", func(t *testing.T) {
		p := &Policy{
			operator: GrantRead,
		}
		other := &Policy{
			operator: GrantWrite,
		}

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.operator = GrantRead
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Agent", func(t *testing.T) {
		p := &Policy{}
		p.agent.Set("test0", GrantRead)
		other := &Policy{}
		other.agent.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.agent.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Key", func(t *testing.T) {
		p := &Policy{}
		p.key.Set("test0", GrantRead)
		other := &Policy{}
		other.key.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.key.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Node", func(t *testing.T) {
		p := &Policy{}
		p.node.Set("test0", GrantRead)
		other := &Policy{}
		other.node.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.node.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Service", func(t *testing.T) {
		p := &Policy{}
		p.service.Set("test0", GrantRead)
		other := &Policy{}
		other.service.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.service.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Event", func(t *testing.T) {
		p := &Policy{}
		p.event.Set("test0", GrantRead)
		other := &Policy{}
		other.event.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.event.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Query", func(t *testing.T) {
		p := &Policy{}
		p.query.Set("test0", GrantRead)
		other := &Policy{}
		other.query.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.query.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})

	t.Run("Session", func(t *testing.T) {
		p := &Policy{}
		p.session.Set("test0", GrantRead)
		other := &Policy{}
		other.session.Set("test0", GrantWrite)

		assert.False(t, p.Equals(other))
		assert.False(t, other.Equals(p))

		other.session.Set("test0", GrantRead)
		assert.True(t, p.Equals(other))
		assert.True(t, other.Equals(p))
	})
}

func TestPolicy_GetKeyring(t *testing.T) {
	p := &Policy{
		keyring: GrantWrite,
	}

	assert.EqualValues(t, GrantWrite, p.GetKeyring())
}

func TestPolicy_SetKeyring(t *testing.T) {
	p := &Policy{}
	p.SetKeyring(GrantWrite)
	assert.EqualValues(t, GrantWrite, p.keyring)
}

func TestPolicy_GetOperator(t *testing.T) {
	p := &Policy{
		operator: GrantWrite,
	}

	assert.EqualValues(t, GrantWrite, p.GetOperator())
}

func TestPolicy_SetOperator(t *testing.T) {
	p := &Policy{}
	p.SetOperator(GrantWrite)
	assert.EqualValues(t, GrantWrite, p.operator)
}

func TestPolicy_Agent(t *testing.T) {
	p := &Policy{}
	p.agent.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.agent, p.Agent())
}

func TestPolicy_Key(t *testing.T) {
	p := &Policy{}
	p.key.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.key, p.Key())
}

func TestPolicy_Node(t *testing.T) {
	p := &Policy{}
	p.node.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.node, p.Node())
}

func TestPolicy_Service(t *testing.T) {
	p := &Policy{}
	p.service.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.service, p.Service())
}

func TestPolicy_Event(t *testing.T) {
	p := &Policy{}
	p.event.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.event, p.Event())
}

func TestPolicy_Query(t *testing.T) {
	p := &Policy{}
	p.query.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.query, p.Query())
}

func TestPolicy_Session(t *testing.T) {
	p := &Policy{}
	p.session.Set("test0", GrantWrite)
	assert.EqualValues(t, &p.session, p.Session())
}

func TestPolicy_Clone(t *testing.T) {
	// Prepare our source: set up read permissions for every basic grant and in every
	// grant map
	source := &Policy{}
	source.keyring = GrantRead
	source.operator = GrantRead
	source.agent.Set("agent0", GrantRead)
	source.key.Set("key0", GrantRead)
	source.node.Set("node0", GrantRead)
	source.service.Set("service0", GrantRead)
	source.session.Set("session0", GrantRead)
	source.event.Set("event0", GrantRead)
	source.query.Set("query0", GrantRead)

	// Create our clone and check if the clone equals the source
	clone := source.Clone()
	assert.True(t, clone.Equals(source))

	// Modify the clone
	clone.keyring = GrantWrite
	clone.operator = GrantWrite
	clone.agent.Set("agent0", GrantWrite)
	clone.key.Set("key0", GrantWrite)
	clone.node.Set("node0", GrantWrite)
	clone.service.Set("service0", GrantWrite)
	clone.session.Set("session0", GrantWrite)
	clone.event.Set("event0", GrantWrite)
	clone.query.Set("query0", GrantWrite)

	// Check that the source is unaffected by this
	assert.EqualValues(t, source.keyring, GrantRead)
	assert.EqualValues(t, source.operator, GrantRead)
	assert.EqualValues(t, GrantRead, source.agent.Get("agent0"))
	assert.EqualValues(t, GrantRead, source.key.Get("key0"))
	assert.EqualValues(t, GrantRead, source.node.Get("node0"))
	assert.EqualValues(t, GrantRead, source.service.Get("service0"))
	assert.EqualValues(t, GrantRead, source.session.Get("session0"))
	assert.EqualValues(t, GrantRead, source.event.Get("event0"))
	assert.EqualValues(t, GrantRead, source.query.Get("query0"))

	// Ensure that clone and source are not equal anymore
	assert.False(t, clone.Equals(source))
}
