package consulacl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicy_GenerateRules(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		p := &Policy{}
		assert.EqualValues(t, "", p.GenerateRules())
	})

	t.Run("Operator", func(t *testing.T) {
		p := &Policy{
			keyring:  GrantWrite,
			operator: GrantRead,
		}

		assert.EqualValues(t,
			`keyring = "write"
operator = "read"`, p.GenerateRules())
	})

	t.Run("Full", func(t *testing.T) {
		p := &Policy{}
		p.keyring = GrantWrite
		p.operator = GrantRead

		p.agent.Set("agent1", GrantWrite)
		p.agent.Set("agent0", GrantRead)
		p.agent.grants["agent2"] = GrantNone

		p.key.Set("key1", GrantWrite)
		p.key.Set("key0", GrantRead)
		p.key.grants["key2"] = GrantNone

		p.node.Set("node1", GrantWrite)
		p.node.Set("node0", GrantRead)
		p.node.grants["node2"] = GrantNone

		p.service.Set("service1", GrantWrite)
		p.service.Set("service0", GrantRead)
		p.service.grants["service2"] = GrantNone

		p.event.Set("event1", GrantWrite)
		p.event.Set("event0", GrantRead)
		p.event.grants["event2"] = GrantNone

		p.query.Set("query1", GrantWrite)
		p.query.Set("query0", GrantRead)
		p.query.grants["query2"] = GrantNone

		p.session.Set("session1", GrantWrite)
		p.session.Set("session0", GrantRead)
		p.session.grants["session2"] = GrantNone

		assert.EqualValues(t, `keyring = "write"
operator = "read"
agent "agent0" {
  policy = "read"
}
agent "agent1" {
  policy = "write"
}
event "event0" {
  policy = "read"
}
event "event1" {
  policy = "write"
}
key "key0" {
  policy = "read"
}
key "key1" {
  policy = "write"
}
node "node0" {
  policy = "read"
}
node "node1" {
  policy = "write"
}
query "query0" {
  policy = "read"
}
query "query1" {
  policy = "write"
}
service "service0" {
  policy = "read"
}
service "service1" {
  policy = "write"
}
session "session0" {
  policy = "read"
}
session "session1" {
  policy = "write"
}`, p.GenerateRules())
	})
}
