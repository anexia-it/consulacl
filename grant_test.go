package consulacl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrant_String(t *testing.T) {
	t.Run("ValidGrants", func(t *testing.T) {
		for g, grantName := range grantNameMap {
			assert.EqualValues(t, grantName, g.String())
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		assert.PanicsWithValue(t, "invalid grant type", func() {
			_ = Grant(grantMax).String()
		})
	})
}

func TestGrantByName(t *testing.T) {
	assert.EqualValues(t, GrantNone, GrantByName("invalid"))

	for expectedGrant, name := range grantNameMap {
		assert.EqualValues(t, expectedGrant, GrantByName(name))
	}
}
