package consulacl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantMap_Set(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		gm := GrantMap{}
		gm.Set("test", GrantWrite)
		require.NotNil(t, gm.grants)
		assert.EqualValues(t, GrantWrite, gm.grants["test"])
	})

	t.Run("Override", func(t *testing.T) {
		gm := GrantMap{}
		gm.Set("test", GrantWrite)
		gm.Set("test", GrantRead)
		require.NotNil(t, gm.grants)
		assert.EqualValues(t, GrantRead, gm.grants["test"])
	})

	t.Run("ImplicitRemove", func(t *testing.T) {
		gm := GrantMap{}
		gm.Set("test", GrantWrite)
		gm.Set("test", GrantNone)
		require.NotNil(t, gm.grants)
		_, ok := gm.grants["test"]
		assert.False(t, ok)
	})
}

func TestGrantMap_Remove(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		gm := GrantMap{}
		gm.Remove("test")
		assert.Nil(t, gm.grants)
	})

	t.Run("NotExisting", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = make(map[string]Grant)
		gm.Remove("test")
	})

	t.Run("Existing", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test": GrantWrite,
		}
		gm.Remove("test")
		assert.Len(t, gm.grants, 0)
	})
}

func TestGrantMap_Get(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		gm := GrantMap{}
		assert.EqualValues(t, GrantNone, gm.Get("test"))
	})

	t.Run("Mismatch", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test0": GrantWrite,
		}

		assert.EqualValues(t, GrantNone, gm.Get("test1"))
	})

	t.Run("OK", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test": GrantWrite,
		}

		assert.EqualValues(t, GrantWrite, gm.Get("test"))
	})
}

func TestGrantMap_Is(t *testing.T) {
	t.Run("Unknown", func(t *testing.T) {
		gm := GrantMap{}
		assert.False(t, gm.Is("test", GrantRead))
	})

	t.Run("NotEqual", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test": GrantWrite,
		}
		assert.False(t, gm.Is("test", GrantRead))
	})

	t.Run("Equal", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test": GrantWrite,
		}
		assert.True(t, gm.Is("test", GrantWrite))
	})
}

func TestGrantMap_Equals(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		gm := GrantMap{}
		assert.False(t, gm.Equals(nil))
	})

	t.Run("LengthMismatch", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test": GrantWrite,
		}
		other := GrantMap{}

		assert.False(t, gm.Equals(&other))
		assert.False(t, other.Equals(&gm))
	})

	t.Run("Mismatch", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test0": GrantWrite,
			"test1": GrantRead,
		}
		other := GrantMap{}
		other.grants = map[string]Grant{
			"test0": GrantWrite,
			"test1": GrantWrite,
		}

		assert.False(t, gm.Equals(&other))
		assert.False(t, other.Equals(&gm))
	})

	t.Run("Match", func(t *testing.T) {
		gm := GrantMap{}
		gm.grants = map[string]Grant{
			"test0": GrantWrite,
			"test1": GrantRead,
		}
		other := GrantMap{}
		other.grants = map[string]Grant{
			"test0": GrantWrite,
			"test1": GrantRead,
		}

		assert.True(t, gm.Equals(&other))
		assert.True(t, other.Equals(&gm))
	})
}

func TestGrantMap_Clone(t *testing.T) {
	// Initialize our source
	source := GrantMap{}
	source.Set("target0", GrantRead)
	source.Set("target1", GrantWrite)
	source.Set("target2", GrantList)
	source.Set("target3", GrantDeny)

	// Create a clone
	clone := source.Clone()

	// Check if the contents match
	require.True(t, clone.Equals(&source))

	// Change a grant of the clone ...
	clone.Set("target3", GrantRead)
	assert.EqualValues(t, GrantRead, clone.Get("target3"))
	// ... and ensure the source was not affected by this change
	assert.EqualValues(t, GrantDeny, source.Get("target3"))

	// Finally ensure that clone and source are not equal anymore
	assert.False(t, clone.Equals(&source))
}
