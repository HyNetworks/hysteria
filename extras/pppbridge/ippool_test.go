package pppbridge

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPPoolBasic(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", pool.Gateway())

	seen := make(map[string]bool)
	first, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", first)
	seen[first] = true

	// Allocate remaining 252 IPs (10.0.0.3 through 10.0.0.254)
	for i := 0; i < 252; i++ {
		ip, err := pool.Allocate()
		require.NoError(t, err)
		assert.False(t, seen[ip], "duplicate IP: %s", ip)
		seen[ip] = true
	}
	assert.Equal(t, 253, len(seen))

	// Pool exhausted
	_, err = pool.Allocate()
	assert.Error(t, err)
}

func TestIPPoolRelease(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/30")
	require.NoError(t, err)

	ip, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", ip)

	// Pool is now exhausted (/30 only has 1 client IP)
	_, err = pool.Allocate()
	assert.Error(t, err)

	pool.Release(ip)

	// After release, the IP is available again
	ip2, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, ip, ip2)
}

func TestIPPoolConcurrent(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/24")
	require.NoError(t, err)

	var mu sync.Mutex
	allocated := make(map[string]bool)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := pool.Allocate()
			if err != nil {
				return
			}
			mu.Lock()
			assert.False(t, allocated[ip], "duplicate IP: %s", ip)
			allocated[ip] = true
			mu.Unlock()

			pool.Release(ip)
		}()
	}
	wg.Wait()
}

func TestIPPoolSmallCIDR(t *testing.T) {
	// /30: .0 network, .1 gateway, .2 client, .3 broadcast
	pool, err := NewIPPool("10.0.0.0/30")
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", pool.Gateway())

	ip, err := pool.Allocate()
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", ip)

	// Only 1 allocatable IP
	_, err = pool.Allocate()
	assert.Error(t, err)
}

func TestIPPoolInvalidCIDR(t *testing.T) {
	_, err := NewIPPool("not-a-cidr")
	assert.Error(t, err)

	_, err = NewIPPool("10.0.0.0/32")
	assert.Error(t, err)
}
