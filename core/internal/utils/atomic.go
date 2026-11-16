package utils

import (
	"sync/atomic"
	"time"
)

var atomicTimeBase = time.Now()

// AtomicTime stores a time as an offset from atomicTimeBase, so that Set does not allocate.
type AtomicTime struct {
	v atomic.Int64
}

func NewAtomicTime(t time.Time) *AtomicTime {
	a := &AtomicTime{}
	a.Set(t)
	return a
}

func (t *AtomicTime) Set(new time.Time) {
	t.v.Store(int64(new.Sub(atomicTimeBase)))
}

func (t *AtomicTime) Get() time.Time {
	return atomicTimeBase.Add(time.Duration(t.v.Load()))
}

type Atomic[T any] struct {
	v atomic.Value
}

func (a *Atomic[T]) Load() T {
	value := a.v.Load()
	if value == nil {
		var zero T
		return zero
	}
	return value.(T)
}

func (a *Atomic[T]) Store(value T) {
	a.v.Store(value)
}

func (a *Atomic[T]) Swap(new T) T {
	old := a.v.Swap(new)
	if old == nil {
		var zero T
		return zero
	}
	return old.(T)
}

func (a *Atomic[T]) CompareAndSwap(old, new T) bool {
	return a.v.CompareAndSwap(old, new)
}
