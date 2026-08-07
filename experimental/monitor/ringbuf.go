// experimental/monitor/ringbuf.go
package monitor

import "sync"

type RingBuffer[T any] struct {
	mu   sync.RWMutex
	buf  []T
	head int
	size int
	cap  int
}

func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buf: make([]T, capacity),
		cap: capacity,
	}
}

func (r *RingBuffer[T]) Push(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[(r.head+r.size)%r.cap] = v
	if r.size < r.cap {
		r.size++
	} else {
		r.head = (r.head + 1) % r.cap
	}
}

func (r *RingBuffer[T]) Last(n int) []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n > r.size {
		n = r.size
	}
	result := make([]T, n)
	for i := 0; i < n; i++ {
		idx := (r.head + r.size - n + i) % r.cap
		result[i] = r.buf[idx]
	}
	return result
}

func (r *RingBuffer[T]) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}
