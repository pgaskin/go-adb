package adbproxy

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"
	"time"
)

// TODO: rewrite some tests with synctest

// TODO: test socket logic (with and without delayed acks)

func TestDeadline(t *testing.T) {
	expect := func(done <-chan struct{}, isDone bool, msg string, a ...any) {
		var prefix string
		if _, _, line, ok := runtime.Caller(1); ok {
			prefix = fmt.Sprintf("line %d: ", line)
		}
		select {
		case <-done:
			if !isDone {
				if msg == "" {
					msg = "expected Done channel to be open"
				}
				t.Errorf(prefix+msg, a...)
			}
		default:
			if isDone {
				if msg == "" {
					msg = "expected Done channel to be closed"
				}
				t.Errorf(prefix+msg, a...)
			}
		}
	}
	var d deadline
	ch1 := d.Done()
	ch2 := d.Done()
	expect(ch1, false, "expected new Done channel to be open")
	expect(ch2, false, "expected new Done channel to be open")
	d.SetTimeout(0)
	time.Sleep(time.Millisecond * 25)
	expect(ch1, true, "expected Done channel after immediate timeout to be closed")
	expect(ch2, true, "expected Done channel after immediate timeout to be closed")
	ch3 := d.Done()
	expect(ch3, true, "expected new Done channel after timeout to be closed")
	d.SetTimeout(-1)
	ch4 := d.Done()
	expect(ch4, false, "expected new Done channel after cleared timeout to be open")
	expect(ch1, true, "expected old Done channel after immediate timeout to be closed")
	expect(ch2, true, "expected old Done channel after immediate timeout to be closed")
	expect(ch3, true, "expected old Done channel after immediate timeout to be closed")
	d.SetTimeout(time.Millisecond * 500)
	d.SetTimeout(time.Minute)
	time.Sleep(time.Second)
	expect(ch4, false, "expected Done channel after set and extended timeout to be open")
	d.SetTimeout(time.Millisecond * 25)
	time.Sleep(time.Second)
	expect(ch4, true, "expected Done channel after set and extended and reduced then elapsed timeout to be closed")
	d.Set(time.Now().Add(time.Millisecond * 500))
	ch5 := d.Done()
	expect(ch5, false, "expected new Done channel to be open after new timeout set but not yet elapsed")
	time.Sleep(time.Second)
	expect(ch5, true, "expected Done channel to be closed after elapsed timeout")
}

func BenchmarkDeadline(b *testing.B) {
	b.Run("UnsetCheck", func(b *testing.B) {
		b.ReportAllocs()
		var d deadline
		for b.Loop() {
			select {
			case <-d.Done():
				panic("wtf")
			default:
			}
		}
	})
	b.Run("SetCheck", func(b *testing.B) {
		b.ReportAllocs()
		var d deadline
		d.SetTimeout(math.MaxInt64)
		b.ResetTimer()
		for b.Loop() {
			select {
			case <-d.Done():
				panic("wtf")
			default:
			}
		}
	})
	b.Run("ExpiredCheck", func(b *testing.B) {
		b.ReportAllocs()
		var d deadline
		d.SetTimeout(0)
		<-d.Done()
		b.ResetTimer()
		for b.Loop() {
			select {
			case <-d.Done():
			default:
				panic("wtf")
			}
		}
	})
	b.Run("UnsetSet", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var d deadline
			d.SetTimeout(math.MaxInt64)
		}
	})
	b.Run("SetSet", func(b *testing.B) {
		b.ReportAllocs()
		var d deadline
		d.SetTimeout(0)
		<-d.Done()
		b.ResetTimer()
		for b.Loop() {
			d.SetTimeout(math.MaxInt64)
		}
	})
	b.Run("ExpiredSet", func(b *testing.B) {
		b.ReportAllocs()
		var d deadline
		d.SetTimeout(0)
		<-d.Done()
		b.ResetTimer()
		for b.Loop() {
			d.SetTimeout(0)
			<-d.Done()
		}
	})
}

func TestCloser(t *testing.T) {
	var c closer
	ch := c.Closed()
	select {
	case <-ch:
		t.Errorf("expected Closed channel to not be closed")
	default:
	}
	start := make(chan struct{})
	finish := make(chan error)
	first := make(chan error)
	go func() {
		first <- c.Close(func() error {
			close(start)
			return <-finish
		})
	}()
	<-start
	if !c.IsClosed() {
		t.Errorf("expected IsClosed to be true immediately after calling close")
	}
	select {
	case <-ch:
	default:
		t.Errorf("expected Closed channel to be closed")
	}
	if c.Closed() != ch {
		t.Errorf("expected Closed to return the same channel every time")
	}
	second := make(chan error)
	go func() {
		second <- c.Close(func() error {
			t.Errorf("expected Close function to only be called on the first close (even while the first close is still running)")
			return errors.New("second")
		})
	}()
	finish <- errors.New("first")
	firstErr := <-first
	secondErr := <-second
	if firstErr != secondErr || firstErr.Error() != "first" {
		t.Errorf("expected Close to return the correct error, got %#v and %#v", firstErr, secondErr)
	}
	select {
	case <-ch:
	default:
		t.Errorf("expected Closed channel to still be closed")
	}
	select {
	case <-ch:
	default:
		t.Errorf("expected Closed channel to still be closed")
	}
	if c.Closed() != ch {
		t.Errorf("expected Closed to return the same channel every time")
	}
}
