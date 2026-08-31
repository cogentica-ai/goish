package context_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// Cancellation has to propagate DOWN and never up, a cause has to be
// distinguishable from the Err that carries it, and a deadline has to
// win against a later one and lose against an earlier one. The cases
// below are the ones where a plausible implementation and Go's part
// company.
func TestGoishRef(t *testing.T) {
	bg := context.Background()

	// Background and TODO: no deadline, nil Done, nil Err, nil Cause.
	for _, c := range []struct {
		name string
		ctx  context.Context
	}{{"background", bg}, {"todo", context.TODO()}} {
		d, ok := c.ctx.Deadline()
		fmt.Printf("%s deadline=(%v,%v) done-nil=%v err=%v cause=%v\n",
			c.name, d.IsZero(), ok, c.ctx.Done() == nil, c.ctx.Err(), context.Cause(c.ctx))
	}

	// WithCancel: Err is nil before, Canceled after, and cancelling
	// twice changes nothing.
	{
		ctx, cancel := context.WithCancel(bg)
		fmt.Printf("cancel before err=%v cause=%v\n", ctx.Err(), context.Cause(ctx))
		cancel()
		<-ctx.Done()
		fmt.Printf("cancel after err=%v is-canceled=%v cause=%v\n",
			ctx.Err(), errors.Is(ctx.Err(), context.Canceled), context.Cause(ctx))
		cancel()
		fmt.Printf("cancel twice err=%v\n", ctx.Err())
	}

	// Cancellation goes DOWN: cancelling the parent cancels the child,
	// and cancelling the child leaves the parent alone.
	{
		parent, pcancel := context.WithCancel(bg)
		child, ccancel := context.WithCancel(parent)
		defer ccancel()
		pcancel()
		<-child.Done()
		fmt.Printf("down parent=%v child=%v\n", parent.Err(), child.Err())

		p2, p2cancel := context.WithCancel(bg)
		defer p2cancel()
		c2, c2cancel := context.WithCancel(p2)
		c2cancel()
		<-c2.Done()
		fmt.Printf("up parent=%v child=%v\n", p2.Err(), c2.Err())
	}

	// WithCancelCause: Err stays Canceled, Cause carries the reason.
	// That split is the point.
	{
		boom := errors.New("boom")
		ctx, cancel := context.WithCancelCause(bg)
		cancel(boom)
		<-ctx.Done()
		fmt.Printf("cause err=%v is-canceled=%v cause=%v is-boom=%v\n",
			ctx.Err(), errors.Is(ctx.Err(), context.Canceled),
			context.Cause(ctx), errors.Is(context.Cause(ctx), boom))
		// A nil cause falls back to Canceled.
		c2, cancel2 := context.WithCancelCause(bg)
		cancel2(nil)
		<-c2.Done()
		fmt.Printf("cause-nil err=%v cause=%v\n", c2.Err(), context.Cause(c2))
	}

	// Deadlines: an already-past one fires at once; a later child
	// deadline does NOT extend an earlier parent one.
	{
		past, cancel := context.WithDeadline(bg, time.Now().Add(-time.Hour))
		defer cancel()
		<-past.Done()
		fmt.Printf("past err=%v is-exceeded=%v\n",
			past.Err(), errors.Is(past.Err(), context.DeadlineExceeded))

		soon, c1 := context.WithTimeout(bg, 20*time.Millisecond)
		defer c1()
		later, c2 := context.WithTimeout(soon, time.Hour)
		defer c2()
		sd, _ := soon.Deadline()
		ld, _ := later.Deadline()
		fmt.Printf("nested-deadline child-not-later=%v\n", !ld.After(sd))
		<-later.Done()
		fmt.Printf("nested err=%v\n", later.Err())
	}

	// DeadlineExceeded is a net.Error: Timeout() and Temporary() are
	// both true, which is how a caller that already branches on a
	// socket timeout treats a context one the same way.
	{
		var ne net.Error
		ok := errors.As(context.DeadlineExceeded, &ne)
		fmt.Printf("neterr as=%v timeout=%v\n", ok, ok && ne.Timeout())
		fmt.Printf("errtexts canceled=%q exceeded=%q\n",
			context.Canceled.Error(), context.DeadlineExceeded.Error())
	}

	// WithTimeoutCause: Err is still DeadlineExceeded, Cause is the
	// reason given.
	{
		why := errors.New("too slow")
		ctx, cancel := context.WithTimeoutCause(bg, 10*time.Millisecond, why)
		defer cancel()
		<-ctx.Done()
		fmt.Printf("timeoutcause err=%v is-exceeded=%v cause=%v is-why=%v\n",
			ctx.Err(), errors.Is(ctx.Err(), context.DeadlineExceeded),
			context.Cause(ctx), errors.Is(context.Cause(ctx), why))
	}

	// WithValue: lookup walks up, a miss is nil, and a cancel in the
	// chain does not sever the values above it.
	{
		type k string
		v1 := context.WithValue(bg, k("a"), 1)
		v2 := context.WithValue(v1, k("b"), 2)
		cctx, cancel := context.WithCancel(v2)
		defer cancel()
		v3 := context.WithValue(cctx, k("c"), 3)
		for _, key := range []string{"a", "b", "c", "d"} {
			fmt.Printf("value %q -> %v (through cancel: %v)\n",
				key, v2.Value(k(key)), v3.Value(k(key)))
		}
	}

	// WithoutCancel: keeps the values, drops the cancellation.
	{
		type k string
		base := context.WithValue(bg, k("a"), 1)
		ctx, cancel := context.WithCancel(base)
		free := context.WithoutCancel(ctx)
		cancel()
		<-ctx.Done()
		d, ok := free.Deadline()
		fmt.Printf("withoutcancel parent-err=%v free-err=%v value=%v done-nil=%v deadline=(%v,%v)\n",
			ctx.Err(), free.Err(), free.Value(k("a")), free.Done() == nil, d.IsZero(), ok)
	}

	// AfterFunc: runs on cancel, stop() prevents it, and stop() after
	// cancel returns false.
	{
		ran := make(chan struct{})
		ctx, cancel := context.WithCancel(bg)
		context.AfterFunc(ctx, func() { close(ran) })
		cancel()
		<-ran
		fmt.Printf("afterfunc ran=true\n")

		c2, cancel2 := context.WithCancel(bg)
		fired := make(chan struct{})
		stop := context.AfterFunc(c2, func() { close(fired) })
		fmt.Printf("afterfunc stop-before-cancel=%v\n", stop())
		fmt.Printf("afterfunc stop-twice=%v\n", stop())
		cancel2()
		<-c2.Done()
		select {
		case <-fired:
			fmt.Printf("afterfunc ran-after-stop=true\n")
		case <-time.After(50 * time.Millisecond):
			fmt.Printf("afterfunc ran-after-stop=false\n")
		}

		c3, cancel3 := context.WithCancel(bg)
		cancel3()
		<-c3.Done()
		done3 := make(chan struct{})
		stop3 := context.AfterFunc(c3, func() { close(done3) })
		<-done3
		fmt.Printf("afterfunc already-canceled ran=true stop-after=%v\n", stop3())
	}
}
