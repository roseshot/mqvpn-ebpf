package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"
)

func silentReconnectLogger()*slog.Logger{
	return slog.New(slog.NewTextHandler(io.Discard,nil))
}

func TestReconnectBackoffUpToThirtySeconds(t *testing.T){
	want:=[]time.Duration{
		time.Second,2*time.Second,4*time.Second,8*time.Second,
		16*time.Second,30*time.Second,30*time.Second,
	}
	var got []time.Duration
	next:=reconnectInitialDelay
	for range want {
		got=append(got,next)
		next=nextReconnectDelay(next)
	}
	if !reflect.DeepEqual(got,want){t.Fatalf("backoff: got %v, want %v",got,want)}
}

func TestReconnectSupervisorRetriesFailureAndCleanRemoteEOF(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background())
	defer cancel()
	var attempts int
	var delays []time.Duration
	attempt:=func(context.Context)error{
		attempts++
		if attempts==1{return errors.New("WAN temporarily unreachable")}
		// A clean EOF from ClientPump is also a disconnected VPN, not a
		// request to stop the daemon.
		if attempts==2{return nil}
		cancel()
		return nil
	}
	wait:=func(_ context.Context,d time.Duration)error{
		delays=append(delays,d)
		return nil
	}
	err:=runClientSupervisorWithWait(ctx,true,silentReconnectLogger(),attempt,wait)
	if !errors.Is(err,context.Canceled) || attempts!=3 {
		t.Fatalf("expected canceled after 3 attempts: %v (%d attempts)",err,attempts)
	}
	if !reflect.DeepEqual(delays,[]time.Duration{time.Second,2*time.Second}) {
		t.Fatalf("unexpected retry delays: %v",delays)
	}
}

func TestReconnectSupervisorDisabledAttemptsExactlyOnce(t *testing.T){
	var attempts,waits int
	sentinel:=errors.New("single attempt failed")
	err:=runClientSupervisorWithWait(context.Background(),false,silentReconnectLogger(),
		func(context.Context)error{attempts++;return sentinel},
		func(context.Context,time.Duration)error{waits++;return nil},
	)
	if !errors.Is(err,sentinel)||attempts!=1||waits!=0 {
		t.Fatalf("disabled reconnect did not return single error: %v attempts=%d waits=%d",err,attempts,waits)
	}
	// A cleanly completed single session is also terminal when disabled.
	err=runClientSupervisorWithWait(context.Background(),false,silentReconnectLogger(),
		func(context.Context)error{attempts++;return nil},
		func(context.Context,time.Duration)error{waits++;return nil},
	)
	if err!=nil||attempts!=2||waits!=0 {t.Fatalf("single session did not exit: %v",err)}
}

func TestReconnectSupervisorStopsOnCancellationDuringBackoff(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background())
	attempts:=0
	var delay time.Duration
	err:=runClientSupervisorWithWait(ctx,true,silentReconnectLogger(),
		func(context.Context)error{
			attempts++
			return errors.New("WAN offline")
		},
		func(ctx context.Context,d time.Duration)error{
			delay=d
			cancel()
			return waitReconnect(ctx,d)
		},
	)
	if !errors.Is(err,context.Canceled)||attempts!=1||delay!=time.Second {
		t.Fatalf("cancellation during backoff: %v attempts=%d delay=%v",err,attempts,delay)
	}
}
func TestReconnectSupervisorRespectsPreCanceledContext(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	attempts:=0
	err:=runClientSupervisorWithWait(ctx,true,silentReconnectLogger(),
		func(context.Context)error{attempts++;return nil},
		func(context.Context,time.Duration)error{t.Fatal("must not wait");return nil},
	)
	if !errors.Is(err,context.Canceled)||attempts!=0 {t.Fatalf("pre-canceled daemon retried: %v, %d",err,attempts)}
}

func TestReconnectSupervisorWaitRespectsCanceledParent(t *testing.T){
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	if err:=waitReconnect(ctx,30*time.Second);!errors.Is(err,context.Canceled){
		t.Fatalf("cancel did not interrupt backoff: %v",err)
	}
	if reconnectStableAfter!=time.Minute{t.Fatalf("unexpected backoff reset threshold: %v",reconnectStableAfter)}
}
