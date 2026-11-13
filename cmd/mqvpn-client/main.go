package main

import (
    "context"
    "errors"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/roseshot/mqvpn-ebpf/internal/app"
    "github.com/roseshot/mqvpn-ebpf/internal/logging"
)

func main() {
    ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
    defer stop()
    args,opts,err:=logging.Extract(os.Args[1:])
    logger:=logging.New(opts)
    if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
    err=app.RunClient(ctx,args,logger)
    if err!=nil&&!errors.Is(err,context.Canceled)&&!errors.Is(err,flag.ErrHelp){
        logger.Error("mqvpn terminated","error",err)
        os.Exit(1)
    }
}
