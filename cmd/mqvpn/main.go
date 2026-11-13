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

func main(){
    ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
    defer stop()
    if len(os.Args)<2{fmt.Fprintln(os.Stderr,"usage: mqvpn server|client [options]");os.Exit(2)}
    if os.Args[1]=="help"||os.Args[1]=="-h"||os.Args[1]=="--help"{
        fmt.Println("usage: mqvpn server|client [options]")
        return
    }
    args,opts,err:=logging.Extract(os.Args[2:])
    if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
    logger:=logging.New(opts)
    switch os.Args[1]{
    case "server":err=app.RunServer(ctx,args,logger)
    case "client":err=app.RunClient(ctx,args,logger)
    default:err=fmt.Errorf("unknown subcommand %q",os.Args[1])
    }
    if err!=nil&&!errors.Is(err,context.Canceled)&&!errors.Is(err,flag.ErrHelp){
        logger.Error("mqvpn terminated","error",err)
        os.Exit(1)
    }
}
