package logging

import (
  "fmt"
  "log/slog"
  "os"
  "strings"
)

type Options struct{ Level slog.Level; Format string }

func ParseLevel(value string)(slog.Level,error){
  switch strings.ToLower(strings.TrimSpace(value)){
  case "", "info":return slog.LevelInfo,nil
  case "debug":return slog.LevelDebug,nil
  case "warn","warning":return slog.LevelWarn,nil
  case "error":return slog.LevelError,nil
  default:return 0,fmt.Errorf("invalid log level %q; expected debug|info|warn|error",value)
  }
}

// Extract strips common --log-level and --log-format options before routing
// remaining arguments to the selected server/client CLI.
func Extract(args []string)([]string,Options,error){
  level:=os.Getenv("MQVPN_LOG_LEVEL")
  format:=os.Getenv("MQVPN_LOG_FORMAT")
  if format==""{format="text"}
  out:=make([]string,0,len(args))
  for i:=0;i<len(args);i++{
    a:=args[i]
    switch{
    case a=="--log-level"||a=="--log-format":
      if i+1>=len(args){return nil,Options{},fmt.Errorf("%s requires a value",a)}
      i++
      if a=="--log-level"{level=args[i]}else{format=args[i]}
    case strings.HasPrefix(a,"--log-level="):level=strings.TrimPrefix(a,"--log-level=")
    case strings.HasPrefix(a,"--log-format="):format=strings.TrimPrefix(a,"--log-format=")
    default:out=append(out,a)
    }
  }
  l,err:=ParseLevel(level)
  if err!=nil{return nil,Options{},err}
  format=strings.ToLower(strings.TrimSpace(format))
  if format!="text"&&format!="json"{return nil,Options{},fmt.Errorf("invalid log format %q; expected text|json",format)}
  return out,Options{Level:l,Format:format},nil
}

func New(opts Options)*slog.Logger{
  handlerOpts:=&slog.HandlerOptions{Level:opts.Level}
  if opts.Format=="json"{return slog.New(slog.NewJSONHandler(os.Stderr,handlerOpts))}
  return slog.New(slog.NewTextHandler(os.Stderr,handlerOpts))
}
