package main

import (
	"flag"
	"fmt"
	"github.com/caryxiao/go-zlog"
	shd "github.com/caryxiao/ssh-hosts-deny"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	var Config shd.CmdConfig
	var logPath string
	var logLevel int

	flag.StringVar(&Config.SecureFile, "sf", "", "Please specify a file you need to monitor")
	flag.StringVar(&Config.DenyFile, "df", "/etc/hosts.deny", "hosts.deny file path")
	flag.IntVar(&Config.SshLoginFailCnt, "cnt", 5, "ssh login failed count")
	flag.BoolVar(&Config.PrintVer, "v", false, "print version")
	flag.StringVar(&logPath, "log-path", "", "log save path, default terminal output")
	flag.IntVar(&logLevel, "log-level", 5, "log level, default:5, trace:6, debug:5, info:4, warning:3, error:2, fatal:1, panic:0")

	flag.StringVar(&Config.CheckStyle, "check-style", "password", "check style: pam or password")

	flag.Parse()

	if Config.PrintVer {
		shd.PrintVersion()
		os.Exit(0)
	}

	if logPath != "" {
		// set log path
		zlog.SetOutput(logPath)
	}

	// set log level
	zlog.SetLevel(logLevel)

	// set log format style
	zlog.SetFormat("[%level%]: %time% - [%trace_id%] %msg%")

	zlog.Logger.Debugf("%#v", Config)

	err := shd.Watch(Config)

	if err != nil { //exit when an error is found
		os.Exit(0)
	}

	waitSignal()
}

func waitSignal() {
	var signalChan = make(chan os.Signal, 2)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	for sig := range signalChan {
		if sig == syscall.SIGHUP {
			fmt.Println("SIGHUP")
		} else if sig == syscall.SIGINT {
			zlog.Logger.Debugf("signal: %v, ctrl+c", sig)
			os.Exit(0)
		} else {
			zlog.Logger.Debugf("signal: %v", sig)
			os.Exit(0)
		}
	}
}
