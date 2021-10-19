package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/underscorenico/dnsv/internal/config"
	"github.com/underscorenico/dnsv/internal/dns"

	"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		signal.Stop(signals)
	}()

	go func() {
		<-signals
		os.Exit(1)
	}()

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	var config config.Config

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("error reading config file, %s", err)
	}
	err := viper.Unmarshal(&config)
	if err != nil {
		log.Fatalf("bad formatted configuration, %v", err)
	}
	log.SetFormatter(&log.JSONFormatter{})
	v := dns.NewDNSValidator(config)
	panic(v.MainLoop())
}
