/**
* @program: go
*
* @description:
*
* @author: lemo
*
* @create: 2023-01-06 10:53
**/

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var defaultDNS = []string{"8.8.8.8"}

var dnsCache = &cache{}

type cache struct {
	data map[string]*data
	mux  sync.RWMutex
}

type data struct {
	a  []dns.RR
	ip string
	t  time.Time
}

func (c *cache) init() {
	c.data = make(map[string]*data)
}

func (c *cache) Set(domain string, ip string, a []dns.RR) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.data[domain] = &data{a: a, ip: ip, t: time.Now()}
}

func (c *cache) Get(domain string) (string, []dns.RR) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	if d, ok := c.data[domain]; ok {
		if time.Now().Sub(d.t) < time.Minute*3 {
			return d.ip, d.a
		}
	}
	return "", nil
}

type handler struct{}

var domainMap = make(map[string]string)
var matchDomainMap = make(map[string]string)

func (t *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var msg = &dns.Msg{}
	msg.SetReply(r)

	var domain = msg.Question[0].Name
	var tp = r.Question[0].Qtype
	// && tp != dns.TypeHTTPS
	if tp != dns.TypeA {
		err := w.WriteMsg(msg)
		if err != nil {
			println(err.Error())
		}
		return
	}

	msg.Authoritative = true

	// cache
	var ip, aCache = dnsCache.Get(domain)
	if aCache != nil {
		msg.Answer = aCache
		doHandler(w, domain, ip, msg)
		return
	}

	ip = domainMap[domain]
	if ip == "" {
		ip = matchDomain(domain)
	}

	if ip != "" {
		var rr []dns.RR
		var a = &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: tp, Class: dns.ClassINET, Ttl: 1},
			A:   net.ParseIP(ip),
		}
		rr = append(rr, a)
		msg.Answer = rr
		dnsCache.Set(domain, ip, rr)

		doHandler(w, domain, ip, msg)
		return
	}

	var err error
	var res = &dns.Msg{}
	var qes = (&dns.Msg{}).SetQuestion(domain, tp)
	for i := 0; i < len(defaultDNS); i++ {
		res, err = dns.Exchange(qes, defaultDNS[i]+":53")
		if err != nil {
			println("trying to exchange", defaultDNS[i], "failed:", err.Error())
		} else {
			break
		}
	}

	var rr []dns.RR

	for _, i2 := range res.Answer {
		if i2.Header().Rrtype == tp {
			ip = i2.(*dns.A).A.String()
			var a = &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: tp, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			}
			rr = append(rr, a)
		}
	}

	msg.Answer = rr
	dnsCache.Set(domain, ip, rr)

	doHandler(w, domain, ip, msg)
	return
}

func doHandler(w dns.ResponseWriter, domain, ip string, msg *dns.Msg) {
	println("domain:", domain[0:len(domain)-1], "ip:", ip)
	err := w.WriteMsg(msg)
	if err != nil {
		println(err.Error())
	}
}

func matchDomain(domain string) string {
	for dm, ip := range matchDomainMap {
		if strings.HasSuffix(domain, dm) {
			return ip
		}
	}
	return ""
}

func addDomain(domain, ip string) {
	if len(domain) == 0 {
		return
	}
	if domain[0:2] == "*." {
		matchDomainMap[domain[2:]+"."] = ip
	} else {
		domainMap[domain+"."] = ip
	}
}

func StartDNS(addr string, fn func()) {
	dnsCache.init()
	srv := &dns.Server{Addr: addr + ":" + strconv.Itoa(53), Net: "udp"}
	srv.Handler = &handler{}
	srv.NotifyStartedFunc = func() {
		fn()
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			println(err.Error())
		}
	}()
}

func main() {

	var configFile = GetArgs([]string{"-r", "--recover"}, os.Args[1:])
	var domain = GetArgs([]string{"-d", "--domain"}, os.Args[1:])
	var addr = GetArgs([]string{"-a", "--addr"}, os.Args[1:])
	var dnss = GetArgs([]string{"--default"}, os.Args[1:])

	if dnss != "" {
		defaultDNS = []string{}
		var arr = strings.Split(dnss, ",")
		for i := 0; i < len(arr); i++ {
			defaultDNS = append(defaultDNS, arr[i])
		}
	}

	if addr == "" {
		addr = "127.0.0.1"
	}

	if domain != "" {
		var arr = strings.Split(domain, ",")
		for i := 0; i < len(arr); i++ {
			var ds = strings.Split(arr[i], ":")
			addDomain(ds[0], ds[1])
		}
	}

	if configFile != "" {
		var f, err = os.Open(configFile)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		defer func() { _ = f.Close() }()
		bts, err := io.ReadAll(f)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}

		var arr = strings.Split(string(bts), "\n")
		for i := 0; i < len(arr); i++ {
			if arr[i] == "" {
				continue
			}

			var ds = strings.Split(arr[i], " ")
			if len(ds) < 2 {
				continue
			}

			addDomain(ds[0], ds[1])
		}
	}

	AddNameServer()

	StartDNS(addr, func() {
		println("DNS Network:", addr+":53")
		println("Default dns:", strings.Join(defaultDNS, " "))
		for dm, ip := range domainMap {
			println("->", dm[0:len(dm)-1], ip)
		}
		for dm, ip := range matchDomainMap {
			println("->", "*."+dm[0:len(dm)-1], ip)
		}
	})

	var signalList = []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, signalList...)
	<-signalChan
	signal.Stop(signalChan)
	DeleteNameServer()
}

func GetArgs(flag []string, args []string) string {
	for i := 0; i < len(args); i++ {
		for j := 0; j < len(flag); j++ {
			if args[i] == flag[j] {
				if i+1 < len(args) {
					return args[i+1]
				}
			}
		}
	}
	return ""
}

func GetDefaultNDS() {
	f, err := os.OpenFile("/etc/resolv.conf", os.O_RDWR, 0777)
	if err != nil {
		println(err.Error())
		os.Exit(0)
	}

	defer func() { _ = f.Close() }()

	var lines []string

	var reader = bufio.NewReader(f)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			println(err.Error())
			os.Exit(0)
		}

		lines = append(lines, line)
	}

	var arr []string

	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "nameserver") {
			arr = append(arr, strings.TrimSpace(strings.ReplaceAll(lines[i], "nameserver", "")))
		}
	}

	if len(arr) != 0 {
		defaultDNS = arr
	}
}

func AddNameServer() {
	if runtime.GOOS == "darwin" {
		GetDefaultNDS()
		addNameServerDarwin()
	}
}

func addNameServerDarwin() {
	var fn = func(domain, ip string) {
		str := fmt.Sprintf("domain %s\nnameserver %s", domain, ip)
		name := `/etc/resolver/` + domain + `.local`
		f, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0755)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		_, err = f.WriteString(str)
		if err != nil {
			println(err.Error())
			os.Exit(0)
		}
		_ = f.Close()
		println("Create", name)
	}

	for dm, ip := range domainMap {
		fn(dm[0:len(dm)-1], ip)
	}

	for dm, ip := range matchDomainMap {
		fn(dm[0:len(dm)-1], ip)
	}
}

func DeleteNameServer() {
	if runtime.GOOS == "darwin" {
		deleteNameServerDarwin()
	}
}

func deleteNameServerDarwin() {
	var fn = func(domain, ip string) {
		name := `/etc/resolver/` + domain + `.local`
		err := os.Remove(name)
		if err != nil {
			println(err.Error())
		}
		println("Delete", name)
	}

	for dm, ip := range domainMap {
		fn(dm[0:len(dm)-1], ip)
	}

	for dm, ip := range matchDomainMap {
		fn(dm[0:len(dm)-1], ip)
	}
}
