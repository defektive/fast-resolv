// reincarnated from https://github.com/threatstream/go-bulk-dns-resolver/blob/master/main.go
package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"github.com/asaskevich/govalidator"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	ver "github.com/analog-substance/util/cli/version"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"

	homedir "github.com/mitchellh/go-homedir"
)

var version = "v0.0.0"
var commit = "replace"

type (
	Result struct {
		domain       string
		originalLine string
		addresses    []string
		txt          []string
		mx           []string
		cName        string
		hosts        []string
		addrErr      error
		txtErr       error
		mxErr        error
		cNameErr     error
		hostsErr     error
	}
)

var (
	domainCleanerRe = regexp.MustCompile(`^([0-9]+,)?([^\/]*)(?:\/.*)?$`)
	ipMatch         = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)
	ch              = make(chan Result, concurrency)
	unboundInstance = unbound.New()

	//go:embed fast-resolv.conf
	defaultConf []byte
	resolveConf string

	domainsFile   string
	concurrency   int
	lookupTimeout time.Duration
	maxAttempts   int
	outputLock    sync.Mutex
	versionFlag   bool
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func init() {
	home, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}

	confDir := filepath.Join(home, ".fast-resolv")
	if !exists(confDir) {
		_ = os.MkdirAll(confDir, 0755)
	}

	defaultResolvConf := filepath.Join(confDir, "fast-resolv.conf")
	if !exists(defaultResolvConf) {
		_ = os.WriteFile(defaultResolvConf, defaultConf, 0644)
	}

	flag.IntVar(&concurrency, "c", 100, "concurrent lookups")
	flag.DurationVar(&lookupTimeout, "t", 10, "lookup timeout")
	flag.IntVar(&maxAttempts, "a", 4, "Number of failed attempts before we give up")
	flag.StringVar(&resolveConf, "r", defaultResolvConf, "path to a resolv.conf")
	flag.StringVar(&domainsFile, "d", "domains.txt", "path to file with domains to lookup")
	flag.BoolVar(&versionFlag, "v", false, "Display version information")
}

func lookupHost(domain string, attemptNumber int) (addrs []string, err error) {
	timeout := make(chan error)
	go func() {
		addrs, err = unboundInstance.LookupHost(domain)
		timeout <- err
	}()

	select {
	case err = <-timeout:
		if err != nil {
			if attemptNumber < maxAttempts {
				return lookupHost(domain, attemptNumber+1)
			}
			syncPrintf("!!!!! failed: max attempts exhausted for domain=%s error=%s\n", domain, err)
		}
	case <-time.After(lookupTimeout * time.Second):
		err = fmt.Errorf("!!!!! error: timed out for \"%v\" after %v seconds", domain, lookupTimeout)
	}
	return addrs, err
}

func lookupAddr(addr string, attemptNumber int) (hosts []string, err error) {
	timeout := make(chan error)
	go func() {
		hosts, err = unboundInstance.LookupAddr(addr)
		timeout <- err
	}()

	select {
	case err = <-timeout:
		if err != nil {
			if attemptNumber < maxAttempts {
				return lookupHost(addr, attemptNumber+1)
			}
			syncPrintf("!!!!! failed: max attempts exhausted for addr=%s error=%s\n", addr, err)
		}
	case <-time.After(lookupTimeout * time.Second):
		err = fmt.Errorf("!!!!! error: timed out for \"%v\" after %v seconds", addr, lookupTimeout)
	}
	return hosts, err
}

func lookupTxt(domain string, attemptNumber int) (txts []string, err error) {
	timeout := make(chan error)
	go func() {
		txts, err = unboundInstance.LookupTXT(domain)
		timeout <- err
	}()

	select {
	case err = <-timeout:
		if err != nil {
			if attemptNumber < maxAttempts {
				return lookupTxt(domain, attemptNumber+1)
			}
			syncPrintf("!!!!! failed: max attempts exhausted for domain=%s error=%s\n", domain, err)
		}
	case <-time.After(lookupTimeout * time.Second):
		err = fmt.Errorf("!!!!! error: timed out for \"%v\" after %v seconds", domain, lookupTimeout)
	}
	return txts, err
}

func lookupMX(domain string, attemptNumber int) (mx []string, err error) {
	mxDNS := []*dns.MX{}
	timeout := make(chan error)
	go func() {
		mxDNS, err = unboundInstance.LookupMX(domain)
		timeout <- err
	}()

	select {
	case err = <-timeout:
		if err != nil {
			if attemptNumber < maxAttempts {
				return lookupMX(domain, attemptNumber+1)
			}
			syncPrintf("!!!!! failed: max attempts exhausted for domain=%s error=%s\n", domain, err)
		}
	case <-time.After(lookupTimeout * time.Second):
		err = fmt.Errorf("!!!!! error: timed out for \"%v\" after %v seconds", domain, lookupTimeout)
	}

	for _, mxRec := range mxDNS {
		mx = append(mx, fmt.Sprintf("%s", mxRec))
	}

	return mx, err
}

func lookupCName(domain string, attemptNumber int) (cname string, err error) {
	timeout := make(chan error)
	go func() {
		cname, err = unboundInstance.LookupCNAME(domain)
		timeout <- err
	}()

	select {
	case err = <-timeout:
		if err != nil {
			if attemptNumber < maxAttempts {
				return lookupCName(domain, attemptNumber+1)
			}
			syncPrintf("!!!!! failed: max attempts exhausted for domain=%s error=%s\n", domain, err)
		}
	case <-time.After(lookupTimeout * time.Second):
		err = fmt.Errorf("!!!!! error: timed out for \"%v\" after %v seconds", domain, lookupTimeout)
	}
	return cname, err
}

func resolve(domainStr string) {
	if ipMatch.MatchString(domainStr) {
		hosts, hostsErr := lookupAddr(domainStr, 1)
		ch <- Result{domainStr, "", nil, nil, nil, "", hosts, nil, nil, nil, nil, hostsErr}
	} else {
		domain := domainCleanerRe.ReplaceAllString(domainStr, "$2")

		addrs, addrErr := lookupHost(domain, 1)
		txts, txtErr := lookupTxt(domain, 1)
		mx, mxErr := lookupMX(domain, 1)
		cName, cNameErr := lookupCName(domain, 1)
		ch <- Result{domainStr, domain, addrs, txts, mx, cName, nil, addrErr, txtErr, mxErr, cNameErr, nil}
	}
}

func resolveWorker(linkChan chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for domain := range linkChan {
		resolve(domain)
	}
}

func syncPrintf(msg string, args ...interface{}) {
	outputLock.Lock()
	fmt.Printf(msg, args...)
	err := os.Stdout.Sync()
	if err != nil {
		syncPrintf("!!!!! failed: sync err=%s\n", err)
	}
	outputLock.Unlock()
}

func getDomains() []string {
	domains := []string{}

	var scanner *bufio.Scanner

	if domainsFile == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		file, err := os.Open(domainsFile)
		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		domain := scanner.Text()
		if govalidator.IsDNSName(domain) {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return domains

}
func main() {
	flag.Parse()

	if versionFlag {
		fmt.Printf("fast-resolv %s\n", ver.GetVersionInfo(version, commit))
		os.Exit(0)
	}

	unboundInstance.ResolvConf(resolveConf)
	domains := getDomains()

	if len(domains) == 0 {
		fmt.Println("[!] No Domains found")
		return
	}

	for _, domain := range domains {
		fmt.Println(domain)
	}

	tasks := make(chan string, concurrency)

	// Spawn resolveWorker goroutines.
	wg := new(sync.WaitGroup)

	// Adding routines to workgroup and running then.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go resolveWorker(tasks, wg)
	}

	receiver := func(numDomains int) {
		defer wg.Done()

		i := 0
	Loop:
		for {
			select {
			case result := <-ch:
				for _, ip := range result.addresses {
					syncPrintf("%s has address %s\n", result.domain, ip)
				}

				for _, txt := range result.txt {
					syncPrintf("%s has TXT %s\n", result.domain, txt)
				}

				for _, mx := range result.mx {
					syncPrintf("%s has MX %s\n", result.domain, mx)
				}

				for _, host := range result.hosts {
					syncPrintf("%s domain name pointer %s\n", result.domain, host)
				}

				if len(result.cName) > 0 {
					syncPrintf("%s is an alias for %s\n", result.domain, result.cName)
				}

				i++
				if i == numDomains {
					break Loop
				}
			}
		}
	}

	wg.Add(1)
	go receiver(len(domains))

	// Processing all links by spreading them to `free` goroutines
	for _, domain := range domains {
		tasks <- domain
	}

	close(tasks)

	wg.Wait()
}
