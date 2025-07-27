package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type NSRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip,omitempty"`
	TTL  uint32 `json:"ttl,omitempty"`
}

type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"preference"`
	IP   string `json:"ip,omitempty"`
	TTL  uint32 `json:"ttl,omitempty"`
}

type TXTRecord struct {
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type SOARecord struct {
	NS      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minttl  uint32 `json:"min_ttl"`
	TTL     uint32 `json:"ttl,omitempty"`
}

type SRVRecord struct {
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	TTL      uint32 `json:"ttl,omitempty"`
}

type CAARecord struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
	Flags uint8  `json:"flags"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type ARecord struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl,omitempty"`
}

type AAAARecord struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl,omitempty"`
}

type PTRRecord struct {
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type CNAMERecord struct {
	Target string `json:"target"`
	TTL    uint32 `json:"ttl,omitempty"`
}

type DNSRecord struct {
	Domain     string       `json:"domain"`
	A          []ARecord    `json:"a,omitempty"`
	AAAA       []AAAARecord `json:"aaaa,omitempty"`
	NS         []NSRecord   `json:"ns,omitempty"`
	MX         []MXRecord   `json:"mx,omitempty"`
	TXT        []TXTRecord  `json:"txt,omitempty"`
	CNAME      *CNAMERecord `json:"cname,omitempty"`
	SOA        *SOARecord   `json:"soa,omitempty"`
	PTR        []PTRRecord  `json:"ptr,omitempty"`
	SRV        []SRVRecord  `json:"srv,omitempty"`
	CAA        []CAARecord  `json:"caa,omitempty"`
	Resolver   string       `json:"resolver"`
	LookupTime int64        `json:"lookup_time_ms"`
	Timestamp  string       `json:"timestamp"`
	Errors     []string     `json:"errors,omitempty"`
}

type Config struct {
	Timeout        time.Duration
	LookupTimeout  time.Duration
	MaxConcurrency int
	Port           string
	RateLimit      rate.Limit
	RateLimitBurst int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
}

type DNSChecker struct {
	config   Config
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	client   *dns.Client
}

func loadConfig() Config {
	config := Config{
		Timeout:        5 * time.Second,
		LookupTimeout:  3 * time.Second,
		MaxConcurrency: 10,
		Port:           "3000",
		RateLimit:      rate.Every(time.Second),
		RateLimitBurst: 10,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    30 * time.Second,
	}

	if timeout := os.Getenv("DNS_TIMEOUT"); timeout != "" {
		if parsed, err := time.ParseDuration(timeout); err == nil {
			config.Timeout = parsed
		}
	}

	if lookupTimeout := os.Getenv("DNS_LOOKUP_TIMEOUT"); lookupTimeout != "" {
		if parsed, err := time.ParseDuration(lookupTimeout); err == nil {
			config.LookupTimeout = parsed
		}
	}

	if maxConcurrency := os.Getenv("DNS_MAX_CONCURRENCY"); maxConcurrency != "" {
		if parsed, err := strconv.Atoi(maxConcurrency); err == nil && parsed > 0 {
			config.MaxConcurrency = parsed
		}
	}

	if port := os.Getenv("PORT"); port != "" {
		config.Port = port
	}

	if rateLimit := os.Getenv("RATE_LIMIT"); rateLimit != "" {
		if parsed, err := strconv.Atoi(rateLimit); err == nil && parsed > 0 {
			config.RateLimit = rate.Every(time.Second / time.Duration(parsed))
		}
	}

	if rateLimitBurst := os.Getenv("RATE_LIMIT_BURST"); rateLimitBurst != "" {
		if parsed, err := strconv.Atoi(rateLimitBurst); err == nil && parsed > 0 {
			config.RateLimitBurst = parsed
		}
	}

	return config
}

func NewDNSChecker() *DNSChecker {
	config := loadConfig()

	return &DNSChecker{
		config:   config,
		limiters: make(map[string]*rate.Limiter),
		client: &dns.Client{
			Timeout: config.LookupTimeout,
		},
	}
}

func (dc *DNSChecker) getRateLimiter(ip string) *rate.Limiter {
	dc.mu.RLock()
	limiter, exists := dc.limiters[ip]
	dc.mu.RUnlock()

	if !exists {
		dc.mu.Lock()
		limiter, exists = dc.limiters[ip]
		if !exists {
			limiter = rate.NewLimiter(dc.config.RateLimit, dc.config.RateLimitBurst)
			dc.limiters[ip] = limiter
		}
		dc.mu.Unlock()
	}

	return limiter
}

func (dc *DNSChecker) getClientIP(r *http.Request) string {
	// Check for X-Real-IP header (used by reverse proxies)
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Check for X-Forwarded-For header (used by load balancers)
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, get the first one
		if ips := strings.Split(ip, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (dc *DNSChecker) getResolverIP(resolver string) string {
	switch resolver {
	case "google":
		return "8.8.8.8"
	case "cloudflare":
		return "1.1.1.1"
	case "opendns":
		return "208.67.222.222"
	case "quad9":
		return "9.9.9.9"
	default:
		return "1.1.1.1"
	}
}

func (dc *DNSChecker) createResolver(resolver string) *net.Resolver {
	resolverIP := dc.getResolverIP(resolver)

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: dc.config.LookupTimeout}
			return d.DialContext(ctx, "udp", resolverIP+":53")
		},
	}
}

func isValidResolver(resolver string) bool {
	switch resolver {
	case "google", "cloudflare", "opendns", "quad9":
		return true
	default:
		return false
	}
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Check for valid characters and format
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainRegex.MatchString(domain)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func sanitizeDomain(domain string) string {
	// Remove leading/trailing whitespace
	domain = strings.TrimSpace(domain)
	// Convert to lowercase
	domain = strings.ToLower(domain)
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func reverseIP(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	if ipv4 := parsedIP.To4(); ipv4 != nil {
		// IPv4 reverse lookup
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
	}

	// IPv6 reverse lookup
	ipv6 := parsedIP.To16()
	var reversed []string
	for i := len(ipv6) - 1; i >= 0; i-- {
		reversed = append(reversed, fmt.Sprintf("%x", ipv6[i]&0xf))
		reversed = append(reversed, fmt.Sprintf("%x", ipv6[i]>>4))
	}
	return strings.Join(reversed, ".") + ".ip6.arpa"
}

func (dc *DNSChecker) queryDNS(domain string, qtype uint16, resolver string) (*dns.Msg, error) {
	resolverIP := dc.getResolverIP(resolver)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.SetEdns0(4096, true)

	response, _, err := dc.client.Exchange(msg, resolverIP+":53")
	if err != nil {
		return nil, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with rcode: %d", response.Rcode)
	}

	return response, nil
}

func (dc *DNSChecker) lookupWithFallback(ctx context.Context, domain string, resolver string) DNSRecord {
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(ctx, dc.config.Timeout)
	defer cancel()

	resolverInstance := dc.createResolver(resolver)
	resolverIP := dc.getResolverIP(resolver)

	result := DNSRecord{
		Domain:    domain,
		Resolver:  resolverIP,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Errors:    []string{},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, dc.config.MaxConcurrency)

	addError := func(errMsg string) {
		mu.Lock()
		result.Errors = append(result.Errors, errMsg)
		mu.Unlock()
	}

	// Check if input is an IP address for PTR lookup
	isIPAddress := isValidIP(domain)

	lookupFuncs := []func(){}

	if isIPAddress {
		// PTR lookup for IP addresses
		lookupFuncs = append(lookupFuncs, func() {
			defer wg.Done()
			reverseDomain := reverseIP(domain)
			if reverseDomain == "" {
				addError("Invalid IP address for PTR lookup")
				return
			}

			if response, err := dc.queryDNS(reverseDomain, dns.TypePTR, resolver); err == nil {
				mu.Lock()
				for _, rr := range response.Answer {
					if ptr, ok := rr.(*dns.PTR); ok {
						result.PTR = append(result.PTR, PTRRecord{
							Value: strings.TrimSuffix(ptr.Ptr, "."),
							TTL:   ptr.Hdr.Ttl,
						})
					}
				}
				mu.Unlock()
			} else {
				// Fallback to standard library
				if names, err := resolverInstance.LookupAddr(ctx, domain); err == nil {
					mu.Lock()
					for _, name := range names {
						result.PTR = append(result.PTR, PTRRecord{
							Value: strings.TrimSuffix(name, "."),
						})
					}
					mu.Unlock()
				} else {
					addError(fmt.Sprintf("PTR lookup failed: %v", err))
				}
			}
		})
	} else {
		// Regular domain lookups
		lookupFuncs = []func(){
			// A and AAAA records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeA, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if a, ok := rr.(*dns.A); ok {
							result.A = append(result.A, ARecord{
								IP:  a.A.String(),
								TTL: a.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					// Fallback to standard library
					if ips, err := resolverInstance.LookupIPAddr(ctx, domain); err == nil {
						mu.Lock()
						for _, ip := range ips {
							if ip.IP.To4() != nil {
								result.A = append(result.A, ARecord{IP: ip.IP.String()})
							}
						}
						mu.Unlock()
					} else {
						addError(fmt.Sprintf("A record lookup failed: %v", err))
					}
				}

				if response, err := dc.queryDNS(domain, dns.TypeAAAA, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							result.AAAA = append(result.AAAA, AAAARecord{
								IP:  aaaa.AAAA.String(),
								TTL: aaaa.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					// Fallback to standard library
					if ips, err := resolverInstance.LookupIPAddr(ctx, domain); err == nil {
						mu.Lock()
						for _, ip := range ips {
							if ip.IP.To4() == nil {
								result.AAAA = append(result.AAAA, AAAARecord{IP: ip.IP.String()})
							}
						}
						mu.Unlock()
					} else {
						addError(fmt.Sprintf("AAAA record lookup failed: %v", err))
					}
				}
			},

			// CNAME records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeCNAME, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if cname, ok := rr.(*dns.CNAME); ok {
							result.CNAME = &CNAMERecord{
								Target: strings.TrimSuffix(cname.Target, "."),
								TTL:    cname.Hdr.Ttl,
							}
							break
						}
					}
					mu.Unlock()
				} else {
					// Fallback to standard library
					if cname, err := resolverInstance.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
						mu.Lock()
						result.CNAME = &CNAMERecord{
							Target: strings.TrimSuffix(cname, "."),
						}
						mu.Unlock()
					} else if err != nil {
						addError(fmt.Sprintf("CNAME lookup failed: %v", err))
					}
				}
			},

			// NS records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeNS, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if ns, ok := rr.(*dns.NS); ok {
							nsHost := strings.TrimSuffix(ns.Ns, ".")
							ipAddrs, _ := resolverInstance.LookupHost(ctx, nsHost)
							ip := ""
							if len(ipAddrs) > 0 {
								ip = ipAddrs[0]
							}
							result.NS = append(result.NS, NSRecord{
								Host: nsHost,
								IP:   ip,
								TTL:  ns.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					// Fallback to standard library
					if ns, err := resolverInstance.LookupNS(ctx, domain); err == nil {
						mu.Lock()
						for _, n := range ns {
							ipAddrs, _ := resolverInstance.LookupHost(ctx, n.Host)
							ip := ""
							if len(ipAddrs) > 0 {
								ip = ipAddrs[0]
							}
							result.NS = append(result.NS, NSRecord{Host: n.Host, IP: ip})
						}
						mu.Unlock()
					} else {
						addError(fmt.Sprintf("NS lookup failed: %v", err))
					}
				}
			},

			// MX records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeMX, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if mx, ok := rr.(*dns.MX); ok {
							mxHost := strings.TrimSuffix(mx.Mx, ".")
							ipAddrs, _ := resolverInstance.LookupHost(ctx, mxHost)
							ip := ""
							if len(ipAddrs) > 0 {
								ip = ipAddrs[0]
							}
							result.MX = append(result.MX, MXRecord{
								Host: mxHost,
								Pref: mx.Preference,
								IP:   ip,
								TTL:  mx.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					// Fallback to standard library
					if mx, err := resolverInstance.LookupMX(ctx, domain); err == nil {
						mu.Lock()
						for _, m := range mx {
							ipAddrs, _ := resolverInstance.LookupHost(ctx, m.Host)
							ip := ""
							if len(ipAddrs) > 0 {
								ip = ipAddrs[0]
							}
							result.MX = append(result.MX, MXRecord{Host: m.Host, Pref: m.Pref, IP: ip})
						}
						mu.Unlock()
					} else {
						addError(fmt.Sprintf("MX lookup failed: %v", err))
					}
				}
			},

			// TXT records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeTXT, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if txt, ok := rr.(*dns.TXT); ok {
							result.TXT = append(result.TXT, TXTRecord{
								Value: strings.Join(txt.Txt, ""),
								TTL:   txt.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					// Fallback to standard library
					if txt, err := resolverInstance.LookupTXT(ctx, domain); err == nil {
						mu.Lock()
						for _, t := range txt {
							result.TXT = append(result.TXT, TXTRecord{Value: t})
						}
						mu.Unlock()
					} else {
						addError(fmt.Sprintf("TXT lookup failed: %v", err))
					}
				}
			},

			// SOA records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeSOA, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if soa, ok := rr.(*dns.SOA); ok {
							result.SOA = &SOARecord{
								NS:      strings.TrimSuffix(soa.Ns, "."),
								Mbox:    strings.TrimSuffix(soa.Mbox, "."),
								Serial:  soa.Serial,
								Refresh: soa.Refresh,
								Retry:   soa.Retry,
								Expire:  soa.Expire,
								Minttl:  soa.Minttl,
								TTL:     soa.Hdr.Ttl,
							}
							break
						}
					}
					mu.Unlock()
				} else {
					addError(fmt.Sprintf("SOA lookup failed: %v", err))
				}
			},

			// SRV records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeSRV, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if srv, ok := rr.(*dns.SRV); ok {
							result.SRV = append(result.SRV, SRVRecord{
								Target:   strings.TrimSuffix(srv.Target, "."),
								Port:     srv.Port,
								Priority: srv.Priority,
								Weight:   srv.Weight,
								TTL:      srv.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					addError(fmt.Sprintf("SRV lookup failed: %v", err))
				}
			},

			// CAA records
			func() {
				defer wg.Done()
				if response, err := dc.queryDNS(domain, dns.TypeCAA, resolver); err == nil {
					mu.Lock()
					for _, rr := range response.Answer {
						if caa, ok := rr.(*dns.CAA); ok {
							result.CAA = append(result.CAA, CAARecord{
								Tag:   caa.Tag,
								Value: caa.Value,
								Flags: caa.Flag,
								TTL:   caa.Hdr.Ttl,
							})
						}
					}
					mu.Unlock()
				} else {
					addError(fmt.Sprintf("CAA lookup failed: %v", err))
				}
			},
		}
	}

	wg.Add(len(lookupFuncs))
	for _, f := range lookupFuncs {
		sem <- struct{}{}
		go func(f func()) {
			defer func() { <-sem }()
			f()
		}(f)
	}
	wg.Wait()
	close(sem)

	result.LookupTime = time.Since(startTime).Milliseconds()
	return result
}

func (dc *DNSChecker) Lookup(ctx context.Context, domain string, resolver string) DNSRecord {
	return dc.lookupWithFallback(ctx, domain, resolver)
}

func (dc *DNSChecker) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := dc.getClientIP(r)
		limiter := dc.getRateLimiter(clientIP)

		if !limiter.Allow() {
			respondWithError(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func apiHandler(dc *DNSChecker) http.HandlerFunc {
	return dc.rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			respondWithError(w, "domain parameter is required", http.StatusBadRequest)
			return
		}

		// Sanitize domain
		domain = sanitizeDomain(domain)

		// Validate domain or IP
		if !isValidDomain(domain) && !isValidIP(domain) {
			respondWithError(w, "invalid domain or IP address format", http.StatusBadRequest)
			return
		}

		resolver := r.URL.Query().Get("resolver")
		if resolver == "" {
			resolver = "cloudflare"
		} else if !isValidResolver(resolver) {
			respondWithError(w, "invalid resolver specified. Valid options: google, cloudflare, opendns, quad9", http.StatusBadRequest)
			return
		}

		result := dc.Lookup(r.Context(), domain, resolver)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if err := json.NewEncoder(w).Encode(result); err != nil {
			respondWithError(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
	}
	json.NewEncoder(w).Encode(health)
}

func respondWithError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

var startTime = time.Now()

func main() {
	dc := NewDNSChecker()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/lookup", apiHandler(dc))
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <title>DNS Lookup API</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .example { background: #e8f4f8; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>DNS Lookup API</h1>
    <p>A comprehensive DNS lookup service with support for multiple record types and resolvers.</p>
    
    <h2>Endpoints</h2>
    <div class="endpoint">
        <strong>GET /api/lookup</strong><br>
        Parameters: domain (required - domain name or IP address), resolver (optional: google, cloudflare, opendns, quad9)
    </div>
    <div class="endpoint">
        <strong>GET /health</strong><br>
        Health check endpoint
    </div>
    
    <h2>Example Usage</h2>
    <div class="example">
        <strong>Domain lookup:</strong><br>
        <code>/api/lookup?domain=example.com&resolver=cloudflare</code>
    </div>
    <div class="example">
        <strong>PTR (reverse DNS) lookup:</strong><br>
        <code>/api/lookup?domain=8.8.8.8&resolver=google</code>
    </div>
    
    <h2>Supported Record Types</h2>
    <p>A, AAAA, NS, MX, TXT, CNAME, SOA, SRV, CAA, PTR (reverse DNS)</p>
    
    <h2>Rate Limiting</h2>
    <p>Rate limiting is applied per IP address to ensure fair usage.</p>
</body>
</html>`))
	})

	server := &http.Server{
		Addr:         ":" + dc.config.Port,
		Handler:      mux,
		ReadTimeout:  dc.config.ReadTimeout,
		WriteTimeout: dc.config.WriteTimeout,
		IdleTimeout:  dc.config.IdleTimeout,
	}

	fmt.Printf("DNS Lookup API Server starting on port %s\n", dc.config.Port)
	fmt.Printf("Available endpoints:\n")
	fmt.Printf("  - GET /api/lookup?domain=example.com&resolver=cloudflare\n")
	fmt.Printf("  - GET /api/lookup?domain=8.8.8.8&resolver=google (PTR lookup)\n")
	fmt.Printf("  - GET /health\n")
	fmt.Printf("  - GET / (documentation)\n")
	fmt.Printf("\nSupported resolvers: google, cloudflare, opendns, quad9\n")
	fmt.Printf("Rate limit: %v requests per second per IP\n", dc.config.RateLimit)
	fmt.Printf("Features:\n")
	fmt.Printf("  - Forward DNS lookups (A, AAAA, NS, MX, TXT, CNAME, SOA, SRV, CAA)\n")
	fmt.Printf("  - Reverse DNS lookups (PTR)\n")
	fmt.Printf("  - IP-based rate limiting\n")
	fmt.Printf("  - Multiple DNS resolvers\n")
	fmt.Printf("  - Concurrent DNS queries\n")
	fmt.Printf("  - Fallback to standard library\n")

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
