package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// --- PROMETHEUS METRICS ---
var (
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_api_request_duration_seconds",
			Help:    "Time taken to process DNS API requests",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5},
		},
		[]string{"status", "resolver"},
	)

	dnsQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_query_duration_seconds",
			Help:    "Time taken for upstream DNS queries",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2},
		},
		[]string{"rtype", "resolver", "transport"},
	)

	dnsRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_api_requests_total",
			Help: "Total number of DNS API requests",
		},
		[]string{"status"},
	)

	activeGoroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dns_api_active_workers",
			Help: "Number of currently active DNS lookup workers",
		},
	)
)

func init() {
	prometheus.MustRegister(requestDuration, dnsQueryDuration, dnsRequestTotal, activeGoroutines)
}

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
	Port             string
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	GlobalTimeout    time.Duration
	DNSLookupTimeout time.Duration
	MaxGlobalConcur  int
	RateLimit        rate.Limit
	RateLimitBurst   int
	TrustedProxies   []string
}

type DNSChecker struct {
	config    Config
	limiters  sync.Map
	globalSem chan struct{}
}

// --- CONFIG & SETUP ---

func loadConfig() Config {
	cfg := Config{
		Port:             getEnv("PORT", "3000"),
		ReadTimeout:      10 * time.Second,
		WriteTimeout:     10 * time.Second,
		IdleTimeout:      30 * time.Second,
		GlobalTimeout:    6 * time.Second,
		DNSLookupTimeout: 2 * time.Second,
		MaxGlobalConcur:  1000,
		RateLimit:        rate.Every(time.Second / 5),
		RateLimitBurst:   10,
	}

	if proxies := getEnv("TRUSTED_PROXIES", ""); proxies != "" {
		cfg.TrustedProxies = strings.Split(proxies, ",")
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func NewDNSChecker(cfg Config) *DNSChecker {
	return &DNSChecker{
		config:    cfg,
		globalSem: make(chan struct{}, cfg.MaxGlobalConcur),
	}
}

// --- RATE LIMITER & IP LOGIC ---

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func (dc *DNSChecker) getLimiter(ip string) *rate.Limiter {
	now := time.Now()
	val, exists := dc.limiters.Load(ip)
	if exists {
		cl := val.(*clientLimiter)
		cl.lastSeen = now
		return cl.limiter
	}
	limiter := rate.NewLimiter(dc.config.RateLimit, dc.config.RateLimitBurst)
	dc.limiters.Store(ip, &clientLimiter{limiter: limiter, lastSeen: now})
	return limiter
}

func (dc *DNSChecker) cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			dc.limiters.Range(func(key, value any) bool {
				cl := value.(*clientLimiter)
				if time.Since(cl.lastSeen) > 1*time.Hour {
					dc.limiters.Delete(key)
				}
				return true
			})
		case <-ctx.Done():
			return
		}
	}
}

func (dc *DNSChecker) getClientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = r.RemoteAddr
	}

	if len(dc.config.TrustedProxies) == 0 {
		return remoteIP
	}

	isTrusted := false
	for _, proxy := range dc.config.TrustedProxies {
		if proxy == remoteIP {
			isTrusted = true
			break
		}
	}

	if isTrusted {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
	}
	return remoteIP
}

// --- DNS CORE LOGIC ---

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

func (dc *DNSChecker) robustQuery(ctx context.Context, domain string, qtype uint16, resolverIP string) ([]dns.RR, error) {
	select {
	case dc.globalSem <- struct{}{}:
		activeGoroutines.Inc()
		defer func() {
			<-dc.globalSem
			activeGoroutines.Dec()
		}()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	c := new(dns.Client)
	c.Timeout = dc.config.DNSLookupTimeout
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.SetEdns0(4096, true)

	start := time.Now()
	transport := "udp"
	resp, _, err := c.ExchangeContext(ctx, msg, resolverIP+":53")

	if err == nil && resp != nil && resp.Truncated {
		c.Net = "tcp"
		transport = "tcp"
		resp, _, err = c.ExchangeContext(ctx, msg, resolverIP+":53")
	}

	duration := time.Since(start).Seconds()
	dnsQueryDuration.WithLabelValues(dns.TypeToString[qtype], resolverIP, transport).Observe(duration)

	if err != nil {
		return nil, err
	}
	return resp.Answer, nil
}

func (dc *DNSChecker) quickHostLookup(ctx context.Context, host string, resolverIP string) string {
	rrs, err := dc.robustQuery(ctx, host, dns.TypeA, resolverIP)
	if err == nil {
		for _, rr := range rrs {
			if a, ok := rr.(*dns.A); ok {
				return a.A.String()
			}
		}
	}
	return ""
}

func (dc *DNSChecker) Lookup(ctx context.Context, domain string, resolverName string) DNSRecord {
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(ctx, dc.config.GlobalTimeout)
	defer cancel()

	resolverIP := dc.getResolverIP(resolverName)

	result := DNSRecord{
		Domain:    domain,
		Resolver:  resolverIP,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Errors:    []string{},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	isIP := net.ParseIP(domain) != nil

	addError := func(err string) {
		mu.Lock()
		result.Errors = append(result.Errors, err)
		mu.Unlock()
	}

	if isIP {
		// --- PTR LOOKUP ---
		wg.Add(1)
		go func() {
			defer wg.Done()
			reverse, err := dns.ReverseAddr(domain)
			if err != nil {
				addError("Invalid IP for PTR")
				return
			}
			rrs, err := dc.robustQuery(ctx, reverse, dns.TypePTR, resolverIP)
			if err != nil {
				addError(fmt.Sprintf("PTR lookup failed: %v", err))
				return
			}
			mu.Lock()
			for _, rr := range rrs {
				if ptr, ok := rr.(*dns.PTR); ok {
					result.PTR = append(result.PTR, PTRRecord{
						Value: strings.TrimSuffix(ptr.Ptr, "."),
						TTL:   ptr.Hdr.Ttl,
					})
				}
			}
			mu.Unlock()
		}()
	} else {
		// --- DOMAIN LOOKUPS ---

		// 1. A Records
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rrs, err := dc.robustQuery(ctx, domain, dns.TypeA, resolverIP); err == nil {
				mu.Lock()
				for _, rr := range rrs {
					if a, ok := rr.(*dns.A); ok {
						result.A = append(result.A, ARecord{IP: a.A.String(), TTL: a.Hdr.Ttl})
					}
				}
				mu.Unlock()
			}
		}()

		// 2. AAAA Records
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rrs, err := dc.robustQuery(ctx, domain, dns.TypeAAAA, resolverIP); err == nil {
				mu.Lock()
				for _, rr := range rrs {
					if aaaa, ok := rr.(*dns.AAAA); ok {
						result.AAAA = append(result.AAAA, AAAARecord{IP: aaaa.AAAA.String(), TTL: aaaa.Hdr.Ttl})
					}
				}
				mu.Unlock()
			}
		}()

		// 3. NS Records
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rrs, err := dc.robustQuery(ctx, domain, dns.TypeNS, resolverIP); err == nil {
				var nsList []NSRecord
				var nsWg sync.WaitGroup
				var nsMu sync.Mutex

				for _, rr := range rrs {
					if ns, ok := rr.(*dns.NS); ok {
						nsHost := strings.TrimSuffix(ns.Ns, ".")
						nsWg.Add(1)
						go func(host string, ttl uint32) {
							defer nsWg.Done()
							ip := dc.quickHostLookup(ctx, host, resolverIP)
							nsMu.Lock()
							nsList = append(nsList, NSRecord{Host: host, IP: ip, TTL: ttl})
							nsMu.Unlock()
						}(nsHost, ns.Hdr.Ttl)
					}
				}
				nsWg.Wait()
				mu.Lock()
				result.NS = append(result.NS, nsList...)
				mu.Unlock()
			}
		}()

		// 4. MX Records
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rrs, err := dc.robustQuery(ctx, domain, dns.TypeMX, resolverIP); err == nil {
				var mxList []MXRecord
				var mxWg sync.WaitGroup
				var mxMu sync.Mutex

				for _, rr := range rrs {
					if mx, ok := rr.(*dns.MX); ok {
						mxHost := strings.TrimSuffix(mx.Mx, ".")
						mxWg.Add(1)
						go func(host string, pref uint16, ttl uint32) {
							defer mxWg.Done()
							ip := dc.quickHostLookup(ctx, host, resolverIP)
							mxMu.Lock()
							mxList = append(mxList, MXRecord{Host: host, Pref: pref, IP: ip, TTL: ttl})
							mxMu.Unlock()
						}(mxHost, mx.Preference, mx.Hdr.Ttl)
					}
				}
				mxWg.Wait()
				mu.Lock()
				result.MX = append(result.MX, mxList...)
				mu.Unlock()
			}
		}()

		// 5. TXT, CNAME, SOA, SRV, CAA
		wg.Add(5)

		go func() { defer wg.Done(); simpleQuery[dns.TXT](dc, ctx, domain, resolverIP, &result, &mu) }()
		go func() { defer wg.Done(); simpleQuery[dns.CNAME](dc, ctx, domain, resolverIP, &result, &mu) }()
		go func() { defer wg.Done(); simpleQuery[dns.SOA](dc, ctx, domain, resolverIP, &result, &mu) }()
		go func() { defer wg.Done(); simpleQuery[dns.SRV](dc, ctx, domain, resolverIP, &result, &mu) }()
		go func() { defer wg.Done(); simpleQuery[dns.CAA](dc, ctx, domain, resolverIP, &result, &mu) }()
	}

	wg.Wait()
	result.LookupTime = time.Since(startTime).Milliseconds()
	return result
}

func simpleQuery[T any](dc *DNSChecker, ctx context.Context, domain, resolverIP string, result *DNSRecord, mu *sync.Mutex) {
	var qtype uint16
	switch any(new(T)).(type) {
	case *dns.TXT:
		qtype = dns.TypeTXT
	case *dns.CNAME:
		qtype = dns.TypeCNAME
	case *dns.SOA:
		qtype = dns.TypeSOA
	case *dns.SRV:
		qtype = dns.TypeSRV
	case *dns.CAA:
		qtype = dns.TypeCAA
	}

	rrs, err := dc.robustQuery(ctx, domain, qtype, resolverIP)
	if err != nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.TXT:
			result.TXT = append(result.TXT, TXTRecord{Value: strings.Join(v.Txt, ""), TTL: v.Hdr.Ttl})
		case *dns.CNAME:
			result.CNAME = &CNAMERecord{Target: strings.TrimSuffix(v.Target, "."), TTL: v.Hdr.Ttl}
		case *dns.SOA:
			result.SOA = &SOARecord{
				NS: strings.TrimSuffix(v.Ns, "."), Mbox: strings.TrimSuffix(v.Mbox, "."),
				Serial: v.Serial, Refresh: v.Refresh, Retry: v.Retry, Expire: v.Expire, Minttl: v.Minttl, TTL: v.Hdr.Ttl,
			}
		case *dns.SRV:
			result.SRV = append(result.SRV, SRVRecord{
				Target: strings.TrimSuffix(v.Target, "."), Port: v.Port,
				Priority: v.Priority, Weight: v.Weight, TTL: v.Hdr.Ttl,
			})
		case *dns.CAA:
			result.CAA = append(result.CAA, CAARecord{Tag: v.Tag, Value: v.Value, Flags: v.Flag, TTL: v.Hdr.Ttl})
		}
	}
}

// --- UTILS ---

func sanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	return strings.TrimSuffix(domain, ".")
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainRegex.MatchString(domain)
}

// --- HANDLERS ---

func (dc *DNSChecker) handleLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}
	domain = sanitizeDomain(domain)

	if !isValidDomain(domain) && net.ParseIP(domain) == nil {
		http.Error(w, `{"error":"invalid domain or ip"}`, http.StatusBadRequest)
		return
	}

	resolver := r.URL.Query().Get("resolver")
	if resolver == "" {
		resolver = "cloudflare"
	}

	result := dc.Lookup(r.Context(), domain, resolver)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (dc *DNSChecker) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ip := dc.getClientIP(r)
		limiter := dc.getLimiter(ip)

		if !limiter.Allow() {
			dnsRequestTotal.WithLabelValues("rate_limited").Inc()
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		rw := &responseWriter{ResponseWriter: w, statusCode: 200}
		next(rw, r)

		duration := time.Since(start).Seconds()
		requestDuration.WithLabelValues(fmt.Sprintf("%d", rw.statusCode), r.URL.Query().Get("resolver")).Observe(duration)
		dnsRequestTotal.WithLabelValues(fmt.Sprintf("%d", rw.statusCode)).Inc()

		slog.Info("Request", "ip", ip, "status", rw.statusCode, "dur", duration, "path", r.URL.Path)
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// --- MAIN ---

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := loadConfig()
	dc := NewDNSChecker(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go dc.cleanupLimiters(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/lookup", dc.middleware(dc.handleLookup))
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// HTML UI
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
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// 5. Graceful Shutdown
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("Server starting", "port", cfg.Port)
		serverErrors <- server.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		slog.Error("Server error", "error", err)
	case <-shutdown:
		slog.Info("Server shutting down...")
		timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer timeoutCancel()

		if err := server.Shutdown(timeoutCtx); err != nil {
			slog.Error("Graceful shutdown failed", "error", err)
			if err := server.Close(); err != nil {
				slog.Error("Forced close failed", "error", err)
			}
		}
	}
	slog.Info("Server stopped")
}
