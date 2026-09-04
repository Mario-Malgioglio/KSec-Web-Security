package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort = "8080"
	appName     = "KSec - Auditor servidores Web"
)

var (
	appServer      *http.Server
	shutdownLock   sync.Mutex
	shutdownTimer  *time.Timer
	isShuttingDown bool
	hasConnected   bool
	activeTabs     = make(map[string]time.Time)
	tabsMutex      sync.Mutex
)

type HeartbeatPayload struct {
	TabID  string `json:"tabId"`
	Action string `json:"action"` // "ping" or "leave"
}

// Data models for audit results
type AuditRequest struct {
	URL string `json:"url"`
}

type RemediationSnippet struct {
	Nginx   string `json:"nginx"`
	Apache  string `json:"apache"`
	Express string `json:"express"`
	Caddy   string `json:"caddy"`
}

type AuditRuleResult struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	HeaderName         string             `json:"headerName"`
	Category           string             `json:"category"`
	Status             string             `json:"status"` // pass, warning, fail, info
	Description        string             `json:"description"`
	ValueFound         string             `json:"valueFound"`
	RecommendedValue   string             `json:"recommendedValue"`
	ScoreImpact        int                `json:"scoreImpact"`
	MDNUrl             string             `json:"mdnUrl"`
	RemediationSnippet RemediationSnippet `json:"remediationSnippet"`
}

type SecurityAuditReport struct {
	TargetURL     string            `json:"targetUrl"`
	FinalURL      string            `json:"finalUrl"`
	StatusCode    int               `json:"statusCode"`
	LatencyMs     int64             `json:"latencyMs"`
	IsHTTPS       bool              `json:"isHttps"`
	Grade         string            `json:"grade"`
	Score         int               `json:"score"`
	TotalChecks   int               `json:"totalChecks"`
	PassedChecks  int               `json:"passedChecks"`
	WarningChecks int               `json:"warningChecks"`
	FailedChecks  int               `json:"failedChecks"`
	Summary       string            `json:"summary"`
	Timestamp     string            `json:"timestamp"`
	Headers       map[string]string `json:"headers"`
	Results       []AuditRuleResult `json:"results"`
}

type APIResponse struct {
	Success bool                 `json:"success"`
	Error   string               `json:"error,omitempty"`
	Report  *SecurityAuditReport `json:"report,omitempty"`
}

func main() {
	mux := http.NewServeMux()

	// Static & Web App handlers
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/audit", handleAudit)
	mux.HandleFunc("/api/heartbeat", handleHeartbeat)
	mux.HandleFunc("/api/shutdown", handleShutdown)

	serverAddr := ":" + defaultPort
	appURL := fmt.Sprintf("http://localhost:%s", defaultPort)

	fmt.Println("==================================================================")
	fmt.Printf("🦅  %s\n", appName)
	fmt.Printf("🚀  Servidor web iniciado en: %s\n", appURL)
	fmt.Println("🌐  Abriendo automáticamente en el navegador...")
	fmt.Println("🛑  Al cerrar el navegador, el aplicativo se cerrará y liberará la memoria.")
	fmt.Println("==================================================================")

	// Start background watchdog for browser closure
	go startWatchdog()

	// Open browser automatically in a separate goroutine
	go func() {
		time.Sleep(600 * time.Millisecond)
		openBrowser(appURL)
	}()

	appServer = &http.Server{
		Addr:         serverAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	if err := appServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error al iniciar el servidor: %v\n", err)
	}
}

// handleHeartbeat tracks active browser tabs and schedules shutdown when all are closed
func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p HeartbeatPayload
	_ = json.NewDecoder(r.Body).Decode(&p)
	if p.TabID == "" {
		p.TabID = "default"
	}

	tabsMutex.Lock()
	hasConnected = true

	if p.Action == "leave" {
		delete(activeTabs, p.TabID)
		remaining := len(activeTabs)
		tabsMutex.Unlock()

		if remaining == 0 {
			// All tabs closed: schedule shutdown after a brief grace period (1.5s) to allow F5/refresh
			scheduleShutdown(1500*time.Millisecond, "Navegador o pestaña cerrada")
		}
	} else {
		// Ping received: update timestamp and cancel any pending shutdown
		activeTabs[p.TabID] = time.Now()
		cancelScheduledShutdown()
		tabsMutex.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleShutdown triggers an explicit immediate shutdown upon user request
func handleShutdown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"shutting_down"}`))

	go func() {
		time.Sleep(200 * time.Millisecond)
		executeShutdown("Solicitud manual de cierre")
	}()
}

// startWatchdog continuously monitors active browser sessions and cleans up stale tabs
func startWatchdog() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tabsMutex.Lock()
		if !hasConnected {
			tabsMutex.Unlock()
			continue
		}

		now := time.Now()
		// Remove tabs that haven't sent a heartbeat in over 5 seconds
		for id, lastPing := range activeTabs {
			if now.Sub(lastPing) > 5*time.Second {
				delete(activeTabs, id)
			}
		}

		remaining := len(activeTabs)
		tabsMutex.Unlock()

		if remaining == 0 {
			scheduleShutdown(1500*time.Millisecond, "Sin conexión activa del navegador (pestañas cerradas)")
		}
	}
}

// scheduleShutdown prepares to shut down the server after a delay unless cancelled
func scheduleShutdown(delay time.Duration, reason string) {
	shutdownLock.Lock()
	defer shutdownLock.Unlock()

	if isShuttingDown {
		return
	}

	if shutdownTimer != nil {
		shutdownTimer.Stop()
	}

	shutdownTimer = time.AfterFunc(delay, func() {
		tabsMutex.Lock()
		remaining := len(activeTabs)
		tabsMutex.Unlock()

		if remaining > 0 {
			// Tab reconnected (e.g. page refresh)
			return
		}

		executeShutdown(reason)
	})
}

// cancelScheduledShutdown aborts a pending shutdown if the browser reconnects
func cancelScheduledShutdown() {
	shutdownLock.Lock()
	defer shutdownLock.Unlock()

	if shutdownTimer != nil {
		shutdownTimer.Stop()
		shutdownTimer = nil
	}
}

// executeShutdown terminates the server, forces garbage collection, frees OS memory, and exits
func executeShutdown(reason string) {
	shutdownLock.Lock()
	if isShuttingDown {
		shutdownLock.Unlock()
		return
	}
	isShuttingDown = true
	shutdownLock.Unlock()

	fmt.Println("\n==================================================================")
	fmt.Printf("🛑  %s\n", reason)
	fmt.Println("🧹  Liberando memoria de la aplicación (runtime.GC)...")
	runtime.GC()
	fmt.Println("💾  Devolviendo memoria física al sistema operativo (debug.FreeOSMemory)...")
	debug.FreeOSMemory()
	fmt.Println("👋  Aplicativo KSec finalizado completamente.")
	fmt.Println("==================================================================")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if appServer != nil {
			_ = appServer.Shutdown(ctx)
		}
		os.Exit(0)
	}()
}

// openBrowser launches the OS default web browser with the target URL
func openBrowser(targetURL string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default: // linux, freebsd, openbsd, netbsd
		cmd = exec.Command("xdg-open", targetURL)
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("Aviso: Para ingresar accede manualmente a: %s\n", targetURL)
	}
}

// handleIndex serves the embedded single-page HTML interface
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(embeddedHTML))
}

// handleAudit processes live website inspection and returns security score report
func handleAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: "Método no permitido"})
		return
	}

	var req AuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: "JSON de solicitud inválido"})
		return
	}

	target := strings.TrimSpace(req.URL)
	if target == "" {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: "Por favor ingresa una URL válida"})
		return
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil || parsedURL.Host == "" {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: fmt.Sprintf("La URL '%s' no es válida", target)})
		return
	}

	// Create custom HTTP client with timeout & TLS config
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	httpReq, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: "Error al construir la solicitud HTTP"})
		return
	}

	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (KSec Security Auditor)")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "es-ES,es;q=0.9,en;q=0.8")

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	latency := time.Since(startTime).Milliseconds()

	if err != nil {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Error de conexión al escanear %s: %v", parsedURL.Host, err),
		})
		return
	}
	defer resp.Body.Close()

	// Extract response headers (normalized to lower-case)
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = strings.Join(v, ", ")
		}
	}

	finalURL := resp.Request.URL.String()
	isHTTPS := strings.HasPrefix(finalURL, "https://")

	report := analyzeHeaders(headers, finalURL, isHTTPS, resp.StatusCode, latency)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Report:  report,
	})
}

// analyzeHeaders inspects headers according to Mozilla Observatory & MDN guidelines
func analyzeHeaders(headers map[string]string, targetURL string, isHTTPS bool, statusCode int, latency int64) *SecurityAuditReport {
	var results []AuditRuleResult
	score := 100

	// 1. Content-Security-Policy (CSP)
	cspVal, hasCSP := headers["content-security-policy"]
	if !hasCSP {
		score -= 25
		results = append(results, AuditRuleResult{
			ID:               "csp",
			Name:             "Content-Security-Policy (CSP)",
			HeaderName:       "Content-Security-Policy",
			Category:         "XSS & Inyección",
			Status:           "fail",
			Description:      "Mitiga ataques de Cross-Site Scripting (XSS), inyección de datos y ejecución de recursos no autorizados.",
			ValueFound:       "",
			RecommendedValue: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
			ScoreImpact:      -25,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/CSP",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;",
				Apache:  "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"",
				Express: "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"], objectSrc: [\"'none'\"] } }));",
				Caddy:   "header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"",
			},
		})
	} else if strings.Contains(cspVal, "unsafe-inline") || strings.Contains(cspVal, "unsafe-eval") || strings.Contains(cspVal, "*") {
		score -= 10
		results = append(results, AuditRuleResult{
			ID:               "csp",
			Name:             "Content-Security-Policy (CSP)",
			HeaderName:       "Content-Security-Policy",
			Category:         "XSS & Inyección",
			Status:           "warning",
			Description:      "Se detectó CSP pero incluye directivas permisivas ('unsafe-inline', 'unsafe-eval' o comodines *) que reducen su eficacia contra XSS.",
			ValueFound:       cspVal,
			RecommendedValue: "default-src 'self'; script-src 'self'; object-src 'none';",
			ScoreImpact:      -10,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/CSP",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;",
				Apache:  "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"",
				Express: "app.use(helmet.contentSecurityPolicy());",
				Caddy:   "header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "csp",
			Name:             "Content-Security-Policy (CSP)",
			HeaderName:       "Content-Security-Policy",
			Category:         "XSS & Inyección",
			Status:           "pass",
			Description:      "Política de Seguridad de Contenido configurada correctamente y sin directivas inseguras.",
			ValueFound:       cspVal,
			RecommendedValue: "Configuración robusta activa",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/CSP",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header Content-Security-Policy \"...\" always;",
			},
		})
	}

	// 2. HTTP Strict Transport Security (HSTS)
	hstsVal, hasHSTS := headers["strict-transport-security"]
	if !isHTTPS {
		score -= 20
		results = append(results, AuditRuleResult{
			ID:               "hsts",
			Name:             "Strict-Transport-Security (HSTS)",
			HeaderName:       "Strict-Transport-Security",
			Category:         "Transporte & TLS",
			Status:           "fail",
			Description:      "El servidor no utiliza HTTPS. HSTS requiere un canal cifrado para proteger contra ataques de degradación (SSL Strip).",
			ValueFound:       "Conexión HTTP no segura",
			RecommendedValue: "max-age=31536000; includeSubDomains; preload",
			ScoreImpact:      -20,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Strict-Transport-Security",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
				Apache:  "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
				Express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
				Caddy:   "header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
			},
		})
	} else if !hasHSTS {
		score -= 20
		results = append(results, AuditRuleResult{
			ID:               "hsts",
			Name:             "Strict-Transport-Security (HSTS)",
			HeaderName:       "Strict-Transport-Security",
			Category:         "Transporte & TLS",
			Status:           "fail",
			Description:      "Falta la cabecera HSTS. Los navegadores pueden intentar conexiones iniciales en texto plano no cifradas.",
			ValueFound:       "",
			RecommendedValue: "max-age=31536000; includeSubDomains; preload",
			ScoreImpact:      -20,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Strict-Transport-Security",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
				Apache:  "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
				Express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
				Caddy:   "header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
			},
		})
	} else if !strings.Contains(hstsVal, "max-age") || strings.Contains(hstsVal, "max-age=0") {
		score -= 10
		results = append(results, AuditRuleResult{
			ID:               "hsts",
			Name:             "Strict-Transport-Security (HSTS)",
			HeaderName:       "Strict-Transport-Security",
			Category:         "Transporte & TLS",
			Status:           "warning",
			Description:      "El valor de max-age es demasiado corto o nulo. Se recomienda al menos 1 año (31536000 segundos).",
			ValueFound:       hstsVal,
			RecommendedValue: "max-age=31536000; includeSubDomains; preload",
			ScoreImpact:      -10,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Strict-Transport-Security",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
				Apache:  "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
				Express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
				Caddy:   "header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "hsts",
			Name:             "Strict-Transport-Security (HSTS)",
			HeaderName:       "Strict-Transport-Security",
			Category:         "Transporte & TLS",
			Status:           "pass",
			Description:      "Cabecera HSTS configurada correctamente.",
			ValueFound:       hstsVal,
			RecommendedValue: "max-age=31536000; includeSubDomains",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Strict-Transport-Security",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header Strict-Transport-Security \"max-age=31536000\" always;",
			},
		})
	}

	// 3. X-Content-Type-Options
	xctoVal, hasXCTO := headers["x-content-type-options"]
	if !hasXCTO || !strings.EqualFold(strings.TrimSpace(xctoVal), "nosniff") {
		score -= 10
		results = append(results, AuditRuleResult{
			ID:               "x-content-type-options",
			Name:             "X-Content-Type-Options",
			HeaderName:       "X-Content-Type-Options",
			Category:         "XSS & Inyección",
			Status:           "fail",
			Description:      "Evita que los navegadores realicen 'MIME-sniffing' e interpreten archivos no ejecutables (ej. imágenes) como scripts.",
			ValueFound:       xctoVal,
			RecommendedValue: "nosniff",
			ScoreImpact:      -10,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Content-Type-Options",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header X-Content-Type-Options \"nosniff\" always;",
				Apache:  "Header always set X-Content-Type-Options \"nosniff\"",
				Express: "app.use(helmet.noSniff());",
				Caddy:   "header X-Content-Type-Options \"nosniff\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "x-content-type-options",
			Name:             "X-Content-Type-Options",
			HeaderName:       "X-Content-Type-Options",
			Category:         "XSS & Inyección",
			Status:           "pass",
			Description:      "MIME-sniffing deshabilitado con 'nosniff'.",
			ValueFound:       xctoVal,
			RecommendedValue: "nosniff",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Content-Type-Options",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header X-Content-Type-Options \"nosniff\" always;",
			},
		})
	}

	// 4. X-Frame-Options / Frame Protection
	xfoVal, hasXFO := headers["x-frame-options"]
	hasCSPFrame := hasCSP && strings.Contains(cspVal, "frame-ancestors")
	if !hasXFO && !hasCSPFrame {
		score -= 15
		results = append(results, AuditRuleResult{
			ID:               "x-frame-options",
			Name:             "Protección contra Framing (X-Frame-Options)",
			HeaderName:       "X-Frame-Options",
			Category:         "Incrustación & Clickjacking",
			Status:           "fail",
			Description:      "Protege contra ataques de Clickjacking impidiendo que el sitio sea embebido en iframes no autorizados.",
			ValueFound:       "",
			RecommendedValue: "DENY o SAMEORIGIN",
			ScoreImpact:      -15,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Frame-Options",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header X-Frame-Options \"DENY\" always;",
				Apache:  "Header always set X-Frame-Options \"DENY\"",
				Express: "app.use(helmet.frameguard({ action: \"deny\" }));",
				Caddy:   "header X-Frame-Options \"DENY\"",
			},
		})
	} else {
		valDisplay := xfoVal
		if valDisplay == "" && hasCSPFrame {
			valDisplay = "Protegido mediante CSP frame-ancestors"
		}
		results = append(results, AuditRuleResult{
			ID:               "x-frame-options",
			Name:             "Protección contra Framing (X-Frame-Options)",
			HeaderName:       "X-Frame-Options",
			Category:         "Incrustación & Clickjacking",
			Status:           "pass",
			Description:      "Protección activa contra ataques de Clickjacking.",
			ValueFound:       valDisplay,
			RecommendedValue: "DENY / SAMEORIGIN",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Frame-Options",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header X-Frame-Options \"DENY\" always;",
			},
		})
	}

	// 5. Referrer-Policy
	refVal, hasRef := headers["referrer-policy"]
	if !hasRef {
		score -= 10
		results = append(results, AuditRuleResult{
			ID:               "referrer-policy",
			Name:             "Referrer-Policy",
			HeaderName:       "Referrer-Policy",
			Category:         "Privacidad & Fugas",
			Status:           "warning",
			Description:      "Controla cuánta información de referencia (rutas y tokens en URL) se comparte al navegar hacia otros sitios.",
			ValueFound:       "",
			RecommendedValue: "strict-origin-when-cross-origin",
			ScoreImpact:      -10,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Referrer-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
				Apache:  "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
				Express: "app.use(helmet.referrerPolicy({ policy: \"strict-origin-when-cross-origin\" }));",
				Caddy:   "header Referrer-Policy \"strict-origin-when-cross-origin\"",
			},
		})
	} else if strings.EqualFold(refVal, "unsafe-url") || strings.EqualFold(refVal, "no-referrer-when-downgrade") {
		score -= 5
		results = append(results, AuditRuleResult{
			ID:               "referrer-policy",
			Name:             "Referrer-Policy",
			HeaderName:       "Referrer-Policy",
			Category:         "Privacidad & Fugas",
			Status:           "warning",
			Description:      "La política actual puede filtrar la ruta completa y parámetros de consulta a sitios externos.",
			ValueFound:       refVal,
			RecommendedValue: "strict-origin-when-cross-origin",
			ScoreImpact:      -5,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Referrer-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
				Apache:  "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
				Express: "app.use(helmet.referrerPolicy({ policy: \"strict-origin-when-cross-origin\" }));",
				Caddy:   "header Referrer-Policy \"strict-origin-when-cross-origin\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "referrer-policy",
			Name:             "Referrer-Policy",
			HeaderName:       "Referrer-Policy",
			Category:         "Privacidad & Fugas",
			Status:           "pass",
			Description:      "Política de referencia segura configurada.",
			ValueFound:       refVal,
			RecommendedValue: "strict-origin-when-cross-origin",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Referrer-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
			},
		})
	}

	// 6. Cross-Origin-Opener-Policy (COOP)
	coopVal, hasCOOP := headers["cross-origin-opener-policy"]
	if !hasCOOP {
		score -= 5
		results = append(results, AuditRuleResult{
			ID:               "coop",
			Name:             "Cross-Origin-Opener-Policy (COOP)",
			HeaderName:       "Cross-Origin-Opener-Policy",
			Category:         "Aislamiento Origen Cruzado",
			Status:           "warning",
			Description:      "Aísla el contexto de navegación en un grupo diferente para mitigar ataques de canales laterales como Spectre.",
			ValueFound:       "",
			RecommendedValue: "same-origin",
			ScoreImpact:      -5,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Cross-Origin-Opener-Policy \"same-origin\" always;",
				Apache:  "Header always set Cross-Origin-Opener-Policy \"same-origin\"",
				Express: "app.use(helmet.crossOriginOpenerPolicy({ policy: \"same-origin\" }));",
				Caddy:   "header Cross-Origin-Opener-Policy \"same-origin\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "coop",
			Name:             "Cross-Origin-Opener-Policy (COOP)",
			HeaderName:       "Cross-Origin-Opener-Policy",
			Category:         "Aislamiento Origen Cruzado",
			Status:           "pass",
			Description:      "Contexto de navegación aislado con COOP.",
			ValueFound:       coopVal,
			RecommendedValue: "same-origin",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header Cross-Origin-Opener-Policy \"same-origin\" always;",
			},
		})
	}

	// 7. Cross-Origin-Embedder-Policy (COEP)
	coepVal, hasCOEP := headers["cross-origin-embedder-policy"]
	if !hasCOEP {
		results = append(results, AuditRuleResult{
			ID:               "coep",
			Name:             "Cross-Origin-Embedder-Policy (COEP)",
			HeaderName:       "Cross-Origin-Embedder-Policy",
			Category:         "Aislamiento Origen Cruzado",
			Status:           "info",
			Description:      "Evita que el documento cargue recursos de orígenes cruzados que no otorguen permiso explícito (CORP/CORS).",
			ValueFound:       "",
			RecommendedValue: "require-corp",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;",
				Apache:  "Header always set Cross-Origin-Embedder-Policy \"require-corp\"",
				Express: "app.use(helmet.crossOriginEmbedderPolicy());",
				Caddy:   "header Cross-Origin-Embedder-Policy \"require-corp\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "coep",
			Name:             "Cross-Origin-Embedder-Policy (COEP)",
			HeaderName:       "Cross-Origin-Embedder-Policy",
			Category:         "Aislamiento Origen Cruzado",
			Status:           "pass",
			Description:      "Incrustación de recursos de origen cruzado restringida con COEP.",
			ValueFound:       coepVal,
			RecommendedValue: "require-corp",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;",
			},
		})
	}

	// 8. Permissions-Policy
	permVal, hasPerm := headers["permissions-policy"]
	if !hasPerm {
		results = append(results, AuditRuleResult{
			ID:               "permissions-policy",
			Name:             "Permissions-Policy",
			HeaderName:       "Permissions-Policy",
			Category:         "Privacidad & Fugas",
			Status:           "info",
			Description:      "Restringe el acceso a APIs sensibles del navegador (cámara, micrófono, geolocalización, giroscopio).",
			ValueFound:       "",
			RecommendedValue: "camera=(), microphone=(), geolocation=()",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Permissions-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
				Apache:  "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
				Express: "app.use(helmet.permittedCrossDomainPolicies());",
				Caddy:   "header Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "permissions-policy",
			Name:             "Permissions-Policy",
			HeaderName:       "Permissions-Policy",
			Category:         "Privacidad & Fugas",
			Status:           "pass",
			Description:      "Permisos de hardware y APIs del navegador restringidos explícitamente.",
			ValueFound:       permVal,
			RecommendedValue: "camera=(), microphone=()",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Permissions-Policy",
			RemediationSnippet: RemediationSnippet{
				Nginx: "add_header Permissions-Policy \"...\" always;",
			},
		})
	}

	// 9. Server Banner / Information Disclosure
	serverVal, hasServer := headers["server"]
	poweredByVal, hasPowered := headers["x-powered-by"]
	aspNetVal, hasAspNet := headers["x-aspnet-version"]

	var disclosureItems []string
	if hasServer && (strings.Contains(serverVal, "/") || strings.Contains(serverVal, "Apache") || strings.Contains(serverVal, "nginx") || strings.Contains(serverVal, "IIS") || strings.Contains(serverVal, "Cloudflare")) {
		disclosureItems = append(disclosureItems, fmt.Sprintf("Server: %s", serverVal))
	}
	if hasPowered {
		disclosureItems = append(disclosureItems, fmt.Sprintf("X-Powered-By: %s", poweredByVal))
	}
	if hasAspNet {
		disclosureItems = append(disclosureItems, fmt.Sprintf("X-AspNet-Version: %s", aspNetVal))
	}

	if len(disclosureItems) > 0 {
		score -= 5
		results = append(results, AuditRuleResult{
			ID:               "server-disclosure",
			Name:             "Divulgación de Tecnologías del Servidor",
			HeaderName:       "Server / X-Powered-By",
			Category:         "Divulgación de Servidor",
			Status:           "warning",
			Description:      "El servidor expone detalles sobre su software o versión, facilitando el escaneo automatizado de vulnerabilidades.",
			ValueFound:       strings.Join(disclosureItems, " | "),
			RecommendedValue: "Ocultar o anonimizar las cabeceras de servidor",
			ScoreImpact:      -5,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Server",
			RemediationSnippet: RemediationSnippet{
				Nginx:   "server_tokens off; # Oculta versiones en Nginx",
				Apache:  "ServerSignature Off\nServerTokens Prod",
				Express: "app.disable(\"x-powered-by\");",
				Caddy:   "header -Server",
			},
		})
	} else {
		results = append(results, AuditRuleResult{
			ID:               "server-disclosure",
			Name:             "Divulgación de Tecnologías del Servidor",
			HeaderName:       "Server / X-Powered-By",
			Category:         "Divulgación de Servidor",
			Status:           "pass",
			Description:      "El servidor no divulga versiones ni tecnologías internas innecesarias.",
			ValueFound:       serverVal,
			RecommendedValue: "Sin divulgación",
			ScoreImpact:      0,
			MDNUrl:           "https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Server",
			RemediationSnippet: RemediationSnippet{
				Nginx: "server_tokens off;",
			},
		})
	}

	// Clamp score between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Determine Grade
	var grade string
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 85:
		grade = "A"
	case score >= 80:
		grade = "A-"
	case score >= 75:
		grade = "B+"
	case score >= 70:
		grade = "B"
	case score >= 65:
		grade = "B-"
	case score >= 60:
		grade = "C+"
	case score >= 50:
		grade = "C"
	case score >= 40:
		grade = "D"
	default:
		grade = "F"
	}

	passed := 0
	warning := 0
	failed := 0
	for _, r := range results {
		switch r.Status {
		case "pass":
			passed++
		case "warning":
			warning++
		case "fail":
			failed++
		}
	}

	var summary string
	if grade == "A+" || grade == "A" {
		summary = "El servidor web implementa un perfil de seguridad excelente con protección sólida frente a XSS, Clickjacking y degradación TLS."
	} else if grade == "B+" || grade == "B" || grade == "B-" {
		summary = "Perfil de seguridad aceptable, pero requiere configurar cabeceras recomendadas como CSP estricto o políticas de aislamiento para alcanzar la máxima protección."
	} else if grade == "C+" || grade == "C" {
		summary = "Se detectaron omisiones importantes en cabeceras críticas (HSTS, CSP o X-Frame-Options) que exponen a los usuarios a riesgos de seguridad web."
	} else {
		summary = "Nivel de seguridad crítico. El servidor carece de las principales defensas HTTP modernas según los estándares de Mozilla Observatory."
	}

	return &SecurityAuditReport{
		TargetURL:     targetURL,
		FinalURL:      targetURL,
		StatusCode:    statusCode,
		LatencyMs:     latency,
		IsHTTPS:       isHTTPS,
		Grade:         grade,
		Score:         score,
		TotalChecks:   len(results),
		PassedChecks:  passed,
		WarningChecks: warning,
		FailedChecks:  failed,
		Summary:       summary,
		Timestamp:     time.Now().Format(time.RFC3339),
		Headers:       headers,
		Results:       results,
	}
}

// embeddedHTML contains the single-page application UI with zero backticks inside to ensure clean Go compilation
const embeddedHTML = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>KSec - Auditor servidores Web</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
    code, pre { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="bg-slate-50 text-slate-800 min-h-screen flex flex-col antialiased">

  <!-- Header / Navigation -->
  <header class="sticky top-0 z-40 bg-white/95 backdrop-blur border-b border-slate-200 shadow-xs">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-sm font-bold">
          <i data-lucide="shield" class="w-5 h-5"></i>
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <span class="font-bold text-lg text-slate-900 tracking-tight">KSec - Auditor servidores Web</span>
          </div>
          <p class="text-xs text-slate-500 hidden sm:block">
            Auditoría de seguridad HTTP según Mozilla Observatory y MDN Web Docs
          </p>
        </div>
      </div>
      <div class="flex items-center space-x-2">
        <button onclick="shutdownApp()" class="px-3 py-1.5 rounded-lg border border-rose-200 hover:bg-rose-50 text-rose-700 text-xs font-medium transition-colors flex items-center space-x-1.5 cursor-pointer" title="Cerrar servidor local y liberar memoria">
          <i data-lucide="power" class="w-3.5 h-3.5 text-rose-600"></i>
          <span>Cerrar Aplicativo</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Content Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">

    <!-- Hero Card & URL Input -->
    <div class="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-xs">
      <div class="max-w-3xl">
        <span class="text-[10px] font-bold uppercase tracking-widest text-blue-600 bg-blue-50 px-2.5 py-0.5 rounded-full border border-blue-100">
          Auditor de Servidores Web
        </span>
        <h1 class="text-2xl sm:text-3xl font-extrabold text-slate-900 mt-2">KSec - Auditor servidores Web</h1>
        <p class="text-sm text-slate-600 mt-1">
          Ingresa la URL del servidor web para realizar un análisis completo de cabeceras de seguridad HTTP (CSP, HSTS, X-Content-Type-Options, Frame Options, COOP/COEP y Referrer-Policy).
        </p>
      </div>

      <div class="mt-6 pt-5 border-t border-slate-100">
        <form onsubmit="handleAuditSubmit(event)" class="flex flex-col sm:flex-row items-stretch gap-2.5">
          <div class="relative flex-1">
            <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <i data-lucide="globe" class="w-4 h-4"></i>
            </div>
            <input
              id="urlInput"
              type="text"
              required
              value="https://developer.mozilla.org"
              placeholder="https://ejemplo.com"
              class="w-full pl-10 pr-4 py-2.5 bg-slate-50 focus:bg-white border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 font-mono transition-colors"
            />
          </div>
          <button
            id="auditBtn"
            type="submit"
            class="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold rounded-xl text-sm transition-colors flex items-center justify-center space-x-2 shadow-sm cursor-pointer"
          >
            <i data-lucide="shield-check" class="w-4 h-4"></i>
            <span id="auditBtnText">Auditar Servidor</span>
          </button>
        </form>

        <div id="errorMessage" class="hidden mt-3 p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center space-x-2">
          <i data-lucide="alert-circle" class="w-4 h-4 text-rose-500 shrink-0"></i>
          <span id="errorText"></span>
        </div>
      </div>
    </div>

    <!-- Results Section (Dynamic) -->
    <div id="resultsContainer" class="space-y-6"></div>

  </main>

  <!-- Server Config Modal -->
  <div id="configModal" class="hidden fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
    <div class="bg-white rounded-2xl max-w-2xl w-full border border-slate-200 shadow-xl overflow-hidden">
      <div class="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <i data-lucide="code" class="w-5 h-5 text-blue-600"></i>
          <h3 class="font-bold text-slate-900">Plantillas de Configuración de Servidor</h3>
        </div>
        <button onclick="closeConfigModal()" class="text-slate-400 hover:text-slate-600 p-1 rounded-lg">
          <i data-lucide="x" class="w-5 h-5"></i>
        </button>
      </div>
      <div class="p-6 space-y-4">
        <div class="flex space-x-2 border-b border-slate-100 pb-3">
          <button onclick="switchConfigTab('nginx')" id="tab-nginx" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 text-white">Nginx</button>
          <button onclick="switchConfigTab('apache')" id="tab-apache" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 text-slate-700">Apache</button>
          <button onclick="switchConfigTab('express')" id="tab-express" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 text-slate-700">Express / Node</button>
          <button onclick="switchConfigTab('caddy')" id="tab-caddy" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 text-slate-700">Caddy</button>
        </div>
        <pre id="configCodeBlock" class="p-4 bg-slate-900 text-slate-100 rounded-xl text-xs overflow-x-auto leading-relaxed"></pre>
      </div>
      <div class="px-6 py-3.5 bg-slate-50 border-t border-slate-100 flex justify-end">
        <button onclick="copyCurrentConfig()" id="copyConfigBtn" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl flex items-center space-x-1.5 shadow-sm">
          <i data-lucide="copy" class="w-3.5 h-3.5"></i>
          <span>Copiar Configuración</span>
        </button>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <footer class="mt-auto border-t border-slate-200 bg-white py-6">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
      <div class="flex items-center space-x-2">
        <i data-lucide="shield" class="w-4 h-4 text-blue-600"></i>
        <span>KSec - Auditor Servidores Web en Go • Mozilla Observatory & MDN Guidelines</span>
      </div>
      <span class="font-mono text-slate-400">RFC 6265bis • CSP L3 • HSTS • COOP/COEP</span>
    </div>
  </footer>

  <script>
    var currentReport = null;
    var activeFilter = 'all';

    var serverTemplates = {
      nginx: '# Inserte en su bloque server {} o location / {}\n' +
             'add_header X-Content-Type-Options "nosniff" always;\n' +
             'add_header X-Frame-Options "DENY" always;\n' +
             'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n' +
             'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n' +
             'add_header Cross-Origin-Opener-Policy "same-origin" always;\n' +
             'add_header Cross-Origin-Embedder-Policy "require-corp" always;\n' +
             'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\';" always;\n' +
             'server_tokens off;',
      apache: '# En .htaccess o <VirtualHost>\n' +
              'Header always set X-Content-Type-Options "nosniff"\n' +
              'Header always set X-Frame-Options "DENY"\n' +
              'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n' +
              'Header always set Referrer-Policy "strict-origin-when-cross-origin"\n' +
              'Header always set Cross-Origin-Opener-Policy "same-origin"\n' +
              'Header always set Cross-Origin-Embedder-Policy "require-corp"\n' +
              'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\';"\n' +
              'ServerSignature Off\n' +
              'ServerTokens Prod',
      express: '// Express.js con Helmet\n' +
               'import express from "express";\n' +
               'import helmet from "helmet";\n\n' +
               'const app = express();\n' +
               'app.use(helmet({\n' +
               '  contentSecurityPolicy: {\n' +
               '    directives: {\n' +
               '      defaultSrc: ["\'self\'"],\n' +
               '      scriptSrc: ["\'self\'"],\n' +
               '      objectSrc: ["\'none\'"],\n' +
               '      frameAncestors: ["\'none\'"]\n' +
               '    }\n' +
               '  },\n' +
               '  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },\n' +
               '  crossOriginOpenerPolicy: { policy: "same-origin" },\n' +
               '  crossOriginEmbedderPolicy: true,\n' +
               '  referrerPolicy: { policy: "strict-origin-when-cross-origin" }\n' +
               '}));\n' +
               'app.disable("x-powered-by");',
      caddy: '# Caddyfile\n' +
             'header {\n' +
             '  X-Content-Type-Options "nosniff"\n' +
             '  X-Frame-Options "DENY"\n' +
             '  Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n' +
             '  Referrer-Policy "strict-origin-when-cross-origin"\n' +
             '  Cross-Origin-Opener-Policy "same-origin"\n' +
             '  Cross-Origin-Embedder-Policy "require-corp"\n' +
             '  Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\';"\n' +
             '  -Server\n' +
             '}'
    };

    var activeConfig = 'nginx';

    // Heartbeat & lifecycle detection: closes the application and frees memory on browser exit
    var clientTabId = 'tab_' + Math.random().toString(36).substring(2, 9) + '_' + Date.now();

    function sendHeartbeat(action) {
      var payload = JSON.stringify({ tabId: clientTabId, action: action || 'ping' });
      if (action === 'leave') {
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/api/heartbeat', payload);
          return;
        }
        fetch('/api/heartbeat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          keepalive: true
        }).catch(function() {});
        return;
      }
      fetch('/api/heartbeat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload
      }).catch(function() {});
    }

    // Ping every 2 seconds to confirm the browser is open
    setInterval(function() {
      sendHeartbeat('ping');
    }, 2000);
    sendHeartbeat('ping');

    // Notify server when browser/tab is closing
    window.addEventListener('beforeunload', function() {
      sendHeartbeat('leave');
    });
    window.addEventListener('pagehide', function() {
      sendHeartbeat('leave');
    });

    async function shutdownApp() {
      if (!confirm('¿Deseas cerrar el aplicativo KSec y liberar la memoria del sistema?')) return;
      try {
        await fetch('/api/shutdown', { method: 'POST' });
      } catch (e) {}
      document.body.innerHTML = '<div class="min-h-screen bg-slate-900 text-white flex flex-col items-center justify-center p-6 text-center font-sans">' +
        '<div class="w-16 h-16 rounded-2xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center mb-4 text-3xl font-bold">✓</div>' +
        '<h1 class="text-2xl font-bold mb-2">Aplicativo KSec finalizado</h1>' +
        '<p class="text-slate-400 text-sm max-w-md mb-6">El servidor local se ha detenido por completo y la memoria ha sido liberada hacia el sistema operativo.</p>' +
        '<span class="text-xs text-slate-500">Ya puedes cerrar esta pestaña o ventana del navegador.</span>' +
      '</div>';
    }

    window.addEventListener('DOMContentLoaded', function() {
      lucide.createIcons();
      handleAuditSubmit(new Event('submit'));
    });

    async function handleAuditSubmit(e) {
      if (e) e.preventDefault();
      var urlInput = document.getElementById('urlInput');
      var url = urlInput.value.trim();
      if (!url) return;

      var btn = document.getElementById('auditBtn');
      var btnText = document.getElementById('auditBtnText');
      var errorEl = document.getElementById('errorMessage');
      var errorText = document.getElementById('errorText');

      errorEl.classList.add('hidden');
      btn.disabled = true;
      btnText.innerText = 'Analizando...';

      try {
        var response = await fetch('/api/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url })
        });

        var data = await response.json();
        if (!data.success) {
          throw new Error(data.error || 'Error al analizar el servidor');
        }

        currentReport = data.report;
        renderResults();
      } catch (err) {
        errorText.innerText = err.message || 'Error de conexión con el servidor objetivo';
        errorEl.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btnText.innerText = 'Auditar Servidor';
        lucide.createIcons();
      }
    }

    function renderResults() {
      var container = document.getElementById('resultsContainer');
      if (!currentReport) return;

      var r = currentReport;
      var gradeColor = 
        r.grade.indexOf('A') === 0 ? 'bg-emerald-600 text-white' :
        r.grade.indexOf('B') === 0 ? 'bg-blue-600 text-white' :
        r.grade.indexOf('C') === 0 ? 'bg-amber-500 text-white' : 'bg-rose-600 text-white';

      var filteredResults = activeFilter === 'all' 
        ? r.results 
        : r.results.filter(function(res) { return res.status === activeFilter; });

      var httpsBadge = r.isHttps 
        ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">HTTPS Seguro</span>' 
        : '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">HTTP Inseguro</span>';

      var html = '';
      
      // Overview Score Card
      html += '<div class="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">';
      html += '  <div class="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">';
      html += '    <div class="flex items-center space-x-4 md:col-span-2">';
      html += '      <div class="w-20 h-20 rounded-2xl ' + gradeColor + ' flex flex-col items-center justify-center shadow-md shrink-0">';
      html += '        <span class="text-2xl font-black">' + r.grade + '</span>';
      html += '        <span class="text-[10px] font-bold opacity-90">' + r.score + '/100 pts</span>';
      html += '      </div>';
      html += '      <div>';
      html += '        <div class="flex items-center space-x-2">';
      html += '          <span class="font-bold text-slate-900">' + r.targetUrl + '</span>';
      html += '          ' + httpsBadge;
      html += '        </div>';
      html += '        <p class="text-xs text-slate-500 mt-1">';
      html += '          Latencia de respuesta: <span class="font-mono font-medium">' + r.latencyMs + ' ms</span> • Código: <span class="font-mono font-medium">' + r.statusCode + '</span>';
      html += '        </p>';
      html += '      </div>';
      html += '    </div>';
      html += '    <div class="grid grid-cols-3 gap-2 md:col-span-2 text-center">';
      html += '      <div class="p-3 rounded-xl bg-emerald-50 border border-emerald-100">';
      html += '        <div class="text-xl font-bold text-emerald-700">' + r.passedChecks + '</div>';
      html += '        <div class="text-[11px] font-medium text-emerald-800">Aprobadas</div>';
      html += '      </div>';
      html += '      <div class="p-3 rounded-xl bg-amber-50 border border-amber-100">';
      html += '        <div class="text-xl font-bold text-amber-700">' + r.warningChecks + '</div>';
      html += '        <div class="text-[11px] font-medium text-amber-800">Advertencias</div>';
      html += '      </div>';
      html += '      <div class="p-3 rounded-xl bg-rose-50 border border-rose-100">';
      html += '        <div class="text-xl font-bold text-rose-700">' + r.failedChecks + '</div>';
      html += '        <div class="text-[11px] font-medium text-rose-800">Fallos Críticos</div>';
      html += '      </div>';
      html += '    </div>';
      html += '  </div>';
      html += '</div>';

      // Action Banner with PDF download
      html += '<div class="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-4">';
      html += '  <div class="flex items-start sm:items-center space-x-3.5">';
      html += '    <div class="w-11 h-11 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center shrink-0 border border-blue-100">';
      html += '      <i data-lucide="file-text" class="w-5 h-5"></i>';
      html += '    </div>';
      html += '    <div>';
      html += '      <div class="flex items-center space-x-2">';
      html += '        <h3 class="text-sm font-bold text-slate-900">Informe Ejecutivo y Plan de Acciones</h3>';
      html += '        <span class="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-md bg-emerald-50 text-emerald-700 border border-emerald-200">Documento PDF</span>';
      html += '      </div>';
      html += '      <p class="text-xs text-slate-600 mt-0.5">';
      html += '        Genera y descarga el reporte oficial con el desglose de fallos, puntuación y directivas de configuración recomendadas.';
      html += '      </p>';
      html += '    </div>';
      html += '  </div>';
      html += '  <div class="flex flex-wrap items-center gap-2">';
      html += '    <button onclick="downloadPdfReport()" class="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl transition-colors flex items-center space-x-2 shadow-sm cursor-pointer">';
      html += '      <i data-lucide="file-down" class="w-4 h-4"></i>';
      html += '      <span>Descargar Reporte en PDF</span>';
      html += '    </button>';
      html += '    <button onclick="openConfigModal()" class="px-3.5 py-2.5 bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 text-xs font-medium rounded-xl transition-colors cursor-pointer">';
      html += '      Ver Plantillas Servidor';
      html += '    </button>';
      html += '  </div>';
      html += '</div>';

      // Filters
      html += '<div class="flex items-center justify-between border-b border-slate-200 pb-3">';
      html += '  <div class="flex space-x-2">';
      html += '    <button onclick="setFilter(\'all\')" class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ' + (activeFilter === 'all' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200') + '">Todas (' + r.results.length + ')</button>';
      html += '    <button onclick="setFilter(\'fail\')" class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ' + (activeFilter === 'fail' ? 'bg-rose-600 text-white' : 'bg-rose-50 text-rose-700 hover:bg-rose-100') + '">Fallos (' + r.failedChecks + ')</button>';
      html += '    <button onclick="setFilter(\'warning\')" class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ' + (activeFilter === 'warning' ? 'bg-amber-500 text-white' : 'bg-amber-50 text-amber-700 hover:bg-amber-100') + '">Advertencias (' + r.warningChecks + ')</button>';
      html += '    <button onclick="setFilter(\'pass\')" class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ' + (activeFilter === 'pass' ? 'bg-emerald-600 text-white' : 'bg-emerald-50 text-emerald-700 hover:bg-emerald-100') + '">Aprobadas (' + r.passedChecks + ')</button>';
      html += '  </div>';
      html += '  <span class="text-xs text-slate-500 font-medium">Mostrando ' + filteredResults.length + ' pruebas</span>';
      html += '</div>';

      // Rules List
      html += '<div class="space-y-3">';
      filteredResults.forEach(function(item) {
        var statusBadge = item.status === 'pass' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                          item.status === 'warning' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                          item.status === 'fail' ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-slate-100 text-slate-600';
        
        var valText = item.valueFound ? item.valueFound : '<span class="italic text-slate-400">(No presente)</span>';

        html += '<div class="bg-white border border-slate-200 rounded-xl p-5 shadow-xs transition-all hover:border-slate-300">';
        html += '  <div class="flex items-start justify-between gap-4">';
        html += '    <div class="space-y-1">';
        html += '      <div class="flex items-center space-x-2">';
        html += '        <span class="text-xs font-bold text-slate-900">' + item.name + '</span>';
        html += '        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-medium">' + item.headerName + '</span>';
        html += '        <span class="text-[10px] px-2 py-0.5 rounded-full font-bold ' + statusBadge + '">' + item.status.toUpperCase() + '</span>';
        html += '      </div>';
        html += '      <p class="text-xs text-slate-600">' + item.description + '</p>';
        html += '    </div>';
        html += '    <span class="font-mono text-xs font-bold ' + (item.scoreImpact < 0 ? 'text-rose-600' : 'text-emerald-600') + '">';
        html += '      ' + (item.scoreImpact > 0 ? '+' : '') + item.scoreImpact + ' pts';
        html += '    </span>';
        html += '  </div>';

        html += '  <div class="mt-4 pt-3 border-t border-slate-100 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">';
        html += '    <div class="p-2.5 rounded-lg bg-slate-50 border border-slate-100">';
        html += '      <span class="text-[11px] font-semibold text-slate-500 block mb-1">Valor Detectado:</span>';
        html += '      <code class="font-mono text-[11px] text-slate-800 break-all">' + valText + '</code>';
        html += '    </div>';
        html += '    <div class="p-2.5 rounded-lg bg-blue-50/50 border border-blue-100">';
        html += '      <span class="text-[11px] font-semibold text-blue-700 block mb-1">Recomendación MDN:</span>';
        html += '      <code class="font-mono text-[11px] text-blue-900 break-all">' + item.recommendedValue + '</code>';
        html += '    </div>';
        html += '  </div>';

        if (item.remediationSnippet && item.remediationSnippet.nginx) {
          html += '  <div class="mt-3">';
          html += '    <div class="flex items-center justify-between text-[11px] font-semibold text-slate-500 mb-1">';
          html += '      <span>Directiva Nginx de remediación:</span>';
          html += '      <button onclick="copySnippet(\'' + encodeURIComponent(item.remediationSnippet.nginx) + '\', this)" class="text-blue-600 hover:text-blue-700 flex items-center space-x-1 cursor-pointer">';
          html += '        <i data-lucide="copy" class="w-3 h-3"></i>';
          html += '        <span>Copiar</span>';
          html += '      </button>';
          html += '    </div>';
          html += '    <pre class="p-2.5 bg-slate-900 text-slate-100 rounded-lg text-[11px] overflow-x-auto">' + item.remediationSnippet.nginx + '</pre>';
          html += '  </div>';
        }

        html += '</div>';
      });
      html += '</div>';

      container.innerHTML = html;
      lucide.createIcons();
    }

    function setFilter(filter) {
      activeFilter = filter;
      renderResults();
    }

    function copySnippet(encodedCode, btn) {
      var code = decodeURIComponent(encodedCode);
      navigator.clipboard.writeText(code);
      btn.innerHTML = '<span class="text-emerald-600 font-bold">¡Copiado!</span>';
      setTimeout(function() {
        btn.innerHTML = '<i data-lucide="copy" class="w-3 h-3"></i><span>Copiar</span>';
        lucide.createIcons();
      }, 1500);
    }

    function openConfigModal() {
      document.getElementById('configModal').classList.remove('hidden');
      switchConfigTab(activeConfig);
      lucide.createIcons();
    }

    function closeConfigModal() {
      document.getElementById('configModal').classList.add('hidden');
    }

    function switchConfigTab(tab) {
      activeConfig = tab;
      ['nginx', 'apache', 'express', 'caddy'].forEach(function(t) {
        var btn = document.getElementById('tab-' + t);
        if (t === tab) {
          btn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 text-white';
        } else {
          btn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 text-slate-700 hover:bg-slate-200';
        }
      });
      document.getElementById('configCodeBlock').innerText = serverTemplates[tab];
    }

    function copyCurrentConfig() {
      navigator.clipboard.writeText(serverTemplates[activeConfig]);
      var btn = document.getElementById('copyConfigBtn');
      btn.innerHTML = '<span>¡Configuración Copiada!</span>';
      setTimeout(function() {
        btn.innerHTML = '<i data-lucide="copy" class="w-3.5 h-3.5"></i><span>Copiar Configuración</span>';
        lucide.createIcons();
      }, 1500);
    }

    // PDF Report Generator using jsPDF & autotable
    function downloadPdfReport() {
      if (!currentReport) return;
      var jsPDF = window.jspdf.jsPDF;
      var doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      var r = currentReport;

      // Header Banner
      doc.setFillColor(26, 86, 219);
      doc.rect(0, 0, 210, 24, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('KSEC - AUDITOR DE SERVIDORES WEB', 14, 11);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.text('Informe Oficial de Auditoría de Seguridad HTTP y Remediación', 14, 18);

      var dateStr = new Date(r.timestamp).toLocaleString('es-ES', { dateStyle: 'medium', timeStyle: 'short' });
      doc.setFontSize(8);
      doc.text('Fecha: ' + dateStr, 196, 11, { align: 'right' });
      doc.text('Normativa: Mozilla Observatory / MDN', 196, 18, { align: 'right' });

      // Target Server Card
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(14, 30, 182, 34, 3, 3, 'FD');

      doc.setTextColor(30, 41, 59);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text('Servidor Web Objetivo:', 20, 39);
      doc.setTextColor(37, 99, 235);
      doc.setFontSize(10);
      doc.text(r.targetUrl, 68, 39);

      doc.setTextColor(100, 116, 139);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.text('Pruebas Aprobadas: ' + r.passedChecks + ' / ' + r.totalChecks, 20, 48);
      doc.text('Advertencias: ' + r.warningChecks, 85, 48);
      doc.text('Fallos Críticos: ' + r.failedChecks, 85, 55);
      doc.text('Latencia HTTP: ' + r.latencyMs + ' ms', 20, 55);

      // Grade box
      var gCol = r.grade.indexOf('A') === 0 ? [16, 185, 129] : 
                 r.grade.indexOf('B') === 0 ? [59, 130, 246] : 
                 r.grade.indexOf('C') === 0 ? [245, 158, 11] : [239, 68, 68];
      doc.setFillColor(gCol[0], gCol[1], gCol[2]);
      doc.roundedRect(154, 35, 36, 24, 3, 3, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text('CALIFICACIÓN', 172, 42, { align: 'center' });
      doc.setFontSize(15);
      doc.text(r.grade + ' (' + r.score + '/100)', 172, 53, { align: 'center' });

      // Summary
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text('1. Resumen Ejecutivo del Diagnóstico', 14, 72);
      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      var splitSum = doc.splitTextToSize(r.summary, 182);
      doc.text(splitSum, 14, 78);

      // Table of checks
      var tableData = r.results.map(function(item) {
        return [
          item.name,
          item.category,
          item.status === 'pass' ? 'Aprobado' : item.status === 'warning' ? 'Advertencia' : 'Fallo',
          item.valueFound ? (item.valueFound.length > 40 ? item.valueFound.substring(0, 37) + '...' : item.valueFound) : '(No presente)',
          (item.scoreImpact > 0 ? '+' : '') + item.scoreImpact + ' pts'
        ];
      });

      doc.autoTable({
        startY: 88,
        head: [['Cabecera / Prueba', 'Categoría', 'Estado', 'Valor en Servidor', 'Impacto']],
        body: tableData,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 8, fontStyle: 'bold' },
        bodyStyles: { fontSize: 7.5, textColor: [51, 65, 85], cellPadding: 2 },
        columnStyles: {
          0: { cellWidth: 42, fontStyle: 'bold' },
          1: { cellWidth: 32 },
          2: { cellWidth: 24 },
          3: { cellWidth: 64, font: 'courier' },
          4: { cellWidth: 20, halign: 'center' }
        },
        margin: { left: 14, right: 14 }
      });

      // Actions Page
      doc.addPage();
      doc.setFillColor(26, 86, 219);
      doc.rect(0, 0, 210, 12, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text('KSEC - PLAN DE ACCIONES Y GUÍA DE IMPLEMENTACIÓN', 14, 8);

      var currentY = 22;
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text('2. Plan de Acciones Correctivas y Mitigación', 14, currentY);
      currentY += 6;

      var failedRules = r.results.filter(function(item) { return item.status === 'fail' || item.status === 'warning'; });
      failedRules.forEach(function(rule, idx) {
        if (currentY > 240) {
          doc.addPage();
          currentY = 20;
        }
        var isFail = rule.status === 'fail';
        doc.setFillColor(isFail ? 255 : 255, isFail ? 241 : 251, isFail ? 242 : 235);
        doc.setDrawColor(isFail ? 254 : 254, isFail ? 226 : 243, isFail ? 226 : 199);
        doc.roundedRect(14, currentY, 182, 34, 2, 2, 'FD');

        doc.setTextColor(30, 41, 59);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text((idx + 1) + '. ' + rule.name, 18, currentY + 6);
        doc.setFontSize(7.5);
        doc.setTextColor(isFail ? 220 : 180, isFail ? 38 : 100, 38);
        doc.text(isFail ? '[ACCIÓN CRÍTICA]' : '[MEJORA RECOMENDADA]', 190, currentY + 6, { align: 'right' });

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(71, 85, 105);
        doc.text('Riesgo: ' + rule.description, 18, currentY + 12);

        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text('Valor Recomendado: ', 18, currentY + 20);
        doc.setFont('courier', 'bold');
        doc.setTextColor(37, 99, 235);
        doc.text(rule.recommendedValue.length > 70 ? rule.recommendedValue.substring(0, 67) + '...' : rule.recommendedValue, 50, currentY + 20);

        if (rule.remediationSnippet && rule.remediationSnippet.nginx) {
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(100, 116, 139);
          doc.setFontSize(7.5);
          doc.text('Directiva Nginx: ' + rule.remediationSnippet.nginx.replace(/\n/g, ' '), 18, currentY + 27);
        }

        currentY += 38;
      });

      var safeHost = r.targetUrl.replace(/^https?:\/\//, '').replace(/[\/:]/g, '_');
      doc.save('KSec_Reporte_' + safeHost + '.pdf');
    }
  </script>
</body>
</html>`
