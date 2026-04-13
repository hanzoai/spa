// Package main is hanzoai/spa — zero-config SPA server.
//
// Single app mode (default):
//
//	FROM ghcr.io/hanzoai/spa
//	COPY dist /public
//
// Multi-app mode (MULTI_APP=true):
//
//	FROM ghcr.io/hanzoai/spa
//	COPY --from=build /app/apps/superadmin/dist /public/superadmin
//	COPY --from=build /app/apps/ats/dist        /public/ats
//	ENV MULTI_APP=true
//
// In multi-app mode, the hostname prefix selects the app:
//   ats.example.com   → /public/ats/
//   bd.example.com    → /public/bd/
//   Default           → /public/superadmin/
//
// Features:
//   - SPA mode: index.html served for all routes (client-side routing)
//   - Aggressive caching: hashed assets get 1 year, index.html gets no-cache
//   - Security headers: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
//   - Gzip/Brotli: pre-compressed .gz/.br files served automatically
//   - Health check: GET /health → 200
//   - Port: 3000 (override with PORT env var)
//   - Root: /public (override with ROOT env var)
//   - Scratch-based: ~5MB total image size
package main

import (
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	root := os.Getenv("ROOT")
	if root == "" {
		root = "/public"
	}
	multiApp := os.Getenv("MULTI_APP") == "true"
	defaultApp := os.Getenv("DEFAULT_APP")
	if defaultApp == "" {
		defaultApp = "superadmin"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	if multiApp {
		log.Printf("spa: multi-app mode, root=%s, default=%s, port=%s", root, defaultApp, port)
		mux.Handle("/", multiAppHandler(root, defaultApp))
	} else {
		log.Printf("spa: serving %s on :%s", root, port)
		mux.Handle("/", spaHandler(root))
	}

	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// resolveApp picks the app subdirectory from the hostname prefix.
func resolveApp(host, defaultApp string) string {
	// Strip port
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	// First label of hostname
	prefix := host
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		prefix = host[:idx]
	}
	switch prefix {
	case "ats", "bd", "ta", "superadmin":
		return prefix
	default:
		return defaultApp
	}
}

func multiAppHandler(root, defaultApp string) http.Handler {
	allowFraming := os.Getenv("ALLOW_FRAMING") == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app := resolveApp(r.Host, defaultApp)
		appRoot := filepath.Join(root, app)
		setSecurityHeaders(w, allowFraming)

		path := filepath.Join(appRoot, filepath.Clean(r.URL.Path))
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() {
			serveFile(w, r, filepath.Join(appRoot, "index.html"), true)
			return
		}
		serveFile(w, r, path, false)
	})
}

func spaHandler(root string) http.Handler {
	allowFraming := os.Getenv("ALLOW_FRAMING") == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, allowFraming)
		path := filepath.Join(root, filepath.Clean(r.URL.Path))
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() {
			serveFile(w, r, filepath.Join(root, "index.html"), true)
			return
		}
		serveFile(w, r, path, false)
	})
}

func setSecurityHeaders(w http.ResponseWriter, allowFraming bool) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !allowFraming {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	}
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func serveFile(w http.ResponseWriter, r *http.Request, path string, isFallback bool) {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "error", 500)
		return
	}

	ext := filepath.Ext(path)
	ct := mime.TypeByExtension(ext)
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	name := filepath.Base(path)
	if isFallback || name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	} else if isHashedAsset(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}

	accept := r.Header.Get("Accept-Encoding")
	if strings.Contains(accept, "br") {
		if br, err := os.Open(path + ".br"); err == nil {
			defer br.Close()
			w.Header().Set("Content-Encoding", "br")
			w.Header().Set("Vary", "Accept-Encoding")
			io.Copy(w, br)
			return
		}
	}
	if strings.Contains(accept, "gzip") {
		if gz, err := os.Open(path + ".gz"); err == nil {
			defer gz.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			io.Copy(w, gz)
			return
		}
	}

	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

func isHashedAsset(name string) bool {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if idx := strings.LastIndex(base, "-"); idx > 0 {
		hash := base[idx+1:]
		if len(hash) >= 6 {
			for _, c := range hash {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					return false
				}
			}
			return true
		}
	}
	return false
}
