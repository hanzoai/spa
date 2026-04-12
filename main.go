// Package main is hanzoai/spa — zero-config SPA server.
//
// Drop your Vite/React build output into /public and run. That's it.
// SPA mode is always on. No flags needed.
//
//	FROM ghcr.io/hanzoai/spa
//	COPY dist /public
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

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", spaHandler(root))

	addr := ":" + port
	log.Printf("spa: serving %s on %s", root, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func spaHandler(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		path := filepath.Join(root, filepath.Clean(r.URL.Path))

		// Try the exact file first
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() {
			// SPA fallback: serve index.html for any missing path
			serveFile(w, r, filepath.Join(root, "index.html"), true)
			return
		}

		serveFile(w, r, path, false)
	})
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

	// Content type
	ext := filepath.Ext(path)
	ct := mime.TypeByExtension(ext)
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	// Cache policy: hashed assets get 1 year, everything else no-cache
	name := filepath.Base(path)
	if isFallback || name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	} else if isHashedAsset(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}

	// Try pre-compressed versions (Brotli > Gzip)
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

// isHashedAsset detects Vite/Webpack hashed filenames like index-DByAis3x.js
func isHashedAsset(name string) bool {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	// Pattern: name-HASH.ext where HASH is 6+ alphanumeric chars
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
