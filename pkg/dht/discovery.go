package dht

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DiscoverPublicIP tries multiple services to figure out this machine's public IP.
// Falls back to the local IP if everything fails (e.g. offline / no internet).
func DiscoverPublicIP() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, url := range services {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("could not determine public IP from any service")
}

// GetLocalIP returns the preferred outbound IP of this machine.
// This is the IP that would be used to reach the internet, not 127.0.0.1.
func GetLocalIP() (string, error) {
	// We don't actually send anything, just use the OS routing table to figure out
	// which interface would be used to reach an external address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// ResolveAdvertiseAddr figures out what address this node should tell other peers to use.
// Priority: explicit override > public IP > local IP
func ResolveAdvertiseAddr(listenPort string, advertiseAddr string) (string, error) {
	if advertiseAddr != "" {
		return advertiseAddr, nil
	}

	// Extract port from listen address (e.g. ":7000" or "0.0.0.0:7000")
	_, port, err := net.SplitHostPort(listenPort)
	if err != nil {
		port = listenPort
	}

	// Try public IP first
	publicIP, err := DiscoverPublicIP()
	if err == nil {
		return net.JoinHostPort(publicIP, port), nil
	}

	// Fall back to local IP
	localIP, err := GetLocalIP()
	if err != nil {
		return "", fmt.Errorf("cannot determine any reachable address: %w", err)
	}

	return net.JoinHostPort(localIP, port), nil
}
