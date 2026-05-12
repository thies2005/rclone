package internxt

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/rclone/rclone/fs"
)

func init() {
	setupAndroidDNS()
}

func setupAndroidDNS() {
	dnsServers := strings.TrimSpace(os.Getenv("RCLONE_DNS_SERVERS"))
	if dnsServers == "" {
		return
	}

	servers := strings.Split(dnsServers, ",")
	var valid []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s = s + ":53"
		}
		valid = append(valid, s)
	}

	if len(valid) == 0 {
		return
	}

	fs.Logf(nil, "Android DNS override: using %v", valid)

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var lastErr error
			for _, server := range valid {
				d := net.Dialer{}
				conn, err := d.DialContext(ctx, "udp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
				conn, err = d.DialContext(ctx, "tcp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}
