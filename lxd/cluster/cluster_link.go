package cluster

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/canonical/lxd/lxd/util"
	"github.com/canonical/lxd/shared"
)

// CheckClusterLinkCertificate checks the cluster certificate at each address and ensures every reachable address matches the provided fingerprint.
// If a valid, consistent cluster certificate is found, it is returned with the first address at which it was found. Unreachable addresses are tolerated
// so long as at least one address is reachable and no reachable address presents a different certificate.
func CheckClusterLinkCertificate(ctx context.Context, addresses []string, fingerprint string, userAgent string) (*x509.Certificate, string, error) {
	type result struct {
		cert    *x509.Certificate
		address string
	}

	if len(addresses) == 0 {
		return nil, "", errors.New("Failed checking cluster link certificate: no addresses provided")
	}

	_, ok := ctx.Deadline()
	if !ok {
		// Set default timeout of 30s if no deadline context provided.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(30*time.Second))
		defer cancel()
	}

	// Pass context to the goroutines.
	g, ctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	var once sync.Once
	var firstResult result
	var reachable bool
	var fingerprintMismatch error
	retrievalErrs := make([]error, 0, len(addresses))
	for _, address := range addresses {
		addr := address
		networkAddress := util.CanonicalNetworkAddress(addr, shared.HTTPSDefaultPort)
		u, err := url.Parse("https://" + networkAddress)
		if err != nil || u.Host == "" {
			return nil, "", fmt.Errorf("Invalid URL for address %q: %w", addr, err)
		}

		// Launch a goroutine for each address.
		g.Go(func() error {
			// Try to retrieve the remote certificate.
			cert, err := shared.GetRemoteCertificate(ctx, u.String(), userAgent)
			if err != nil {
				mu.Lock()
				retrievalErrs = append(retrievalErrs, fmt.Errorf("Failed retrieving certificate from %q: %w", addr, err))
				mu.Unlock()
				return nil
			}

			mu.Lock()
			reachable = true
			mu.Unlock()

			// Check that the certificate fingerprint matches the provided fingerprint.
			certDigest := shared.CertFingerprint(cert)
			if fingerprint != certDigest {
				mu.Lock()
				if fingerprintMismatch == nil {
					fingerprintMismatch = fmt.Errorf("Certificate fingerprint mismatch for address %q", addr)
				}

				mu.Unlock()
				return nil
			}

			once.Do(func() {
				firstResult = result{cert: cert, address: addr}
			})
			return nil
		})
	}

	err := g.Wait()
	if err != nil {
		return nil, "", err
	}

	if fingerprintMismatch != nil {
		return nil, "", fingerprintMismatch
	}

	if firstResult.cert != nil {
		return firstResult.cert, firstResult.address, nil
	}

	if reachable {
		return nil, "", errors.New("No reachable address presented the expected cluster certificate")
	}

	if len(retrievalErrs) > 0 {
		return nil, "", fmt.Errorf("Failed retrieving cluster certificate from any address: %w", errors.Join(retrievalErrs...))
	}

	return firstResult.cert, firstResult.address, nil
}
