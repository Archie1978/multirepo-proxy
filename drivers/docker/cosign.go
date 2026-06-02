package docker

// Cosign (Sigstore) signature verification.
//
// Protocol:
//   1. Compute the signature tag: sha256:<hex> → sha256-<hex>.sig
//   2. GET /v2/<image>/manifests/<sigTag> with Accept OCI
//   3. If 404 and RequireSignature=true  → error "no signature found"
//   4. If manifest found + PublicKeyFile configured → ECDSA verification
//      - fetch each layer blob (DSSE envelope)
//      - base64 decode the "dev.cosignproject.cosign/signature" annotation
//      - ecdsa.Verify(pubKey, sha256(blobContent), decodedSig)
//
// Signature format in registry (Cosign ≥ 1.x):
//   - OCI manifest where each layer contains the signature annotation
//   - The layer blob is the SimpleSigning envelope (JSON)
//   - The ECDSA signature (DER) is base64-encoded in the annotation

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	cosignSigAnnotation  = "dev.cosignproject.cosign/signature"
	cosignSigMediaType   = "application/vnd.dev.cosign.simplesigning.v1+json"
	ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
)

// cosignVerifier verifies Cosign signatures of Docker images.
type cosignVerifier struct {
	pubKeys       []*ecdsa.PublicKey // empty = presence-only verification
	requireSig    bool
	fetchWithAuth func(ctx context.Context, url, accept string) ([]byte, http.Header, error)
}

// newCosignVerifier creates a verifier.
// pubKeyFiles: paths to PEM public keys (empty = presence only).
//
//	The signature is valid if it matches at least one key.
//
// requireSig: if true, an absent signature is an error.
// fetchFn: the driver's bearer authentication function.
func newCosignVerifier(pubKeyFiles []string, requireSig bool, fetchFn func(context.Context, string, string) ([]byte, http.Header, error)) (*cosignVerifier, error) {
	v := &cosignVerifier{
		requireSig:    requireSig,
		fetchWithAuth: fetchFn,
	}
	for _, path := range pubKeyFiles {
		if path == "" {
			continue
		}
		key, err := loadECPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("cosign: loading public key %q: %w", path, err)
		}
		v.pubKeys = append(v.pubKeys, key)
	}
	return v, nil
}

// Verify verifies the Cosign signature of the manifest identified by digest.
// imageName: e.g. "library/nginx"
// upstream:  e.g. "https://registry-1.docker.io"
// digest:    e.g. "sha256:abc123…"
//
// Returns nil if the signature is valid (or if Cosign is in presence-only mode and the signature exists).
// Returns an error describing the problem otherwise.
func (v *cosignVerifier) Verify(ctx context.Context, upstream, imageName, digest string) error {
	sigTag := digestToSigTag(digest)
	url := upstream + "/v2/" + imageName + "/manifests/" + sigTag

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	data, _, err := v.fetchWithAuth(ctx, url, ociManifestMediaType)
	if err != nil {
		if err.Error() == "not found" || strings.Contains(err.Error(), "404") {
			if v.requireSig {
				return fmt.Errorf("no Cosign signature found for %s@%s", imageName, digest)
			}
			return nil
		}
		if v.requireSig {
			return fmt.Errorf("error fetching Cosign signature for %s@%s: %w", imageName, digest, err)
		}
		return nil
	}

	// No public key → presence only is sufficient.
	if len(v.pubKeys) == 0 {
		return nil
	}

	// Cryptographic verification: iterate over layers of the signature manifest.
	return v.verifySigManifest(ctx, upstream, imageName, data)
}

// verifySigManifest extracts layers from the signature manifest and verifies at least one.
func (v *cosignVerifier) verifySigManifest(ctx context.Context, upstream, imageName string, manifestData []byte) error {
	var manifest struct {
		Layers []struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("cosign: invalid signature manifest: %w", err)
	}
	if len(manifest.Layers) == 0 {
		return fmt.Errorf("cosign: signature manifest has no layers")
	}

	for _, layer := range manifest.Layers {
		sigB64, ok := layer.Annotations[cosignSigAnnotation]
		if !ok || sigB64 == "" {
			continue
		}

		// Fetch the blob (SimpleSigning envelope = signed payload).
		blobURL := upstream + "/v2/" + imageName + "/blobs/" + layer.Digest
		blobData, _, err := v.fetchWithAuth(ctx, blobURL, cosignSigMediaType)
		if err != nil {
			continue
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			continue
		}

		h := sha256.Sum256(blobData)
		for _, key := range v.pubKeys {
			if verifyECDSA(key, h[:], sigBytes) {
				return nil
			}
		}
	}
	return fmt.Errorf("cosign: no valid signature found for the %d configured key(s)", len(v.pubKeys))
}

// ── Cryptographic helpers ──────────────────────────────────────────────────────

// digestToSigTag converts a digest to a Cosign signature tag.
// "sha256:abc123" → "sha256-abc123.sig"
func digestToSigTag(digest string) string {
	return strings.ReplaceAll(digest, ":", "-") + ".sig"
}

// loadECPublicKey loads an ECDSA public key from a PEM file.
func loadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not of ECDSA type")
	}
	return ecKey, nil
}

// verifyECDSA verifies an ECDSA signature over a hash.
// Supports both formats: DER (ASN.1) and raw r||s.
func verifyECDSA(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	// DER attempt (standard format, used by cosign).
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sig, &rs); err == nil && len(rest) == 0 {
		return ecdsa.Verify(pub, hash, rs.R, rs.S)
	}

	// Raw r||s attempt (fallback, e.g. older formats).
	n := len(sig) / 2
	if len(sig) == 2*n {
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		return ecdsa.Verify(pub, hash, r, s)
	}
	return false
}
