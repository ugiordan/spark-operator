/*
Copyright 2026 The Kubeflow authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"context"
	cryptotls "crypto/tls"
	stderrors "errors"
	"net"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var profileLog = ctrl.Log.WithName("tls-profile")

type FetchResult struct {
	TLSOpts      []func(*cryptotls.Config)
	Fetched      bool
	APIAvailable bool
	RawSpec      map[string]interface{}
}

var APIServerGVK = schema.GroupVersionKind{
	Group: "config.openshift.io", Version: "v1", Kind: "APIServer",
}

func FetchTLSProfile(cfg *rest.Config, scheme *runtime.Scheme) FetchResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		profileLog.Error(err, "Failed to create bootstrap client for TLS profile, using hardened defaults")
		return hardenedDefault()
	}

	return FetchTLSProfileWithClient(ctx, c)
}

func FetchTLSProfileWithClient(ctx context.Context, c client.Client) FetchResult {
	apiServer := &unstructured.Unstructured{}
	apiServer.SetGroupVersionKind(APIServerGVK)

	if err := c.Get(ctx, client.ObjectKey{Name: "cluster"}, apiServer); err != nil {
		if meta.IsNoMatchError(err) {
			profileLog.Info("TLS profile not available (non-OpenShift cluster)")
			return hardenedDefault()
		}
		if errors.IsNotFound(err) {
			profileLog.Info("APIServer resource not found, using hardened defaults")
			return hardenedDefault()
		}
		if isTransient(err) {
			profileLog.Info("Transient error reading APIServer TLS profile, using Intermediate fallback", "error", err)
			return FetchResult{
				TLSOpts:      intermediateOpts(),
				Fetched:      false,
				APIAvailable: true,
				RawSpec:      nil,
			}
		}
		if errors.IsForbidden(err) || errors.IsUnauthorized(err) {
			profileLog.Error(err, "Permission denied reading TLS profile, using hardened defaults; watcher will retry")
			return FetchResult{
				TLSOpts:      intermediateOpts(),
				Fetched:      false,
				APIAvailable: true,
				RawSpec:      nil,
			}
		}
		profileLog.Error(err, "Failed to read APIServer TLS profile, using hardened defaults")
		return hardenedDefault()
	}

	minVersion, ciphers, rawSpec := ParseTLSProfile(apiServer)
	profileLog.Info("Applying cluster TLS profile", "minVersion", minVersion, "ciphers", len(ciphers))

	return FetchResult{
		TLSOpts: []func(*cryptotls.Config){
			func(c *cryptotls.Config) {
				c.MinVersion = minVersion
				if len(ciphers) > 0 {
					c.CipherSuites = ciphers
				}
			},
		},
		Fetched:      true,
		APIAvailable: true,
		RawSpec:      rawSpec,
	}
}

func isTransient(err error) bool {
	if errors.IsServiceUnavailable(err) ||
		errors.IsTimeout(err) ||
		errors.IsServerTimeout(err) ||
		errors.IsTooManyRequests(err) {
		return true
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	return stderrors.As(err, &dnsErr)
}

func hardenedDefault() FetchResult {
	return FetchResult{
		TLSOpts: []func(*cryptotls.Config){
			func(c *cryptotls.Config) { c.MinVersion = cryptotls.VersionTLS12 },
		},
		Fetched: false,
		RawSpec: nil,
	}
}

func intermediateOpts() []func(*cryptotls.Config) {
	return []func(*cryptotls.Config){
		func(c *cryptotls.Config) {
			c.MinVersion = cryptotls.VersionTLS12
			c.CipherSuites = IntermediateCiphers
		},
	}
}

var OpenSSLToGoCipher = map[string]uint16{
	"ECDHE-ECDSA-AES128-GCM-SHA256": cryptotls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-GCM-SHA256":   cryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES256-GCM-SHA384": cryptotls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES256-GCM-SHA384":   cryptotls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-CHACHA20-POLY1305": cryptotls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-RSA-CHACHA20-POLY1305":   cryptotls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-ECDSA-AES128-SHA256":     cryptotls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-RSA-AES128-SHA256":       cryptotls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"AES128-GCM-SHA256":             cryptotls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"AES256-GCM-SHA384":             cryptotls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"AES128-SHA256":                 cryptotls.TLS_RSA_WITH_AES_128_CBC_SHA256,
}

var IntermediateCiphers = []uint16{
	cryptotls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	cryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	cryptotls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	cryptotls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	cryptotls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	cryptotls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func ParseTLSProfile(apiServer *unstructured.Unstructured) (uint16, []uint16, map[string]interface{}) {
	profile, found, err := unstructured.NestedMap(apiServer.Object, "spec", "tlsSecurityProfile")
	if err != nil {
		profileLog.Error(err, "Failed to read tlsSecurityProfile from APIServer, using Intermediate defaults")
		return cryptotls.VersionTLS12, IntermediateCiphers, nil
	}
	if !found || profile == nil {
		return cryptotls.VersionTLS12, IntermediateCiphers, profile
	}
	profileType, _ := profile["type"].(string)
	switch profileType {
	case "Intermediate", "":
		return cryptotls.VersionTLS12, IntermediateCiphers, profile
	case "Custom":
		custom, _, err := unstructured.NestedMap(profile, "custom")
		if err != nil {
			profileLog.Error(err, "Failed to read custom TLS profile, using Intermediate defaults")
			return cryptotls.VersionTLS12, IntermediateCiphers, profile
		}
		if custom == nil {
			profileLog.Info("Custom TLS profile type set but no custom block provided, using Intermediate defaults")
			return cryptotls.VersionTLS12, IntermediateCiphers, profile
		}
		minVer, _ := custom["minTLSVersion"].(string)
		minVersion := TLSVersionFromString(minVer)
		cipherNames, _, err := unstructured.NestedStringSlice(custom, "ciphers")
		if err != nil {
			profileLog.Error(err, "Failed to read ciphers from custom TLS profile, using Intermediate defaults")
			return cryptotls.VersionTLS12, IntermediateCiphers, profile
		}
		var ciphers []uint16
		for _, name := range cipherNames {
			if id, ok := OpenSSLToGoCipher[name]; ok {
				ciphers = append(ciphers, id)
			} else {
				profileLog.Info("Cipher from TLS profile not supported by Go, skipping", "cipher", name)
			}
		}
		return minVersion, ciphers, profile
	case "Modern":
		return cryptotls.VersionTLS13, nil, profile
	case "Old":
		return cryptotls.VersionTLS12, nil, profile
	default:
		profileLog.Info("Unrecognized TLS profile type, using Intermediate defaults", "profileType", profileType)
		return cryptotls.VersionTLS12, IntermediateCiphers, profile
	}
}

func TLSVersionFromString(v string) uint16 {
	switch v {
	case "VersionTLS12":
		return cryptotls.VersionTLS12
	case "VersionTLS13":
		return cryptotls.VersionTLS13
	default:
		return cryptotls.VersionTLS12
	}
}
