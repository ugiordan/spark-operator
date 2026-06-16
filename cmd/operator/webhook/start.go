/*
Copyright 2024 The Kubeflow authors.

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

package webhook

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"slices"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	sparkoperator "github.com/kubeflow/spark-operator/v2"
	"github.com/kubeflow/spark-operator/v2/api/v1beta2"
	"github.com/kubeflow/spark-operator/v2/internal/controller/mutatingwebhookconfiguration"
	"github.com/kubeflow/spark-operator/v2/internal/controller/validatingwebhookconfiguration"
	"github.com/kubeflow/spark-operator/v2/internal/webhook"
	"github.com/kubeflow/spark-operator/v2/pkg/certificate"
	"github.com/kubeflow/spark-operator/v2/pkg/common"
	operatorscheme "github.com/kubeflow/spark-operator/v2/pkg/scheme"
	// +kubebuilder:scaffold:imports
)

var (
	logger = ctrl.Log.WithName("")
)

var (
	namespaces          []string
	labelSelectorFilter string

	// Controller
	controllerThreads int
	cacheSyncTimeout  time.Duration

	// Webhook
	enableResourceQuotaEnforcement bool
	webhookCertDir                 string
	webhookCertName                string
	webhookKeyName                 string
	mutatingWebhookName            string
	validatingWebhookName          string
	webhookPort                    int
	webhookSecretName              string
	webhookSecretNamespace         string
	webhookServiceName             string
	webhookServiceNamespace        string

	// Cert Manager
	enableCertManager bool

	// Leader election
	enableLeaderElection        bool
	leaderElectionLockName      string
	leaderElectionLockNamespace string
	leaderElectionLeaseDuration time.Duration
	leaderElectionRenewDeadline time.Duration
	leaderElectionRetryPeriod   time.Duration

	// Metrics
	enableMetrics      bool
	metricsBindAddress string
	metricsEndpoint    string
	metricsPrefix      string
	metricsLabels      []string

	healthProbeBindAddress string
	secureMetrics          bool
	enableHTTP2            bool
	development            bool
	zapOptions             = logzap.Options{}
)

func NewStartCommand() *cobra.Command {
	var command = &cobra.Command{
		Use:   "start",
		Short: "Start controller and webhook",
		PreRun: func(_ *cobra.Command, args []string) {
			development = viper.GetBool("development")
		},
		Run: func(cmd *cobra.Command, args []string) {
			sparkoperator.PrintVersion(false)
			start()
		},
	}

	// Controller
	command.Flags().IntVar(&controllerThreads, "controller-threads", 10, "Number of worker threads used by the SparkApplication controller.")
	command.Flags().StringSliceVar(&namespaces, "namespaces", []string{}, "The Kubernetes namespace to manage. Will manage custom resource objects of the managed CRD types for the whole cluster if unset or contains empty string.")
	command.Flags().StringVar(&labelSelectorFilter, "label-selector-filter", "", "A comma-separated list of key=value, or key labels to filter resources during watch and list based on the specified labels.")
	command.Flags().DurationVar(&cacheSyncTimeout, "cache-sync-timeout", 30*time.Second, "Informer cache sync timeout.")

	// Webhook
	command.Flags().StringVar(&webhookCertDir, "webhook-cert-dir", "/etc/k8s-webhook-server/serving-certs", "The directory that contains the webhook server key and certificate. "+
		"When running as nonRoot, you must create and own this directory before running this command.")
	command.Flags().StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The file name of webhook server certificate.")
	command.Flags().StringVar(&webhookKeyName, "webhook-key-name", "tls.key", "The file name of webhook server key.")
	command.Flags().StringVar(&mutatingWebhookName, "mutating-webhook-name", "spark-operator-webhook", "The name of the mutating webhook.")
	command.Flags().StringVar(&validatingWebhookName, "validating-webhook-name", "spark-operator-webhook", "The name of the validating webhook.")
	command.Flags().IntVar(&webhookPort, "webhook-port", 9443, "Service port of the webhook server.")
	command.Flags().StringVar(&webhookSecretName, "webhook-secret-name", "spark-operator-webhook-certs", "The name of the secret that contains the webhook server's TLS certificate and key.")
	command.Flags().StringVar(&webhookSecretNamespace, "webhook-secret-namespace", "spark-operator", "The namespace of the secret that contains the webhook server's TLS certificate and key.")
	command.Flags().StringVar(&webhookServiceName, "webhook-svc-name", "spark-webhook", "The name of the Service for the webhook server.")
	command.Flags().StringVar(&webhookServiceNamespace, "webhook-svc-namespace", "spark-webhook", "The name of the Service for the webhook server.")
	command.Flags().BoolVar(&enableResourceQuotaEnforcement, "enable-resource-quota-enforcement", false, "Whether to enable ResourceQuota enforcement for SparkApplication resources. Requires the webhook to be enabled.")

	// Cert Manager
	command.Flags().BoolVar(&enableCertManager, "enable-cert-manager", false, "Enable cert-manager to manage the webhook server's TLS certificate.")

	// Leader election
	command.Flags().BoolVar(&enableLeaderElection, "leader-election", false, "Enable leader election for controller manager. "+
		"Enabling this will ensure there is only one active controller manager.")
	command.Flags().StringVar(&leaderElectionLockName, "leader-election-lock-name", "spark-operator-lock", "Name of the ConfigMap for leader election.")
	command.Flags().StringVar(&leaderElectionLockNamespace, "leader-election-lock-namespace", "spark-operator", "Namespace in which to create the ConfigMap for leader election.")
	command.Flags().DurationVar(&leaderElectionLeaseDuration, "leader-election-lease-duration", 15*time.Second, "Leader election lease duration.")
	command.Flags().DurationVar(&leaderElectionRenewDeadline, "leader-election-renew-deadline", 14*time.Second, "Leader election renew deadline.")
	command.Flags().DurationVar(&leaderElectionRetryPeriod, "leader-election-retry-period", 4*time.Second, "Leader election retry period.")

	// Prometheus metrics
	command.Flags().BoolVar(&enableMetrics, "enable-metrics", false, "Enable metrics.")
	command.Flags().StringVar(&metricsBindAddress, "metrics-bind-address", "0", "The address the metric endpoint binds to. "+
		"Use the port :8080. If not set, it will be 0 in order to disable the metrics server")
	command.Flags().StringVar(&metricsEndpoint, "metrics-endpoint", "/metrics", "Metrics endpoint.")
	command.Flags().StringVar(&metricsPrefix, "metrics-prefix", "", "Prefix for the metrics.")
	command.Flags().StringSliceVar(&metricsLabels, "metrics-labels", []string{}, "Labels to be added to the metrics.")

	command.Flags().StringVar(&healthProbeBindAddress, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	command.Flags().BoolVar(&secureMetrics, "secure-metrics", false, "If set the metrics endpoint is served securely")
	command.Flags().BoolVar(&enableHTTP2, "enable-http2", false, "If set, HTTP/2 will be enabled for the metrics and webhook servers")

	flagSet := flag.NewFlagSet("controller", flag.ExitOnError)
	ctrl.RegisterFlags(flagSet)
	zapOptions.BindFlags(flagSet)
	command.Flags().AddGoFlagSet(flagSet)

	return command
}

func start() {
	setupLog()

	// Create the client rest config. Use kubeConfig if given, otherwise assume in-cluster.
	cfg, err := ctrl.GetConfig()
	if err != nil {
		logger.Error(err, "failed to get kube config")
		os.Exit(1)
	}

	// Create the manager.
	tlsOptions := newTLSOptions(cfg)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: operatorscheme.WebhookScheme,
		Cache:  newCacheOptions(),
		Metrics: metricsserver.Options{
			BindAddress:   metricsBindAddress,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOptions,
		},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port:     webhookPort,
			CertDir:  webhookCertDir,
			CertName: webhookCertName,
			KeyName:  webhookKeyName,
			TLSOpts:  tlsOptions,
		}),
		HealthProbeBindAddress:  healthProbeBindAddress,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        leaderElectionLockName,
		LeaderElectionNamespace: leaderElectionLockNamespace,
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		logger.Error(err, "Failed to create manager")
		os.Exit(1)
	}

	client, err := client.New(cfg, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		logger.Error(err, "Failed to create client")
		os.Exit(1)
	}

	certProvider := certificate.NewProvider(
		client,
		webhookServiceName,
		webhookServiceNamespace,
		enableCertManager,
	)

	if err := wait.ExponentialBackoff(
		wait.Backoff{
			Steps:    5,
			Duration: 1 * time.Second,
			Factor:   2.0,
			Jitter:   0.1,
		},
		func() (bool, error) {
			if err := certProvider.SyncSecret(context.TODO(), webhookSecretName, webhookSecretNamespace); err != nil {
				if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		},
	); err != nil {
		logger.Error(err, "Failed to sync webhook secret")
		os.Exit(1)
	}

	logger.Info("Writing certificates", "path", webhookCertDir, "certificate name", webhookCertName, "key name", webhookKeyName)
	if err := certProvider.WriteFile(webhookCertDir, webhookCertName, webhookKeyName); err != nil {
		logger.Error(err, "Failed to save certificate")
		os.Exit(1)
	}

	if !enableCertManager {
		if err := mutatingwebhookconfiguration.NewReconciler(
			mgr.GetClient(),
			certProvider,
			mutatingWebhookName,
		).SetupWithManager(mgr, controller.Options{}); err != nil {
			logger.Error(err, "Failed to create controller", "controller", "MutatingWebhookConfiguration")
			os.Exit(1)
		}

		if err := validatingwebhookconfiguration.NewReconciler(
			mgr.GetClient(),
			certProvider,
			validatingWebhookName,
		).SetupWithManager(mgr, controller.Options{}); err != nil {
			logger.Error(err, "Failed to create controller", "controller", "ValidatingWebhookConfiguration")
			os.Exit(1)
		}
	}

	if err := ctrl.NewWebhookManagedBy(mgr).
		For(&v1beta2.SparkApplication{}).
		WithDefaulter(webhook.NewSparkApplicationDefaulter()).
		WithValidator(webhook.NewSparkApplicationValidator(mgr.GetClient(), enableResourceQuotaEnforcement)).
		WithLogConstructor(webhook.LogConstructor).
		Complete(); err != nil {
		logger.Error(err, "Failed to create mutating webhook for Spark application")
		os.Exit(1)
	}

	if err := ctrl.NewWebhookManagedBy(mgr).
		For(&v1beta2.ScheduledSparkApplication{}).
		WithDefaulter(webhook.NewScheduledSparkApplicationDefaulter()).
		WithValidator(webhook.NewScheduledSparkApplicationValidator()).
		WithLogConstructor(webhook.LogConstructor).
		Complete(); err != nil {
		logger.Error(err, "Failed to create mutating webhook for Scheduled Spark application")
		os.Exit(1)
	}

	if err := ctrl.NewWebhookManagedBy(mgr).
		For(&corev1.Pod{}).
		WithDefaulter(webhook.NewSparkPodDefaulter(mgr.GetClient(), namespaces)).
		WithLogConstructor(webhook.LogConstructor).
		Complete(); err != nil {
		logger.Error(err, "Failed to create mutating webhook for Spark pod")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", mgr.GetWebhookServer().StartedChecker()); err != nil {
		logger.Error(err, "Failed to set up health check")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", mgr.GetWebhookServer().StartedChecker()); err != nil {
		logger.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	logger.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "Failed to start manager")
		os.Exit(1)
	}
}

// setupLog Configures the logging system
func setupLog() {
	ctrl.SetLogger(logzap.New(
		logzap.UseFlagOptions(&zapOptions),
		func(o *logzap.Options) {
			o.Development = development
			o.ZapOpts = append(o.ZapOpts, zap.AddCaller())
			o.EncoderConfigOptions = append(o.EncoderConfigOptions, func(config *zapcore.EncoderConfig) {
				config.EncodeLevel = zapcore.CapitalLevelEncoder
				config.EncodeTime = zapcore.ISO8601TimeEncoder
				config.EncodeCaller = zapcore.ShortCallerEncoder
			})
		}),
	)
}

// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,resourceNames=cluster,verbs=get

func newTLSOptions(cfg *rest.Config) []func(c *tls.Config) {
	tlsOpts := fetchTLSProfile(cfg)

	// ALPN configuration
	if enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			c.NextProtos = []string{"h2", "http/1.1"}
		})
	} else {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			c.NextProtos = []string{"http/1.1"}
		})
	}
	return tlsOpts
}

func fetchTLSProfile(cfg *rest.Config) []func(*tls.Config) {
	var tlsOpts []func(*tls.Config)
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer bootstrapCancel()

	bootstrapClient, err := client.New(cfg, client.Options{Scheme: operatorscheme.WebhookScheme})
	if err != nil {
		logger.Info("Failed to create bootstrap client for TLS profile, using hardened defaults")
		tlsOpts = append(tlsOpts, func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 })
		return tlsOpts
	}

	apiServer := &unstructured.Unstructured{}
	apiServer.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "config.openshift.io", Version: "v1", Kind: "APIServer",
	})
	if err := bootstrapClient.Get(bootstrapCtx, client.ObjectKey{Name: "cluster"}, apiServer); err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			logger.Info("TLS profile not available, using hardened defaults (non-OpenShift cluster)")
			tlsOpts = append(tlsOpts, func(c *tls.Config) {
				c.MinVersion = tls.VersionTLS12
				c.CipherSuites = intermediateCiphers
			})
			return tlsOpts
		}
		// RBAC errors (403), timeouts, and other transient failures must not be
		// silently downgraded. Fail closed so the operator restarts and retries.
		logger.Error(err, "Failed to read APIServer TLS profile (possible RBAC or transient error), failing startup")
		os.Exit(1)
	}

	minVersion, ciphers := parseTLSProfile(apiServer)
	if ciphers != nil && len(ciphers) == 0 {
		logger.Error(nil, "Custom TLS profile specified ciphers but none are supported by Go, "+
			"refusing to start with unrestricted ciphers")
		os.Exit(1)
	}
	logger.Info("Applying cluster TLS profile", "minVersion", minVersion, "ciphers", len(ciphers))
	tlsOpts = append(tlsOpts, func(c *tls.Config) {
		c.MinVersion = minVersion
		if len(ciphers) > 0 {
			c.CipherSuites = ciphers
		}
	})
	return tlsOpts
}

var openSSLToGoCipher = map[string]uint16{
	"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-GCM-SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES256-GCM-SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES256-GCM-SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-RSA-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-ECDSA-AES128-SHA256":     tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-RSA-AES128-SHA256":       tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"AES128-GCM-SHA256":             tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"AES256-GCM-SHA384":             tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"AES128-SHA256":                 tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
}

var intermediateCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func parseTLSProfile(apiServer *unstructured.Unstructured) (uint16, []uint16) {
	profile, found, err := unstructured.NestedMap(apiServer.Object, "spec", "tlsSecurityProfile")
	if err != nil {
		logger.Error(err, "Failed to read tlsSecurityProfile from APIServer, using Intermediate defaults")
		return tls.VersionTLS12, intermediateCiphers
	}
	if !found || profile == nil {
		return tls.VersionTLS12, intermediateCiphers
	}
	profileType, _ := profile["type"].(string)
	switch profileType {
	case "Intermediate", "":
		return tls.VersionTLS12, intermediateCiphers
	case "Custom":
		custom, _, err := unstructured.NestedMap(profile, "custom")
		if err != nil {
			logger.Error(err, "Failed to read custom TLS profile, using Intermediate defaults")
			return tls.VersionTLS12, intermediateCiphers
		}
		if custom == nil {
			logger.Info("Custom TLS profile type set but no custom block provided, using Intermediate defaults")
			return tls.VersionTLS12, intermediateCiphers
		}
		minVer, _ := custom["minTLSVersion"].(string)
		minVersion := tlsVersionFromString(minVer)
		cipherNames, _, err := unstructured.NestedStringSlice(custom, "ciphers")
		if err != nil {
			logger.Error(err, "Failed to read ciphers from custom TLS profile, using Intermediate defaults")
			return tls.VersionTLS12, intermediateCiphers
		}
		ciphers := make([]uint16, 0, len(cipherNames))
		for _, name := range cipherNames {
			if id, ok := openSSLToGoCipher[name]; ok {
				ciphers = append(ciphers, id)
			} else {
				logger.Info("Cipher from TLS profile not supported by Go, skipping", "cipher", name)
			}
		}
		return minVersion, ciphers
	case "Modern":
		return tls.VersionTLS13, nil
	case "Old":
		return tls.VersionTLS12, nil
	default:
		logger.Info("Unrecognized TLS profile type, using Intermediate defaults", "profileType", profileType)
		return tls.VersionTLS12, intermediateCiphers
	}
}

func tlsVersionFromString(v string) uint16 {
	switch v {
	case "VersionTLS12":
		return tls.VersionTLS12
	case "VersionTLS13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// newCacheOptions creates and returns a cache.Options instance configured with default namespaces and object caching settings.
func newCacheOptions() cache.Options {
	defaultNamespaces := make(map[string]cache.Config)
	if !slices.Contains(namespaces, cache.AllNamespaces) {
		for _, ns := range namespaces {
			defaultNamespaces[ns] = cache.Config{}
		}
	}

	byObject := map[client.Object]cache.ByObject{
		&corev1.Pod{}: {
			Label: labels.SelectorFromSet(labels.Set{
				common.LabelLaunchedBySparkOperator: "true",
			}),
		},
		&v1beta2.SparkApplication{}:          {},
		&v1beta2.ScheduledSparkApplication{}: {},
		&admissionregistrationv1.MutatingWebhookConfiguration{}: {
			Field: fields.SelectorFromSet(fields.Set{
				"metadata.name": mutatingWebhookName,
			}),
		},
		&admissionregistrationv1.ValidatingWebhookConfiguration{}: {
			Field: fields.SelectorFromSet(fields.Set{
				"metadata.name": validatingWebhookName,
			}),
		},
	}

	if enableResourceQuotaEnforcement {
		byObject[&corev1.ResourceQuota{}] = cache.ByObject{}
	}

	options := cache.Options{
		Scheme:            operatorscheme.WebhookScheme,
		DefaultNamespaces: defaultNamespaces,
		ByObject:          byObject,
	}

	return options
}
