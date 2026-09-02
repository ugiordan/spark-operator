package tls

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestProfileWatcherReceivesProfileUpdate(t *testing.T) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("testdata")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("failed to start envtest: %v", err)
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			t.Errorf("failed to stop envtest: %v", err)
		}
	}()

	scheme := runtime.NewScheme()
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	apiServer := makeAPIServerObj("Intermediate")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := k8sClient.Create(ctx, apiServer); err != nil {
		t.Fatalf("failed to create APIServer object: %v", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	watchCtx, err := SetupProfileWatcherRestart(ctx, mgr, FetchResult{
		APIAvailable: true,
		RawSpec:      map[string]interface{}{"type": "Intermediate"},
	})
	if err != nil {
		t.Fatalf("failed to set up watcher: %v", err)
	}

	managerErr := make(chan error, 1)
	go func() {
		managerErr <- mgr.Start(watchCtx)
	}()

	syncCtx, syncCancel := context.WithTimeout(ctx, 10*time.Second)
	defer syncCancel()
	if !mgr.GetCache().WaitForCacheSync(syncCtx) {
		select {
		case err := <-managerErr:
			t.Fatalf("manager stopped before cache synchronization: %v", err)
		default:
			t.Fatal("manager cache did not sync")
		}
	}

	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, apiServer); err != nil {
		t.Fatalf("failed to get APIServer object: %v", err)
	}
	if err := unstructured.SetNestedField(apiServer.Object, "Modern", "spec", "tlsSecurityProfile", "type"); err != nil {
		t.Fatalf("failed to update TLS profile: %v", err)
	}
	if err := k8sClient.Update(ctx, apiServer); err != nil {
		t.Fatalf("failed to update APIServer object: %v", err)
	}

	select {
	case <-watchCtx.Done():
	case err := <-managerErr:
		if watchCtx.Err() == nil {
			t.Fatalf("manager stopped before watcher observed the update: %v", err)
		}
		if err != nil && err != context.Canceled {
			t.Fatalf("manager stopped with unexpected error: %v", err)
		}
		return
	case <-time.After(10 * time.Second):
		t.Fatal("watcher did not observe the APIServer profile update")
	}

	select {
	case err := <-managerErr:
		if err != nil && err != context.Canceled {
			t.Fatalf("manager stopped with unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not stop after the watcher cancelled its context")
	}
}
