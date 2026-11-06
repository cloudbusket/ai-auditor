package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const requestTimeout = 10 * time.Second

type Client struct {
	Clientset k8sclient.Interface
	Config    *rest.Config
	Context   string
}

// NewClient loads in-cluster or external kubeconfig and checks API connectivity.
// Kubernetes remains optional: configuration or connectivity failures are recorded
// in Inventory rather than aborting the host audit.
func NewClient() (*Client, *Inventory, error) {
	inv := &Inventory{}

	config, contextName, err := loadConfig()
	if err != nil {
		inv.Error = err.Error()
		return nil, inv, nil
	}

	inv.Configured = true
	inv.Context = contextName

	config.Timeout = requestTimeout

	clientset, err := k8sclient.NewForConfig(config)
	if err != nil {
		inv.Error = "Unable to initialize Kubernetes client: " + err.Error()
		return nil, inv, nil
	}

	version, err := clientset.Discovery().ServerVersion()
	if err != nil {
		inv.Error = "Kubernetes API is unreachable: " + err.Error()
		return nil, inv, nil
	}

	inv.Connected = true
	inv.ServerVersion = version.GitVersion
	inv.PlatformVersion = version.Platform
	inv.CollectedAt = time.Now().UTC()

	return &Client{
		Clientset: clientset,
		Config:    config,
		Context:   contextName,
	}, inv, nil
}

func loadConfig() (*rest.Config, string, error) {
	// Prefer in-cluster configuration when running inside Kubernetes.
	if config, err := rest.InClusterConfig(); err == nil {
		return config, "in-cluster", nil
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		loadingRules.Precedence = filepath.SplitList(kubeconfig)
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	)

	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, "", fmt.Errorf("Kubernetes is not configured: %w", err)
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("unable to load Kubernetes configuration: %w", err)
	}

	return config, rawConfig.CurrentContext, nil
}

// CollectClusterInfo verifies that the configured client can query cluster nodes.
func CollectClusterInfo(client *Client, inv *Inventory) error {
	if client == nil || client.Clientset == nil {
		return fmt.Errorf("Kubernetes client is not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	_, err := client.Clientset.CoreV1().Nodes().List(
		ctx,
		metav1.ListOptions{Limit: 1},
	)
	if err != nil {
		return fmt.Errorf("unable to query Kubernetes nodes: %w", err)
	}

	if inv != nil {
		inv.Connected = true
	}

	return nil
}
