// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package csrsigner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/substratex509"
	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	ServiceDNSSignerName  = "servicedns.csr.podcert.ate.dev/identity"
	PodIdentitySignerName = "podidentity.csr.podcert.ate.dev/identity"
	backendLabel          = "podcert.ate.dev/backend"
	backendValue          = "csr-configmap"
)

var requiredUsages = []certsv1.KeyUsage{
	certsv1.UsageClientAuth,
	certsv1.UsageDigitalSignature,
	certsv1.UsageServerAuth,
}

// Controller signs the authenticated CSR/ConfigMap compatibility protocol used
// on clusters that do not serve PodCertificateRequest or ClusterTrustBundle.
type Controller struct {
	kc          kubernetes.Interface
	servicePool localca.Pool
	podPool     localca.Pool
	informer    cache.SharedIndexInformer
	queue       workqueue.TypedRateLimitingInterface[string]
}

func New(kc kubernetes.Interface, servicePool, podPool localca.Pool) *Controller {
	factory := informers.NewSharedInformerFactory(kc, 24*time.Hour)
	informer := factory.Certificates().V1().CertificateSigningRequests().Informer()
	c := &Controller{
		kc: kc, servicePool: servicePool, podPool: podPool, informer: informer,
		queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.enqueue,
		UpdateFunc: func(_, newObj any) { c.enqueue(newObj) },
	})
	return c
}

func (c *Controller) enqueue(obj any) {
	csr, ok := obj.(*certsv1.CertificateSigningRequest)
	if !ok || csr.Labels[backendLabel] != backendValue || !supportedSigner(csr.Spec.SignerName) {
		return
	}
	c.queue.Add(csr.Name)
}

func (c *Controller) Run(ctx context.Context, workers int) error {
	defer c.queue.ShutDown()
	go c.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		return fmt.Errorf("CSR informer did not sync")
	}
	if workers < 1 {
		workers = 1
	}
	for range workers {
		go c.runWorker(ctx)
	}
	<-ctx.Done()
	return nil
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *Controller) processNext(ctx context.Context) bool {
	name, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(name)
	obj, exists, err := c.informer.GetIndexer().GetByKey(name)
	if err != nil {
		c.retry(ctx, name, err)
		return true
	}
	if !exists {
		c.queue.Forget(name)
		return true
	}
	csr := obj.(*certsv1.CertificateSigningRequest).DeepCopy()
	if terminal(csr) {
		c.queue.Forget(name)
		return true
	}
	if err := c.sign(ctx, csr); err != nil {
		c.retry(ctx, name, err)
		return true
	}
	c.queue.Forget(name)
	return true
}

func (c *Controller) retry(ctx context.Context, name string, err error) {
	slog.ErrorContext(ctx, "Failed to sign authenticated CSR", "csr", name, "err", err)
	c.queue.AddRateLimited(name)
}

func terminal(csr *certsv1.CertificateSigningRequest) bool {
	if len(csr.Status.Certificate) != 0 {
		return true
	}
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certsv1.CertificateDenied || condition.Type == certsv1.CertificateFailed {
			return true
		}
	}
	return false
}

type identity struct {
	namespace, serviceAccountName, serviceAccountUID string
	podName, podUID, nodeName, nodeUID               string
}

func (c *Controller) sign(ctx context.Context, csr *certsv1.CertificateSigningRequest) error {
	request, id, pod, err := c.validate(ctx, csr)
	if err != nil {
		return err
	}
	lifetime := 24 * time.Hour
	if csr.Spec.ExpirationSeconds != nil && time.Duration(*csr.Spec.ExpirationSeconds)*time.Second < lifetime {
		lifetime = time.Duration(*csr.Spec.ExpirationSeconds) * time.Second
	}
	notBefore := time.Now().Add(-2 * time.Minute)
	template := &x509.Certificate{
		BasicConstraintsValid: true, NotBefore: notBefore, NotAfter: notBefore.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	pool := c.servicePool
	if csr.Spec.SignerName == ServiceDNSSignerName {
		template.DNSNames, err = c.serviceDNSNames(ctx, pod)
		if err != nil {
			return err
		}
	} else {
		pool = c.podPool
		template.Subject = pkix.Name{CommonName: rand.Text()}
		template.URIs = []*url.URL{{Scheme: "spiffe", Host: "cluster.local", Path: path.Join("ns", id.namespace, "sa", id.serviceAccountName)}}
		err = substratex509.AddPodIdentityToCertificate(&substratex509.PodIdentity{
			Namespace: id.namespace, ServiceAccountName: id.serviceAccountName, ServiceAccountUID: id.serviceAccountUID,
			PodName: id.podName, PodUID: id.podUID, NodeName: id.nodeName, NodeUID: id.nodeUID,
		}, template)
		if err != nil {
			return fmt.Errorf("add pod identity: %w", err)
		}
	}
	chain, err := pool.CreateCertificate(template, request.PublicKey)
	if err != nil {
		return fmt.Errorf("sign certificate: %w", err)
	}
	anchors, err := pool.TrustAnchors()
	if err != nil {
		return fmt.Errorf("load trust anchors: %w", err)
	}
	var certificate bytes.Buffer
	for _, der := range chain {
		_ = pem.Encode(&certificate, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	for _, anchor := range anchors {
		_ = pem.Encode(&certificate, &pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})
	}

	if !approved(csr) {
		now := metav1.Now()
		csr.Status.Conditions = append(csr.Status.Conditions, certsv1.CertificateSigningRequestCondition{
			Type: certsv1.CertificateApproved, Status: corev1.ConditionTrue, Reason: "PodIdentityValidated",
			Message:        "Authenticated pod, service account, node, signer, usages, and CSR were validated",
			LastUpdateTime: now, LastTransitionTime: now,
		})
		csr, err = c.kc.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("approve CSR: %w", err)
		}
	}
	csr = csr.DeepCopy()
	csr.Status.Certificate = certificate.Bytes()
	if _, err := c.kc.CertificatesV1().CertificateSigningRequests().UpdateStatus(ctx, csr, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("publish certificate: %w", err)
	}
	slog.InfoContext(ctx, "Issued authenticated pod certificate", "csr", csr.Name, "signer", csr.Spec.SignerName, "pod", id.namespace+"/"+id.podName)
	return nil
}

func (c *Controller) validate(ctx context.Context, csr *certsv1.CertificateSigningRequest) (*x509.CertificateRequest, identity, *corev1.Pod, error) {
	var id identity
	if csr.Labels[backendLabel] != backendValue || !supportedSigner(csr.Spec.SignerName) {
		return nil, id, nil, fmt.Errorf("unsupported backend or signer")
	}
	if !equalUsages(csr.Spec.Usages, requiredUsages) {
		return nil, id, nil, fmt.Errorf("unexpected usages %v", csr.Spec.Usages)
	}
	if csr.Spec.ExpirationSeconds == nil || *csr.Spec.ExpirationSeconds <= 0 || *csr.Spec.ExpirationSeconds > 86400 {
		return nil, id, nil, fmt.Errorf("expirationSeconds must be in (0,86400]")
	}
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(csr.Spec.Username, prefix) {
		return nil, id, nil, fmt.Errorf("requester is not a service account")
	}
	parts := strings.Split(strings.TrimPrefix(csr.Spec.Username, prefix), ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, id, nil, fmt.Errorf("malformed service account username")
	}
	id.namespace, id.serviceAccountName = parts[0], parts[1]
	var err error
	if id.podName, err = singleExtra(csr, "authentication.kubernetes.io/pod-name"); err != nil {
		return nil, id, nil, err
	}
	if id.podUID, err = singleExtra(csr, "authentication.kubernetes.io/pod-uid"); err != nil {
		return nil, id, nil, err
	}
	if id.nodeName, err = singleExtra(csr, "authentication.kubernetes.io/node-name"); err != nil {
		return nil, id, nil, err
	}
	if id.nodeUID, err = singleExtra(csr, "authentication.kubernetes.io/node-uid"); err != nil {
		return nil, id, nil, err
	}
	pod, err := c.kc.CoreV1().Pods(id.namespace).Get(ctx, id.podName, metav1.GetOptions{})
	if err != nil {
		return nil, id, nil, fmt.Errorf("get pod: %w", err)
	}
	if string(pod.UID) != id.podUID || pod.Spec.ServiceAccountName != id.serviceAccountName || pod.Spec.NodeName != id.nodeName {
		return nil, id, nil, fmt.Errorf("authenticated pod identity does not match live pod")
	}
	node, err := c.kc.CoreV1().Nodes().Get(ctx, id.nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, id, nil, fmt.Errorf("get node: %w", err)
	}
	if string(node.UID) != id.nodeUID {
		return nil, id, nil, fmt.Errorf("authenticated node UID does not match live node")
	}
	sa, err := c.kc.CoreV1().ServiceAccounts(id.namespace).Get(ctx, id.serviceAccountName, metav1.GetOptions{})
	if err != nil {
		return nil, id, nil, fmt.Errorf("get service account: %w", err)
	}
	id.serviceAccountUID = string(sa.UID)
	block, rest := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, id, nil, fmt.Errorf("request is not one PEM CSR")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return nil, id, nil, fmt.Errorf("invalid CSR signature")
	}
	if len(request.DNSNames)+len(request.EmailAddresses)+len(request.IPAddresses)+len(request.URIs) != 0 || len(request.Extensions) != 0 {
		return nil, id, nil, fmt.Errorf("CSR must not request extensions or SANs")
	}
	return request, id, pod, nil
}

func (c *Controller) serviceDNSNames(ctx context.Context, pod *corev1.Pod) ([]string, error) {
	services, err := c.kc.CoreV1().Services(pod.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	var names []string
	for _, service := range services.Items {
		if len(service.Spec.Selector) == 0 || !labels.SelectorFromSet(service.Spec.Selector).Matches(labels.Set(pod.Labels)) || service.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		base := service.Name + "." + service.Namespace + ".svc"
		names = append(names, base, base+".cluster.local")
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("pod %s/%s is not selected by a service", pod.Namespace, pod.Name)
	}
	sort.Strings(names)
	return names, nil
}

func singleExtra(csr *certsv1.CertificateSigningRequest, key string) (string, error) {
	values := csr.Spec.Extra[key]
	if len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("%s must have exactly one value", key)
	}
	return values[0], nil
}
func supportedSigner(name string) bool {
	return name == ServiceDNSSignerName || name == PodIdentitySignerName
}
func approved(csr *certsv1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certsv1.CertificateApproved && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func equalUsages(a, b []certsv1.KeyUsage) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]certsv1.KeyUsage(nil), a...), append([]certsv1.KeyUsage(nil), b...)
	sort.Slice(aa, func(i, j int) bool { return aa[i] < aa[j] })
	sort.Slice(bb, func(i, j int) bool { return bb[i] < bb[j] })
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
