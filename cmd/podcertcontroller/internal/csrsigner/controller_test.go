// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package csrsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestValidateAuthenticatedPod(t *testing.T) {
	csr := testCSR(t)
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker-1", UID: "pod-uid", Labels: map[string]string{"app": "worker"}}, Spec: corev1.PodSpec{ServiceAccountName: "worker", NodeName: "node-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", UID: "node-uid"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker", UID: "sa-uid"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "worker"}}},
	)
	c := &Controller{kc: client}
	request, id, pod, err := c.validate(context.Background(), csr)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if request.PublicKey == nil || id.serviceAccountUID != "sa-uid" || pod.Name != "worker-1" {
		t.Fatalf("unexpected validated identity: %#v", id)
	}
	names, err := c.serviceDNSNames(context.Background(), pod)
	if err != nil {
		t.Fatalf("serviceDNSNames: %v", err)
	}
	want := []string{"worker.ax-system.svc", "worker.ax-system.svc.cluster.local"}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("DNS names = %v, want %v", names, want)
	}
}

func TestValidateRejectsSpoofedPodUID(t *testing.T) {
	csr := testCSR(t)
	csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = certsv1.ExtraValue{"other-pod"}
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker-1", UID: "pod-uid"}, Spec: corev1.PodSpec{ServiceAccountName: "worker", NodeName: "node-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", UID: "node-uid"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker", UID: "sa-uid"}},
	)
	c := &Controller{kc: client}
	if _, _, _, err := c.validate(context.Background(), csr); err == nil {
		t.Fatal("validate accepted a spoofed pod UID")
	}
}

func TestValidateRejectsRequestedSAN(t *testing.T) {
	csr := testCSRWithDNSName(t, "attacker.example")
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker-1", UID: "pod-uid"}, Spec: corev1.PodSpec{ServiceAccountName: "worker", NodeName: "node-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", UID: "node-uid"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ax-system", Name: "worker", UID: "sa-uid"}},
	)
	c := &Controller{kc: client}
	if _, _, _, err := c.validate(context.Background(), csr); err == nil {
		t.Fatal("validate accepted a requester-controlled SAN")
	}
}

func testCSR(t *testing.T) *certsv1.CertificateSigningRequest { return testCSRWithDNSName(t, "") }
func testCSRWithDNSName(t *testing.T, dnsName string) *certsv1.CertificateSigningRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{}
	if dnsName != "" {
		template.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	expiration := int32(86400)
	return &certsv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "request-1", Labels: map[string]string{backendLabel: backendValue}},
		Spec: certsv1.CertificateSigningRequestSpec{
			Request:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
			SignerName: PodIdentitySignerName, ExpirationSeconds: &expiration, Usages: requiredUsages,
			Username: "system:serviceaccount:ax-system:worker",
			Extra: map[string]certsv1.ExtraValue{
				"authentication.kubernetes.io/pod-name":  {"worker-1"},
				"authentication.kubernetes.io/pod-uid":   {"pod-uid"},
				"authentication.kubernetes.io/node-name": {"node-1"},
				"authentication.kubernetes.io/node-uid":  {"node-uid"},
			},
		},
	}
}
