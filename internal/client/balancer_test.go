// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"testing"
	"time"
)

func TestBalancerRoundRobin(t *testing.T) {
	b := NewBalancer(BalancingRoundRobin)
	connections := []Connection{
		{Key: "a", Domain: "d1", Resolver: "1.1.1.1", ResolverPort: 53, IsValid: true},
		{Key: "b", Domain: "d2", Resolver: "2.2.2.2", ResolverPort: 53, IsValid: true},
		{Key: "c", Domain: "d3", Resolver: "3.3.3.3", ResolverPort: 53, IsValid: true},
	}

	ptrs := []*Connection{&connections[0], &connections[1], &connections[2]}
	b.SetConnections(ptrs)

	first, ok := b.GetBestConnection()
	if !ok || first.Key != "a" {
		t.Fatalf("unexpected first round robin pick: ok=%v conn=%+v", ok, first)
	}

	second, ok := b.GetBestConnection()
	if !ok || second.Key != "b" {
		t.Fatalf("unexpected second round robin pick: ok=%v conn=%+v", ok, second)
	}
}

func TestBalancerLeastLoss(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss)
	connections := []Connection{
		{Key: "a", Domain: "d1", Resolver: "1.1.1.1", ResolverPort: 53, IsValid: true},
		{Key: "b", Domain: "d2", Resolver: "2.2.2.2", ResolverPort: 53, IsValid: true},
	}

	ptrs := []*Connection{&connections[0], &connections[1]}
	b.SetConnections(ptrs)

	for range 10 {
		b.ReportSend("a")
		b.ReportSend("b")
	}
	for range 9 {
		b.ReportSuccess("a", 2*time.Millisecond)
	}
	for range 3 {
		b.ReportSuccess("b", 1*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok || best.Key != "a" {
		t.Fatalf("unexpected least loss pick: ok=%v conn=%+v", ok, best)
	}
}

func TestBalancerLowestLatency(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency)
	connections := []Connection{
		{Key: "a", Domain: "d1", Resolver: "1.1.1.1", ResolverPort: 53, IsValid: true},
		{Key: "b", Domain: "d2", Resolver: "2.2.2.2", ResolverPort: 53, IsValid: true},
	}

	ptrs := []*Connection{&connections[0], &connections[1]}
	b.SetConnections(ptrs)

	for range 5 {
		b.ReportSuccess("a", 8*time.Millisecond)
		b.ReportSuccess("b", 2*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok || best.Key != "b" {
		t.Fatalf("unexpected lowest latency pick: ok=%v conn=%+v", ok, best)
	}
}

func TestBalancerSetConnectionValidity(t *testing.T) {
	b := NewBalancer(BalancingRoundRobin)
	connections := []Connection{
		{Key: "a", Domain: "d1", Resolver: "1.1.1.1", ResolverPort: 53, IsValid: true},
		{Key: "b", Domain: "d2", Resolver: "2.2.2.2", ResolverPort: 53, IsValid: true},
	}

	ptrs := []*Connection{&connections[0], &connections[1]}
	b.SetConnections(ptrs)

	if !b.SetConnectionValidity("a", false) {
		t.Fatal("SetConnectionValidity should succeed")
	}
	if b.ValidCount() != 1 {
		t.Fatalf("unexpected valid count: got=%d want=%d", b.ValidCount(), 1)
	}

	best, ok := b.GetBestConnection()
	if !ok || best.Key != "b" {
		t.Fatalf("unexpected best connection after disabling a: ok=%v conn=%+v", ok, best)
	}
}
