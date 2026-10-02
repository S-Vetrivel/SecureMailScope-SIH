package capture

import (
	"testing"
	"time"
)

func TestLiveCaptureManager_Lifecycle(t *testing.T) {
	outputDir := t.TempDir()
	
	analyzed := make(chan string, 1)
	emitted := make(chan string, 10)
	
	mgr := NewLiveCaptureManager(
		outputDir,
		func(pcapPath string) {
			analyzed <- pcapPath
		},
		func(eventType string, data interface{}) {
			select {
			case emitted <- eventType:
			default:
			}
		},
	)
	
	if mgr.Stats().Status != "STOPPED" {
		t.Fatalf("expected STOPPED, got %s", mgr.Stats().Status)
	}

	ifaces, err := mgr.GetInterfaces()
	if err != nil {
		t.Fatalf("failed to get interfaces: %v", err)
	}
	
	if len(ifaces) == 0 {
		t.Skip("No interfaces found, skipping capture tests")
	}

	// Just test that the API methods don't panic.
	// Actually capturing needs root on a real interface, so we'll test start on an invalid one.
	err = mgr.Start("invalid-interface-123")
	if err != nil {
		t.Logf("Expected failure on invalid interface: %v", err)
	} else {
		// If it somehow started, check stats and stop
		time.Sleep(100 * time.Millisecond)
		stats := mgr.Stats()
		if stats.Status != "ERROR" && stats.Status != "ACTIVE" {
			t.Errorf("Unexpected status: %s", stats.Status)
		}
		
		_ = mgr.Stop()
	}
}
