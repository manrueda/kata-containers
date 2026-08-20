// Copyright (c) 2026 Kata Containers Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

package katamonitor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dto "github.com/prometheus/client_model/go"
)

func TestSyncSandboxFSPaths(t *testing.T) {
	paths := []string{t.TempDir(), t.TempDir()}
	sandboxIDs := []string{"go-sandbox", "runtime-rs-sandbox"}
	for i, path := range paths {
		require.NoError(t, os.Mkdir(filepath.Join(path, sandboxIDs[i]), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(path, "not-a-sandbox"), nil, 0o644))
	}

	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	km := &KataMonitor{
		sandboxCache: &sandboxCache{
			Mutex:     &sync.Mutex{},
			sandboxes: make(map[string]sandboxCRIMetadata),
		},
	}
	watched := make(map[string]struct{})
	var discovered []string
	for _, path := range paths {
		added, err := km.syncSandboxFSPath(watcher, path, watched)
		require.NoError(t, err)
		discovered = append(discovered, added...)
	}

	assert.ElementsMatch(t, sandboxIDs, discovered)
	assert.Len(t, watched, 2)
	assert.ElementsMatch(t, sandboxIDs, km.sandboxCache.getSandboxList())
}

func TestMarkWatchedPathsUnavailable(t *testing.T) {
	paths := []string{t.TempDir(), t.TempDir()}
	watcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)
	defer watcher.Close()

	state := newSandboxFSPathState(paths)
	km := &KataMonitor{sandboxFSPathState: state}
	watched := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		require.NoError(t, watcher.Add(path))
		watched[path] = struct{}{}
		state.set(path, true)
	}

	km.markWatchedPathsUnavailable(watcher, watched)

	assert.Empty(t, watched)
	for path, available := range state.snapshot() {
		assert.False(t, available, path)
	}
}

func TestPruneMissingSandboxes(t *testing.T) {
	paths := []string{t.TempDir(), t.TempDir()}
	require.NoError(t, os.Mkdir(filepath.Join(paths[1], "live"), 0o755))

	cache := &sandboxCache{
		Mutex:     &sync.Mutex{},
		sandboxes: make(map[string]sandboxCRIMetadata),
	}
	cache.putIfNotExists("live", sandboxCRIMetadata{})
	cache.putIfNotExists("stale", sandboxCRIMetadata{})
	km := &KataMonitor{
		sandboxFSPaths: paths,
		sandboxCache:   cache,
	}

	pending := km.pruneMissingSandboxes([]string{"live", "stale"})

	assert.Equal(t, []string{"live"}, pending)
	assert.Equal(t, []string{"live"}, cache.getSandboxList())
}

func TestSandboxFSPathReadiness(t *testing.T) {
	paths := getSandboxFSPaths()
	require.Len(t, paths, 2)

	state := newSandboxFSPathState(paths)
	km := &KataMonitor{
		sandboxFSPaths:     paths,
		sandboxFSPathState: state,
	}

	assertReadiness := func(expectedStatus int) string {
		recorder := httptest.NewRecorder()
		km.Readiness(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		assert.Equal(t, expectedStatus, recorder.Code)
		return recorder.Body.String()
	}
	metricValue := func(path string) float64 {
		metric := &dto.Metric{}
		require.NoError(t, sandboxFSPathAvailable.WithLabelValues(path).Write(metric))
		return metric.GetGauge().GetValue()
	}

	body := assertReadiness(http.StatusServiceUnavailable)
	assert.Contains(t, body, paths[0]+" unavailable")
	assert.Contains(t, body, paths[1]+" unavailable")
	assert.Equal(t, float64(0), metricValue(paths[0]))
	assert.Equal(t, float64(0), metricValue(paths[1]))

	state.set(paths[0], true)
	body = assertReadiness(http.StatusOK)
	assert.Contains(t, body, paths[0]+" available")
	assert.Contains(t, body, paths[1]+" unavailable")
	assert.Equal(t, float64(1), metricValue(paths[0]))

	state.set(paths[0], false)
	state.set(paths[1], true)
	body = assertReadiness(http.StatusOK)
	assert.Contains(t, body, paths[0]+" unavailable")
	assert.Contains(t, body, paths[1]+" available")
	assert.Equal(t, float64(1), metricValue(paths[1]))

	state.set(paths[1], false)
	assertReadiness(http.StatusServiceUnavailable)
}
