package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type shellSession struct {
	PID        int
	StartTime  string
	User       string
	Port       string
	MarkerPath string
}

func (store projectStore) shellSessionsDir() string {
	return filepath.Join(store.runtimeDir(), "shells")
}

func writeShellSessionMarker(store projectStore, pid int, root bool, port string) (func(), error) {
	startTime, err := processStartTime(pid)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(store.shellSessionsDir(), 0755); err != nil {
		return nil, fmt.Errorf("create shell session dir: %w", err)
	}
	user := "user"
	if root {
		user = "root"
	}
	markerPath := filepath.Join(store.shellSessionsDir(), strconv.Itoa(pid))
	content := fmt.Sprintf("pid=%d\nstarttime=%s\nuser=%s\nport=%s\n", pid, startTime, user, port)
	if err := os.WriteFile(markerPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("write shell session marker: %w", err)
	}
	return func() {
		_ = os.Remove(markerPath)
	}, nil
}

func (store projectStore) activeShellSessions() ([]shellSession, error) {
	return store.readActiveShellSessions(true)
}

func (store projectStore) readActiveShellSessions(cleanStale bool) ([]shellSession, error) {
	entries, err := os.ReadDir(store.shellSessionsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read shell session dir: %w", err)
	}

	sessions := make([]shellSession, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		markerPath := filepath.Join(store.shellSessionsDir(), entry.Name())
		session, err := readShellSessionMarker(markerPath)
		if err != nil {
			if cleanStale {
				_ = os.Remove(markerPath)
			}
			continue
		}
		startTime, err := processStartTime(session.PID)
		if err != nil || startTime != session.StartTime {
			if cleanStale {
				_ = os.Remove(markerPath)
			}
			continue
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func requireNoActiveProjectShells(store projectStore, operation string) error {
	sessions, err := store.activeShellSessions()
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		return nil
	}
	return fmt.Errorf("cannot run %s: %d project shell session(s) are running in other terminals", operation, len(sessions))
}

func readShellSessionMarker(path string) (shellSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return shellSession{}, err
	}
	session := shellSession{MarkerPath: path}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "pid":
			pid, err := strconv.Atoi(value)
			if err != nil {
				return shellSession{}, err
			}
			session.PID = pid
		case "starttime":
			session.StartTime = value
		case "user":
			session.User = value
		case "port":
			session.Port = value
		}
	}
	if session.PID == 0 || session.StartTime == "" {
		return shellSession{}, fmt.Errorf("incomplete shell session marker: %s", path)
	}
	return session, nil
}

func processStartTime(pid int) (string, error) {
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		return "", fmt.Errorf("read process stat for %d: %w", pid, err)
	}
	stat := string(data)
	endCommand := strings.LastIndex(stat, ") ")
	if endCommand < 0 {
		return "", fmt.Errorf("parse process stat for %d", pid)
	}
	fields := strings.Fields(stat[endCommand+2:])
	if len(fields) <= 19 {
		return "", fmt.Errorf("parse process start time for %d", pid)
	}
	return fields[19], nil
}
