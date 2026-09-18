package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type projectImageMismatchReport struct {
	MissingImage        bool
	ExpectedImage       string
	OutdatedBaseImage   bool
	RecordedBaseVersion string
	RequiredBaseVersion string
}

func (report projectImageMismatchReport) hasBlockingIssue() bool {
	return report.MissingImage || report.OutdatedBaseImage
}

func resolveProjectImageForCommand() error {
	store := currentProjectStore()
	if err := store.requireCurrentImageFormat("project image access"); err != nil {
		return err
	}
	report, err := collectProjectImageMismatchesForStore(store)
	if err != nil {
		return err
	}
	if report.MissingImage {
		return fmt.Errorf("project image cannot be found: %s", report.ExpectedImage)
	}
	if report.OutdatedBaseImage {
		return fmt.Errorf(
			"project base image is outdated\n"+
				"  project base image: %s\n"+
				"  required base image: %s\n"+
				"Stop the project VM if it is running, then run `zaigr project rebuild` to recreate it from the current base image and reapply its setups",
			report.RecordedBaseVersion,
			report.RequiredBaseVersion,
		)
	}
	return nil
}

func collectProjectImageMismatchesForStore(store projectStore) (projectImageMismatchReport, error) {
	if err := store.requireCurrentImageFormat("project inspection"); err != nil {
		return projectImageMismatchReport{}, err
	}
	report := projectImageMismatchReport{RequiredBaseVersion: baseRootfsVersion()}
	recordedBase, recorded, err := store.readBaseImageVersion()
	if err != nil {
		return projectImageMismatchReport{}, err
	}
	if recorded {
		report.RecordedBaseVersion = recordedBase
		report.OutdatedBaseImage = recordedBase != "" && report.RequiredBaseVersion != "" && recordedBase != report.RequiredBaseVersion
	}
	path := store.authoritativeImagePath()
	if _, err := os.Stat(path); err == nil {
		return report, nil
	} else if !os.IsNotExist(err) {
		return projectImageMismatchReport{}, err
	}
	report.MissingImage = true
	report.ExpectedImage = filepath.Base(path)
	return report, nil
}

func printProjectImageMismatchWarnings(w io.Writer, report projectImageMismatchReport) {
	if report.MissingImage {
		_, _ = fmt.Fprintln(w, "warning: the project image cannot be found.")
		if report.ExpectedImage != "" {
			_, _ = fmt.Fprintf(w, "  expected image: %s\n", report.ExpectedImage)
		}
	}
	if report.OutdatedBaseImage {
		_, _ = fmt.Fprintln(w, "warning: the project base image is outdated.")
		_, _ = fmt.Fprintf(w, "  project base image: %s\n", report.RecordedBaseVersion)
		_, _ = fmt.Fprintf(w, "  required base image: %s\n", report.RequiredBaseVersion)
	}
	if report.hasBlockingIssue() {
		_, _ = fmt.Fprintln(w, "Stop the project VM if it is running, then run `zaigr project rebuild` to recreate it from the current base image and reapply its setups.")
	}
}
