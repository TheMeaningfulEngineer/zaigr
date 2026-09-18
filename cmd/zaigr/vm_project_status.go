package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type projectStatusImage struct {
	Display        string
	WarningDisplay string
	ExpectedBase   string
	Missing        bool
}

type projectStatusRender struct {
	ProjectPath         string
	StorePath           string
	CPU                 string
	RAM                 string
	Disk                string
	ShowDisk            bool
	Image               projectStatusImage
	ImageMismatch       projectImageMismatchReport
	DirtyImage          projectImageDirtyInfo
	HasDirtyImage       bool
	Running             *runningVMInfo
	Stale               bool
	Preset              storedPresetSelection
	HasPreset           bool
	Applied             []appliedSetup
	AppliedUnavailable  bool
	SetupFailedOnce     bool
	ActiveShellCount    *int
	FirewallEntries     []string
	FirewallUnavailable bool
	ShowFirewall        bool
}

func printProjectStatus(render projectStatusRender) {
	if render.ProjectPath != "" {
		fmt.Printf("project: %s\n", render.ProjectPath)
	}
	fmt.Printf("store-path: %s\n", render.StorePath)
	fmt.Printf("project-image: %s\n", render.Image.Display)
	if render.HasDirtyImage {
		fmt.Printf("project-image-dirty: %s\n", projectImageDirtyStatus(render.DirtyImage))
	}

	fmt.Printf("vm:\n")
	switch {
	case render.Stale:
		fmt.Printf("  status: stale session marker found; not running\n")
	case render.Running != nil:
		fmt.Printf("  status: running on port %s\n", render.Running.Port)
	default:
		fmt.Printf("  status: not running\n")
	}

	if render.ShowDisk {
		fmt.Printf("  config: cpu=%s, ram=%sMB, disk=%s\n", coalesce(render.CPU, "unknown"), coalesce(render.RAM, "unknown"), render.Disk)
	} else {
		fmt.Printf("  config: cpu=%s, ram=%sMB\n", coalesce(render.CPU, "unknown"), coalesce(render.RAM, "unknown"))
	}

	if render.Running != nil && render.Running.ImagePath != "" {
		fmt.Printf("  image booted: %s\n", filepath.Base(render.Running.ImagePath))
	}
	if render.Running != nil && render.HasPreset {
		fmt.Printf("  preset: %s %s\n", render.Preset.Name, statusVersionLabel(render.Preset.Version, render.Preset.Time))
	}
	if render.ActiveShellCount != nil {
		fmt.Printf("  active-shells: %d\n", *render.ActiveShellCount)
	}

	printProjectStatusImageWarning(render.ImageMismatch)

	fmt.Printf("setups:\n")
	if render.AppliedUnavailable {
		fmt.Println("  applied: unavailable")
	} else {
		fmt.Printf("  applied (%d):\n", len(render.Applied))
		if len(render.Applied) == 0 {
			fmt.Println("    (none)")
		} else {
			for _, record := range render.Applied {
				fmt.Printf("    %s  %s\n", displaySetupName(record.Name, record.ProjectLocal), record.Version)
			}
		}
	}
	if render.SetupFailedOnce {
		fmt.Println("This VM had a failed setup once.")
	}

	if render.ShowFirewall {
		if render.FirewallUnavailable {
			fmt.Println("firewall entries: unavailable")
			return
		}
		fmt.Printf("firewall entries (%d):\n", len(render.FirewallEntries))
		if len(render.FirewallEntries) == 0 {
			fmt.Printf("  (none)\n")
			return
		}
		for _, entry := range render.FirewallEntries {
			fmt.Printf("  %s\n", entry)
		}
	}
}

func projectImageDirtyStatus(info projectImageDirtyInfo) string {
	details := make([]string, 0, 2)
	if info.Reason != "" {
		details = append(details, info.Reason)
	}
	if info.Time != "" {
		details = append(details, info.Time)
	}
	if len(details) == 0 {
		return "yes"
	}
	return fmt.Sprintf("yes (%s)", strings.Join(details, ", "))
}

func projectStatusImageFromPaths(committedImagePath string, committedImageMissing bool, fallbackImagePath string, fallbackErr error) projectStatusImage {
	if committedImageMissing {
		base := filepath.Base(committedImagePath)
		return projectStatusImage{
			Display:        fmt.Sprintf("(missing; expected %s)", base),
			WarningDisplay: fmt.Sprintf("missing; expected %s", base),
			ExpectedBase:   base,
			Missing:        true,
		}
	}
	if committedImagePath != "" {
		base := filepath.Base(committedImagePath)
		return projectStatusImage{
			Display:        base,
			WarningDisplay: base,
			ExpectedBase:   base,
		}
	}
	if fallbackErr == nil {
		base := filepath.Base(fallbackImagePath)
		if _, err := os.Stat(fallbackImagePath); err == nil {
			return projectStatusImage{
				Display:        base,
				WarningDisplay: base,
				ExpectedBase:   base,
			}
		}
		return projectStatusImage{
			Display:        "(not present)",
			WarningDisplay: fmt.Sprintf("not present; expected %s", base),
			ExpectedBase:   base,
			Missing:        true,
		}
	}
	return projectStatusImage{
		Display:        "(not available)",
		WarningDisplay: "not available",
		Missing:        true,
	}
}

func printProjectStatusImageWarning(mismatch projectImageMismatchReport) {
	if mismatch.hasBlockingIssue() {
		printProjectImageMismatchWarnings(os.Stdout, mismatch)
	}
}

func statusVersionLabel(hash, timestamp string) string {
	label := storedResourceVersionLabel(hash, timestamp)
	if label == "" {
		return ""
	}
	return "v." + label
}
