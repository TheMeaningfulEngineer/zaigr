package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The base image zaigr builds creates the guest account "user" with these IDs.
const (
	factoryGuestUID = 1000
	factoryGuestGID = 1001
)

// guestIdentityRecordName is the file, next to an image, that remembers the
// guest user's IDs when the guest reported other IDs than the factory ones.
const guestIdentityRecordName = ".guest-identity.json"

type guestIdentityRecord struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// errGuestIdentityChanged reports that the running guest's user has other IDs
// than the ones its file sharing was started with. The right IDs are recorded
// by then, so starting the VM again uses them.
var errGuestIdentityChanged = errors.New("the guest user's IDs differ from the ones file sharing was started with")

// readGuestUserIDs asks the running guest for the user account's IDs.
func readGuestUserIDs(endpoint vmControlEndpoint) (int, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := runVMGuestCommand(ctx, endpoint, "root", `awk -F: '$1 == "user" { print $3, $4; exit }' /etc/passwd`, nil, &out, io.Discard); err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(out.String())
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("guest /etc/passwd has no user account")
	}
	uid, uidErr := strconv.Atoi(fields[0])
	gid, gidErr := strconv.Atoi(fields[1])
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, fmt.Errorf("guest user has invalid UID/GID")
	}
	return uid, gid, nil
}

// rememberGuestIdentity records the IDs the guest reported for imagePath.
func rememberGuestIdentity(imagePath string, uid, gid int) error {
	body, err := json.Marshal(guestIdentityRecord{UID: uid, GID: gid})
	if err != nil {
		return err
	}
	return writeFileAtomically(filepath.Join(filepath.Dir(imagePath), guestIdentityRecordName), body, 0600)
}

// expectedGuestIdentity returns the IDs to start file sharing with: the ones
// the guest last reported for imagePath, or else the factory ones. File
// sharing starts before the guest does, so this can only be an expectation;
// confirmGuestIdentity checks it once the guest runs.
func expectedGuestIdentity(imagePath string) (int, int) {
	body, err := os.ReadFile(filepath.Join(filepath.Dir(imagePath), guestIdentityRecordName))
	if err != nil {
		return factoryGuestUID, factoryGuestGID
	}
	var record guestIdentityRecord
	if err := json.Unmarshal(body, &record); err != nil || record.UID <= 0 || record.GID <= 0 {
		return factoryGuestUID, factoryGuestGID
	}
	return record.UID, record.GID
}

// confirmGuestIdentity asks the freshly booted guest for its user's IDs. When
// they differ from the ones file sharing was started with, it records them and
// returns errGuestIdentityChanged; the caller starts the VM again.
func confirmGuestIdentity(endpoint vmControlEndpoint, imagePath string, startedUID, startedGID int) error {
	uid, gid, err := readGuestUserIDs(endpoint)
	if err != nil {
		return fmt.Errorf("read the guest user's IDs: %w", err)
	}
	if uid == startedUID && gid == startedGID {
		return nil
	}
	logInfo("guest user IDs differ from the expected ones", "image", imagePath, "expected_uid", startedUID, "expected_gid", startedGID, "uid", uid, "gid", gid)
	if imagePath == "" {
		return fmt.Errorf("guest user has UID %d and GID %d, but the booted image is unknown", uid, gid)
	}
	if err := rememberGuestIdentity(imagePath, uid, gid); err != nil {
		return fmt.Errorf("record the guest user's IDs: %w", err)
	}
	return errGuestIdentityChanged
}
