package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type hostAccessQMP struct {
	conn     net.Conn
	reader   *bufio.Reader
	sequence int
}

func openHostAccessQMP(store projectStore) (*hostAccessQMP, error) {
	conn, err := net.DialTimeout("unix", store.monitorSockPath(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	q := &hostAccessQMP{conn: conn, reader: bufio.NewReaderSize(conn, 1024*1024)}
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	greeting, err := q.read()
	if err == nil && greeting["QMP"] == nil {
		err = fmt.Errorf("invalid QMP greeting")
	}
	if err == nil {
		_, err = q.command("qmp_capabilities", nil)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return q, nil
}

func (q *hostAccessQMP) read() (map[string]json.RawMessage, error) {
	line, err := q.reader.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("read bounded QMP reply: %w", err)
	}
	var reply map[string]json.RawMessage
	if err := json.Unmarshal(line, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (q *hostAccessQMP) command(command string, args any) (json.RawMessage, error) {
	if err := q.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	q.sequence++
	request := map[string]any{"execute": command, "id": q.sequence}
	if args != nil {
		request["arguments"] = args
	}
	if err := json.NewEncoder(q.conn).Encode(request); err != nil {
		return nil, err
	}
	for {
		reply, err := q.read()
		if err != nil {
			return nil, err
		}
		if reply["event"] != nil {
			continue
		}
		var id int
		if err := json.Unmarshal(reply["id"], &id); err != nil || id != q.sequence {
			return nil, fmt.Errorf("unexpected QMP reply ID")
		}
		if reply["error"] != nil {
			return nil, fmt.Errorf("QMP %s: %s", command, reply["error"])
		}
		if reply["return"] == nil {
			return nil, fmt.Errorf("missing QMP result")
		}
		return reply["return"], nil
	}
}

func (q *hostAccessQMP) hmp(command string) (string, error) {
	data, err := q.command("human-monitor-command", map[string]string{"command-line": command})
	if err != nil {
		return "", err
	}
	var result string
	err = json.Unmarshal(data, &result)
	return strings.TrimSpace(result), err
}

func (q *hostAccessQMP) forwards() (map[int]int, error) {
	body, err := q.hmp("info usernet")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(body, "(net0):") {
		return nil, fmt.Errorf("QEMU user network state is unavailable: %s", body)
	}
	result := map[int]int{}
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "TCP[HOST_FORWARD]" {
			continue
		}
		if len(f) != 8 {
			return nil, fmt.Errorf("unrecognized QEMU forwarding record")
		}
		if f[2] != "127.0.0.1" || f[4] != "10.0.2.15" {
			continue
		}
		host, e1 := strconv.Atoi(f[3])
		vm, e2 := strconv.Atoi(f[5])
		if e1 != nil || e2 != nil {
			return nil, fmt.Errorf("invalid QEMU forwarding ports")
		}
		result[host] = vm
	}
	return result, nil
}

func (q *hostAccessQMP) applyPort(p hostAccessPort, sshPort string, remove bool) error {
	if strconv.Itoa(p.Host) == sshPort {
		return fmt.Errorf("host port %d is the VM management SSH port; stop the VM and retry", p.Host)
	}
	active, err := q.forwards()
	if err != nil {
		return err
	}
	if existing, found := active[p.Host]; found {
		if existing != p.VM {
			return fmt.Errorf("host port %d forwards to project port %d, not the saved port %d", p.Host, existing, p.VM)
		}
		if !remove {
			return nil
		}
	} else if remove {
		return nil
	}
	command := fmt.Sprintf("hostfwd_add net0 tcp:127.0.0.1:%d-:%d", p.Host, p.VM)
	if remove {
		command = fmt.Sprintf("hostfwd_remove net0 tcp:127.0.0.1:%d", p.Host)
	}
	reply, err := q.hmp(command)
	if err != nil {
		return err
	}
	if (!remove && reply != "") || (remove && !strings.Contains(reply, " removed")) {
		return fmt.Errorf("%s", reply)
	}
	active, err = q.forwards()
	if err != nil {
		return err
	}
	_, found := active[p.Host]
	if found == remove || (!remove && active[p.Host] != p.VM) {
		return fmt.Errorf("forwarding change was not confirmed by QEMU")
	}
	return nil
}
