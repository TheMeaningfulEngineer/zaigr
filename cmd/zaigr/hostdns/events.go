package hostdns

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

const maxRetainedEvents = 4096

// Event reports a DNS question observed by the host broker. It describes DNS
// authorization and answer data only; it does not claim that the guest opened
// a transport connection to any returned address.
type Event struct {
	Sequence   uint64       `json:"sequence"`
	Time       time.Time    `json:"time"`
	Name       string       `json:"name"`
	QueryType  string       `json:"query_type,omitempty"`
	Decision   string       `json:"decision"`
	RCode      int          `json:"rcode"`
	Addresses  []netip.Addr `json:"addresses,omitempty"`
	Generation uint64       `json:"generation"`
	Gap        bool         `json:"gap,omitempty"`
}

var errEventsClosed = errors.New("host DNS event stream is closed")

// EventSequence returns the latest observed DNS event number for a launch.
func (s *Server) EventSequence() uint64 {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	return s.eventSequence
}

// NextEvent waits for the next host-observed DNS event after sequence. If the
// bounded history wrapped, it first returns Gap=true so callers can report
// that some events were missed, then continue from that marker's sequence.
func (s *Server) NextEvent(ctx context.Context, sequence uint64) (Event, error) {
	for {
		s.eventMu.Lock()
		if len(s.events) > 0 {
			first := s.events[0].Sequence
			if sequence+1 < first {
				gap := Event{Sequence: first - 1, Time: time.Now().UTC(), Decision: "history-gap", Gap: true}
				s.eventMu.Unlock()
				return gap, nil
			}
			for _, event := range s.events {
				if event.Sequence > sequence {
					event.Addresses = append([]netip.Addr(nil), event.Addresses...)
					s.eventMu.Unlock()
					return event, nil
				}
			}
		}
		if s.ctx.Err() != nil {
			s.eventMu.Unlock()
			return Event{}, errEventsClosed
		}
		changed := s.eventChanged
		s.eventMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-s.ctx.Done():
			return Event{}, errEventsClosed
		}
	}
}

func (s *Server) recordEvent(name, queryType, decision string, rcode int, addresses []netip.Addr, generation uint64) {
	s.eventMu.Lock()
	s.eventSequence++
	event := Event{
		Sequence: s.eventSequence, Time: time.Now().UTC(), Name: name, QueryType: queryType,
		Decision: decision, RCode: rcode, Addresses: append([]netip.Addr(nil), addresses...),
		Generation: generation,
	}
	if len(s.events) == maxRetainedEvents {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = event
	} else {
		s.events = append(s.events, event)
	}
	close(s.eventChanged)
	s.eventChanged = make(chan struct{})
	s.eventMu.Unlock()
}
