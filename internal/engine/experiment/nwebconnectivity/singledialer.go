package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go"
)

type SingleDialerHTTP1 struct {
	sync.Mutex
	conn *net.Conn
}

func (s *SingleDialerHTTP1) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	s.Lock()
	defer s.Unlock()
	if s.conn == nil {
		return nil, ErrNoConnReuse{location: addr}
	}
	c := s.conn
	s.conn = nil
	return *c, nil
}

type SingleDialerH2 struct {
	sync.Mutex
	conn *net.Conn
}

func (s *SingleDialerH2) DialTLS(network string, addr string, cfg *tls.Config) (net.Conn, error) {
	s.Lock()
	defer s.Unlock()
	if s.conn == nil {
		return nil, ErrNoConnReuse{location: addr}
	}
	c := s.conn
	s.conn = nil
	return *c, nil
}

type SingleDialerH3 struct {
	sync.Mutex
	qsess *quic.EarlySession
}

func (s *SingleDialerH3) Dial(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
	s.Lock()
	defer s.Unlock()
	if s.qsess == nil {
		return nil, errors.New("cannot reuse session")
	}
	qs := s.qsess
	s.qsess = nil
	return *qs, nil
}
