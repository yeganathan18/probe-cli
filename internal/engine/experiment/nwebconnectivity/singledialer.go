package nwebconnectivity

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go"
)

type singleDialerHTTP1 struct {
	sync.Mutex
	conn *net.Conn
}

func (s *singleDialerHTTP1) getConn(network string, addr string) (net.Conn, error) {
	s.Lock()
	defer s.Unlock()
	if s.conn == nil {
		return nil, errors.New("cannot reuse connection")
	}
	c := s.conn
	s.conn = nil
	return *c, nil
}

type singleDialerH2 struct {
	sync.Mutex
	conn *net.Conn
}

func (s *singleDialerH2) getTLSConn(network string, addr string, cfg *tls.Config) (net.Conn, error) {
	s.Lock()
	defer s.Unlock()
	if s.conn == nil {
		return nil, errors.New("cannot reuse connection")
	}
	c := s.conn
	s.conn = nil
	return *c, nil
}

type singleDialerH3 struct {
	sync.Mutex
	qsess *quic.EarlySession
}

func (s *singleDialerH3) getQUICSess(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
	s.Lock()
	defer s.Unlock()
	if s.qsess == nil {
		return nil, errors.New("cannot reuse session")
	}
	qs := s.qsess
	s.qsess = nil
	return *qs, nil
}
