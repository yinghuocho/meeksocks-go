package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/yinghuocho/gosocks"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	headerSessionID    = "X-Session-Id"
	headerMsgType      = "X-MsgType"
	headerUDPPkts      = "X-UDP-Pkts"
	headerForwardedFor = "X-Forwarded-For"
	headerRealIP       = "X-Real-IP"

	// Always return 200 ok, use X-Error to tell client whether request
	// succeeced. This is arguly easier for client to differiate meekserver
	// error with network error.
	headerError = "X-Error"

	msgTypeData = "DATA"
	msgTypeTerm = "TERM"

	minSessionIDLength   = 32
	maxPayloadLength     = 0x10000
	socksTimeout         = time.Minute
	httpTimeout          = 20 * time.Second
	maxSessionStaleness  = 120 * time.Second
	socksReadBufSize     = 0x100000
	turnaroundTimeout    = 50 * time.Millisecond
	maxTurnaroundTimeout = 200 * time.Millisecond
)

type configOptions struct {
	serverAddr string
	socksAddr  string
}

var config configOptions

type session struct {
	remoteAddr string
	tc         *gosocks.SocksConn
	uc         *net.UDPConn
	lastSeen   time.Time
}

func (session *session) touch() {
	session.lastSeen = time.Now()
}

func (session *session) isExpired() bool {
	return time.Since(session.lastSeen) > maxSessionStaleness
}

type server struct {
	sessionMap map[string]*session
	lock       sync.Mutex

	socksAddr string
}

func newServer(socksAddr string) *server {
	return &server{socksAddr: socksAddr, sessionMap: make(map[string]*session)}
}

func httpBadRequest(w http.ResponseWriter) {
	http.Error(w, "Bad request.\n", http.StatusBadRequest)
}

func httpInternalServerError(w http.ResponseWriter) {
	http.Error(w, "Internal server error.\n", http.StatusInternalServerError)
}

func remoteAddr(req *http.Request) (addr string) {
	addr = req.Header.Get(headerRealIP)
	if addr != "" {
		return
	}

	addr = req.Header.Get(headerForwardedFor)
	if addr != "" {
		return
	}

	addr = req.RemoteAddr
	return
}

func meekResponse(w http.ResponseWriter, errMsg string, data []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	if errMsg != "" {
		w.Header().Set(headerError, errMsg)
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (srv *server) getSession(sessionID string, req *http.Request) *session {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	s := srv.sessionMap[sessionID]
	if s == nil {
		s = &session{remoteAddr: remoteAddr(req)}
		srv.sessionMap[sessionID] = s
	}
	s.touch()
	return s
}

func (srv *server) closeSession(sessionID string) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	// log.Printf("closing session %q", sessionId)
	s, ok := srv.sessionMap[sessionID]
	if ok {
		if s.tc != nil {
			s.tc.Close()
		}
		if s.uc != nil {
			s.uc.Close()
		}
		delete(srv.sessionMap, sessionID)
	}
}

// expireSessions purges stale sessions. It is a endless loop quit with main thread
func (srv *server) expireSessions() {
	for {
		time.Sleep(maxSessionStaleness / 2)
		srv.lock.Lock()
		for sID, s := range srv.sessionMap {
			if s.isExpired() {
				if s.tc != nil {
					s.tc.Close()
				}
				if s.uc != nil {
					s.uc.Close()
				}
				delete(srv.sessionMap, sID)
			}
		}
		srv.lock.Unlock()
	}
}

func (srv *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		srv.get(w, req)
	case "POST":
		srv.post(w, req)
	default:
		httpBadRequest(w)
	}
}

func (srv *server) get(w http.ResponseWriter, req *http.Request) {
	if path.Clean(req.URL.Path) != "/" {
		http.NotFound(w, req)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Go Firefly.\n"))
}

func (srv *server) post(w http.ResponseWriter, req *http.Request) {
	sessionID := req.Header.Get(headerSessionID)
	if len(sessionID) < minSessionIDLength {
		meekResponse(w, "Bad request", []byte(""))
		return
	}

	mtype := req.Header.Get(headerMsgType)
	if mtype == msgTypeTerm {
		log.Printf("terminate by client")
		srv.closeSession(sessionID)
		meekResponse(w, "", []byte(""))
		return
	}

	session := srv.getSession(sessionID, req)
	err := srv.transact(session, w, req)
	if err != nil {
		log.Printf("transact error: %s", err)
		srv.closeSession(sessionID)
		return
	}
}

func (srv *server) transact(s *session, w http.ResponseWriter, req *http.Request) error {
	if s.tc == nil {
		return srv.transactBegin(s, w, req)
	}

	udpHeader := req.Header.Get(headerUDPPkts)
	if udpHeader != "" || s.uc != nil {
		return srv.transactUDP(s, w, req)
	}
	return srv.transactTCP(s, w, req)
}

func (srv *server) transactBegin(s *session, w http.ResponseWriter, req *http.Request) error {
	body := http.MaxBytesReader(w, req.Body, maxPayloadLength+1)
	dialer := &gosocks.SocksDialer{
		Timeout: socksTimeout,
		Auth:    &gosocks.AnonymousClientAuthenticator{},
	}
	conn, err := dialer.Dial(srv.socksAddr)
	if err != nil {
		meekResponse(w, "Internal server error", []byte(""))
		return err
	}
	// I am sure that this is a TCPConn
	conn.Conn.(*net.TCPConn).SetReadBuffer(socksReadBufSize)
	s.tc = conn

	socksReq, err := gosocks.ReadSocksRequest(body)
	if socksReq.Cmd == gosocks.SocksCmdUDPAssociate {
		// if cmd is UDP_ASSOCIATE, no restriction on sending address
		socksReq.HostType = gosocks.SocksIPv4Host
		socksReq.DstHost = "0.0.0.0"
		socksReq.DstPort = 0
	}

	if err != nil {
		meekResponse(w, "Bad request", []byte(""))
		return fmt.Errorf("invalid socks request: %s", err)
	}
	socksReply, err := gosocks.ClientRequest(s.tc, socksReq)
	if err != nil || socksReply.Rep != gosocks.SocksSucceeded {
		meekResponse(w, "Internal server error", []byte(""))
		return err
	}

	log.Printf("[%s] cmd 0x%02x with DstAddr: %s:%d", s.remoteAddr, socksReq.Cmd, socksReq.DstHost, socksReq.DstPort)
	if socksReq.Cmd == gosocks.SocksCmdUDPAssociate {
		uc, err := net.Dial("udp", gosocks.SockAddrString(socksReply.BndHost, socksReply.BndPort))
		if err != nil {
			meekResponse(w, "Internal server error", []byte(""))
			return err
		}
		s.uc = uc.(*net.UDPConn)
		s.uc.SetReadBuffer(socksReadBufSize)
	}

	gosocks.WriteSocksReply(w, socksReply)
	return nil
}

func (srv *server) transactTCP(s *session, w http.ResponseWriter, req *http.Request) error {
	body := http.MaxBytesReader(w, req.Body, maxPayloadLength+1)
	_, err := io.Copy(s.tc, body)
	if err != nil {
		meekResponse(w, "Internal server error", []byte(""))
		return err
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	total := 0
	start := time.Now()
	for {
		var buf [maxPayloadLength]byte
		s.tc.SetReadDeadline(time.Now().Add(turnaroundTimeout))
		n, err := s.tc.Read(buf[:])
		if err != nil {
			e, ok := err.(net.Error)
			w.Write([]byte(""))
			if !ok || !e.Timeout() {
				return err
			}
			return nil
		}
		_, err = w.Write(buf[:n])
		total += n
		if err != nil {
			return err
		}
		if time.Now().After(start.Add(maxTurnaroundTimeout)) {
			return nil
		}
		if total > socksReadBufSize {
			return nil
		}
	}
}

func (srv *server) transactUDP(s *session, w http.ResponseWriter, req *http.Request) (err error) {
	body := http.MaxBytesReader(w, req.Body, maxPayloadLength+1)
	udpHeader := req.Header.Get(headerUDPPkts)
	// log.Printf("c -> s : %s", s)
	if udpHeader != "" {
		for _, v := range strings.Split(udpHeader, ",") {
			n, e := strconv.Atoi(v)
			if e != nil {
				err = fmt.Errorf("error to split UDP packets: %s", err)
				return
			}
			p := make([]byte, n)
			_, e = io.ReadFull(body, p)
			if e != nil {
				err = fmt.Errorf("error to split UDP packets: %s", e)
				return
			}
			s.uc.Write(p)
		}
	}

	start := time.Now()
	var data [][]byte
	var pkts []string
	total := 0
loop:
	for {
		var buf [maxPayloadLength]byte
		s.uc.SetReadDeadline(time.Now().Add(turnaroundTimeout))
		n, e := s.uc.Read(buf[:])
		if e != nil {
			e, ok := e.(net.Error)
			if !ok || !e.Timeout() {
				err = e
			}
			break loop
		}
		data = append(data, buf[:n])
		pkts = append(pkts, strconv.Itoa(n))
		total += n
		if total > socksReadBufSize {
			break loop
		}
		if time.Now().After(start.Add(maxTurnaroundTimeout)) {
			return
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(total))
	if total > 0 {
		w.Header().Set(headerUDPPkts, strings.Join(pkts, ","))
	}
	// log.Printf("s -> c : %s", strings.Join(pkts, ","))
	w.Write(bytes.Join(data, []byte("")))
	return
}

func startMeekServer(httpAddr, socksAddr string, quit chan bool) (ln net.Listener, err error) {
	ln, err = net.Listen("tcp", httpAddr)
	if err != nil {
		log.Printf("error in listen %s:%s", httpAddr, err)
		return
	}

	srv := newServer(socksAddr)
	hsrv := &http.Server{
		Handler:      srv,
		ReadTimeout:  httpTimeout,
		WriteTimeout: httpTimeout,
	}
	go srv.expireSessions()
	go func() {
		err := hsrv.Serve(ln)
		if err != nil {
			log.Printf("error in serve HTTP: %s", err)
		}
		// notify other threads to quit
		close(quit)
	}()
	return
}

func startSocksServer(addr string, quit chan bool) (ln net.Listener, err error) {
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		log.Printf("error in listen %s:%s", addr, err)
		return
	}

	ssrv := gosocks.NewBasicServer(addr, socksTimeout)
	go func() {
		err := ssrv.Serve(ln)
		if err != nil {
			log.Printf("error in serve Socks: %s", err)
		}
		// notify other threads to quit
		close(quit)
	}()
	return
}

func rotateLog(filename string, pre *os.File) *os.File {
	if filename == "" {
		return pre
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("error opening log file: %s", err)
		return pre
	}
	log.SetOutput(f)
	if pre != nil {
		pre.Close()
	}
	return f
}

func savePid(filename string) {
	if filename == "" {
		return
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	defer f.Close()
	if err != nil {
		log.Printf("error opening pid file: %s", err)
		return
	}
	f.Write([]byte(strconv.Itoa(os.Getpid())))
}

func main() {
	var logFilename string
	var pidFilename string
	flag.StringVar(&config.serverAddr, "http-addr", ":8000", "HTTP server address")
	flag.StringVar(&config.socksAddr, "socks-addr", "127.0.0.1:10800", "SOCKS server address")
	flag.StringVar(&logFilename, "logfile", "", "file to record log")
	flag.StringVar(&pidFilename, "pidfile", "", "file to save process id")
	flag.Parse()

	logFile := rotateLog(logFilename, nil)

	quit := make(chan bool)
	httpLn, err := startMeekServer(config.serverAddr, config.socksAddr, quit)
	if err != nil {
		log.Fatalf("error to start http server: %s", err)
	}
	log.Printf("http server listens on %s", config.serverAddr)

	socksLn, err := startSocksServer(config.socksAddr, quit)
	if err != nil {
		log.Fatalf("error to start socks server: %s", err)
	}
	log.Printf("socks server listens on %s", config.socksAddr)

	savePid(pidFilename)

	defer httpLn.Close()
	defer socksLn.Close()

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGHUP)

	running := true
	for running == true {
		select {
		case <-quit:
			log.Printf("quit signal received, probably something wrong")
			running = false
		case <-s:
			logFile = rotateLog(logFilename, logFile)
		}
	}
	log.Printf("done")
}
