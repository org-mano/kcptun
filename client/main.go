package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/kcptun/generic"
	"github.com/xtaci/smux"
	"github.com/xtaci/kcptun/go-ping"
)

const (
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	// maximum supported smux version
	maxSmuxVer = 2
	// stream copy buffer size
	bufSize = 4096
)

// VERSION is injected by buildflags
var VERSION = "SELFBUILD"

// handleClient aggregates connection p1 on mux with 'writeLock'
func handleClient(session *smux.Session, p1 net.Conn, quiet bool) {
	logln := func(v ...interface{}) {
		if !quiet {
			log.Println(v...)
		}
	}
	defer p1.Close()
	p2, err := session.OpenStream()
	if err != nil {
		logln(err)
		return
	}

	defer p2.Close()

	logln("stream opened", "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))
	defer logln("stream closed", "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))

	// start tunnel & wait for tunnel termination
	streamCopy := func(dst io.Writer, src io.ReadCloser) {
		if _, err := generic.Copy(dst, src); err != nil {
			// report protocol error
			if err == smux.ErrInvalidProtocol {
				log.Println("smux", err, "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))
			}
		}
		p1.Close()
		p2.Close()
	}

	go streamCopy(p1, p2)
	streamCopy(p2, p1)
}

func handleClientBypass(remoteAddr string, local io.ReadWriteCloser, quiet bool) {
	if !quiet {
		log.Println("stream opened")
		defer log.Println("stream closed")
	}

	createConnBypass := func() (net.Conn, error) {
		kcpconn, err := net.Dial("tcp", remoteAddr)
		log.Println("remoteAddr:", remoteAddr)
		if err != nil {
			return nil, errors.Wrap(err, "createConn()")
		}

		log.Println("connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
		return kcpconn, nil
	}
	remote, err := createConnBypass()
	if err != nil {
		log.Println(err)
		return
	}

	defer local.Close()
	defer remote.Close()

	// start tunnel
	remotedie := make(chan struct{})
	bufremote := make([]byte, 65535)
	go func() {
		io.CopyBuffer(remote, local, bufremote);
		close(remotedie);
	}()

	localdie := make(chan struct{})
	buflocal := make([]byte, 65535)
	go func() {
		io.CopyBuffer(local, remote, buflocal);
		close(localdie);
	}()

	// wait for tunnel termination
	select {
	case <-localdie:
	case <-remotedie:
	}
}

func handleClientAutoBypass(sess *smux.Session, remoteAddr string, remoteAddrTCP string, local io.ReadWriteCloser, chanBypassFlag chan bool, bypassFlag bool, disConFlag *bool, quiet bool) {
	if !quiet {
		log.Println("stream opened")
		defer log.Println("stream closed")
	}

	remotedie := make(chan struct{})
	localdie := make(chan struct{})

	if bypassFlag {
		log.Println("connection bypass")
		createConnBypass := func() (net.Conn, error) {
			kcpconn, err := net.Dial("tcp", remoteAddrTCP)
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}

			log.Println("TCP connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
			return kcpconn, nil
		}
		remote, err := createConnBypass()
		if err != nil {
			log.Println(err)
			return
		}

		defer local.Close()
		defer remote.Close()

		// start tunnel
		bufremote := make([]byte, 65535)
		go func() {
			io.CopyBuffer(remote, local, bufremote);
			close(remotedie);
		}()

		buflocal := make([]byte, 65535)
		go func() {
			io.CopyBuffer(local, remote, buflocal);
			close(localdie);
		}()
	} else {
		log.Println("connection nobypass")
		remote, err := sess.OpenStream()
		if err != nil {
			return
		}
		log.Println("UDP connection:", remote.LocalAddr(), "->", remote.RemoteAddr())

		defer local.Close()
		defer remote.Close()

		// start tunnel
		bufremote := make([]byte, 65535)
		go func() {
			io.CopyBuffer(remote, local, bufremote);
			close(remotedie);
		}()

		buflocal := make([]byte, 65535)
		go func() {
			io.CopyBuffer(local, remote, buflocal);
			close(localdie);
		}()
	}

	// wait for tunnel termination
	select {
	case <-localdie:
		*disConFlag = true
	case <-remotedie:
		*disConFlag = true
	case <-chanBypassFlag:
		*disConFlag = true
	}
}

func checkNetworkQuality(remoteAddr string, bypassFlag *bool) {
	*bypassFlag = true
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Println("Invalid address:", err)
		return
	}

	for {
		pinger, err := ping.NewPinger(host)
		if err != nil {
			log.Println("ERROR:", err.Error())
			return
		}

		pinger.OnRecv = func(pkt *ping.Packet) {
			//log.Println(pkt.Nbytes, "bytes from", pkt.IPAddr, "icmp_seq=", pkt.Seq, "time=", pkt.Rtt)
		}
		pinger.OnFinish = func(stats *ping.Statistics) {
			//var referenceTime time.Duration = 100 * time.Millisecond
			var referenceLoss float64 = 2.0
			//fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
			//fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			//	stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
			//log.Println("avg:", stats.AvgRtt, stats.PacketLoss, "packet loss")
			//if stats.AvgRtt >= referenceTime && stats.PacketLoss >= referenceLoss {
			if stats.PacketLoss >= referenceLoss {
				//log.Println("High latency avg:", stats.AvgRtt, stats.PacketLoss, "packet loss")
				*bypassFlag = false
			} else {
				*bypassFlag = true
				//log.Println("Low latency avg:", stats.AvgRtt, stats.PacketLoss, "packet loss")
			}
		}

		pinger.Count = 100
		pinger.Interval = 100000 //100us
		pinger.Timeout = 300000000 //300ms
		pinger.SetPrivileged(true)

		//fmt.Printf("Count %d, Interval %dns, Timeout=%dns, Privileged=%v\n",
		//		pinger.Count, pinger.Interval, pinger.Timeout, true)

		//fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
		pinger.Run()
		//log.Println("BYPASS:", *bypassFlag)

		time.Sleep(time.Second*10)
	}
}

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	if VERSION == "SELFBUILD" {
		// add more log flags for debugging
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	myApp := cli.NewApp()
	myApp.Name = "kcptun"
	myApp.Usage = "client(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "localaddr,l",
			Value: ":12948",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "vps:29900",
			Usage: "kcp server address",
		},
		cli.StringFlag{
			Name:  "remoteaddrTCP, rt",
			Value: "",
			Usage: "original server address",
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "conn",
			Value: 1,
			Usage: "set num of UDP connections to server",
		},
		cli.IntFlag{
			Name:  "autoexpire",
			Value: 0,
			Usage: "set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
		},
		cli.IntFlag{
			Name:  "scavengettl",
			Value: 600,
			Usage: "set how long an expired connection can live(in sec), -1 to disable",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 128,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 512,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set DSCP(6bit)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.BoolFlag{
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  50,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:  "sockbuf",
			Value: 4194304, // socket buffer size in bytes
			Usage: "per-socket buffer in bytes",
		},
		cli.IntFlag{
			Name:  "smuxver",
			Value: 1,
			Usage: "specify smux version, available 1,2",
		},
		cli.IntFlag{
			Name:  "smuxbuf",
			Value: 4194304,
			Usage: "the overall de-mux buffer in bytes",
		},
		cli.IntFlag{
			Name:  "streambuf",
			Value: 2097152,
			Usage: "per stream receive buffer in bytes, smux v2+",
		},
		cli.IntFlag{
			Name:  "keepalive",
			Value: 10, // nat keepalive interval in seconds
			Usage: "seconds between heartbeats",
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "to suppress the 'stream open/close' messages",
		},
		cli.BoolFlag{
			Name:  "tcp",
			Usage: "to emulate a TCP connection(linux)",
		},
		cli.BoolFlag{
			Name:  "bypass",
			Usage: "enable bypass mode",
		},
		cli.BoolFlag{
			Name:  "nobypass",
			Usage: "disable bypass mode",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.LocalAddr = c.String("localaddr")
		config.RemoteAddr = c.String("remoteaddr")
		config.RemoteAddrTCP = c.String("remoteaddrTCP")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.Conn = c.Int("conn")
		config.AutoExpire = c.Int("autoexpire")
		config.ScavengeTTL = c.Int("scavengettl")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.DSCP = c.Int("dscp")
		config.NoComp = c.Bool("nocomp")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.SmuxBuf = c.Int("smuxbuf")
		config.StreamBuf = c.Int("streambuf")
		config.SmuxVer = c.Int("smuxver")
		config.KeepAlive = c.Int("keepalive")
		config.Log = c.String("log")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.Bypass = c.Bool("bypass")
		config.NoBypass = c.Bool("nobypass")
		config.Quiet = c.Bool("quiet")
		config.TCP = c.Bool("tcp")

		if c.String("c") != "" {
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}

		// the null value defaults to RemoteAddr
		if config.RemoteAddrTCP == "" {
			config.RemoteAddrTCP = config.RemoteAddr
		}

		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		log.Println("version:", VERSION)
		addr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
		checkError(err)
		listener, err := net.ListenTCP("tcp", addr)
		checkError(err)

		log.Println("smux version:", config.SmuxVer)
		log.Println("listening on:", listener.Addr())
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("remote address:", config.RemoteAddr)
		log.Println("remote TCP address:", config.RemoteAddrTCP)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("smuxbuf:", config.SmuxBuf)
		log.Println("streambuf:", config.StreamBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("conn:", config.Conn)
		log.Println("autoexpire:", config.AutoExpire)
		log.Println("scavengettl:", config.ScavengeTTL)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("bypass:", config.Bypass)
		log.Println("nobypass:", config.NoBypass)
		log.Println("quiet:", config.Quiet)
		log.Println("tcp:", config.TCP)

		// parameters check
		if config.SmuxVer > maxSmuxVer {
			log.Fatal("unsupported smux version:", config.SmuxVer)
		}

		if config.Bypass {
			for {
				p1, err := listener.AcceptTCP()
				if err != nil {
					log.Fatalln(err)
				}
				checkError(err)
				go handleClientBypass(config.RemoteAddrTCP, p1, config.Quiet)
			}
		}

		var bypassFlag bool
		bypassFlag = false

		if !config.NoBypass {
			//detect raw TCP address quality
			bypassFlag = true //auto mode, default bypass
			go checkNetworkQuality(config.RemoteAddrTCP, &bypassFlag)
		}

		log.Println("initiating key derivation")
		pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
		log.Println("key derivation done")
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "sm4":
			block, _ = kcp.NewSM4BlockCrypt(pass[:16])
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}

		createConn := func() (*smux.Session, error) {
			kcpconn, err := dial(&config, block)
			if err != nil {
				return nil, errors.Wrap(err, "dial()")
			}
			kcpconn.SetStreamMode(true)
			kcpconn.SetWriteDelay(false)
			kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
			kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
			kcpconn.SetMtu(config.MTU)
			kcpconn.SetACKNoDelay(config.AckNodelay)

			if err := kcpconn.SetDSCP(config.DSCP); err != nil {
				log.Println("SetDSCP:", err)
			}
			if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
				log.Println("SetReadBuffer:", err)
			}
			if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
				log.Println("SetWriteBuffer:", err)
			}
			log.Println("smux version:", config.SmuxVer, "on connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = config.SmuxVer
			smuxConfig.MaxReceiveBuffer = config.SmuxBuf
			smuxConfig.MaxStreamBuffer = config.StreamBuf
			smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

			if err := smux.VerifyConfig(smuxConfig); err != nil {
				log.Fatalf("%+v", err)
			}

			// stream multiplex
			var session *smux.Session
			if config.NoComp {
				session, err = smux.Client(kcpconn, smuxConfig)
			} else {
				session, err = smux.Client(generic.NewCompStream(kcpconn), smuxConfig)
			}
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			return session, nil
		}

		// wait until a connection is ready
		waitConn := func() *smux.Session {
			for {
				if session, err := createConn(); err == nil {
					return session
				} else {
					log.Println("re-connecting:", err)
					time.Sleep(time.Second)
				}
			}
		}

		numconn := uint16(config.Conn)
		muxes := make([]struct {
			session *smux.Session
			ttl     time.Time
		}, numconn)

		for k := range muxes {
			muxes[k].session = waitConn()
			muxes[k].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
		}

		chScavenger := make(chan *smux.Session, 128)
		go scavenger(chScavenger, config.ScavengeTTL)
		go generic.SnmpLogger(config.SnmpLog, config.SnmpPeriod)
		rr := uint16(0)
		for {
			p1, err := listener.AcceptTCP()
			if err != nil {
				log.Fatalf("%+v", err)
			}

			chanBypassFlag := make(chan bool, 1)
			var disConFlag bool
			disConFlag = false

			idx := rr % numconn

			// do auto expiration && reconnection
			if muxes[idx].session.IsClosed() || (config.AutoExpire > 0 && time.Now().After(muxes[idx].ttl)) {
				chScavenger <- muxes[idx].session
				muxes[idx].session = waitConn()
				muxes[idx].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
			}

			go handleClientAutoBypass(muxes[idx].session, config.RemoteAddr, config.RemoteAddrTCP, p1, chanBypassFlag, bypassFlag, &disConFlag, config.Quiet)

			if !config.NoBypass {
				go func() {
					var changeTimestamp int64
					changeTimestamp = 0
					curBypassFlag := bypassFlag
					changeBypassFlag := bypassFlag
					time.Sleep(10 * time.Second)
					for {
						curTimestamp := time.Now().Unix()
						if bypassFlag != curBypassFlag && bypassFlag != changeBypassFlag {
							log.Println("bypass Flag has changed:", bypassFlag)
							changeBypassFlag = bypassFlag
							changeTimestamp = curTimestamp
							//log.Println("changed timestamp:", changeTimestamp)
						} else if bypassFlag == curBypassFlag{
							changeTimestamp = 0
							changeBypassFlag = curBypassFlag
							//log.Println("BypassFlag is consistent with the current value and refresh duration.")
						}

						if disConFlag {
							log.Println("The client connection has been disconnected, stop the timed detection task!!!")
							return
						}

						if changeTimestamp > 0 {
							if curTimestamp-changeTimestamp > 60 {
								if curBypassFlag != changeBypassFlag {
									chanBypassFlag <- bypassFlag
									log.Println("BypassFlag has changed and its duration exceeds 60s, close the socket!!!")
									return
								}
							}
							//log.Println("BypassFlag has changed, but the duration was less than 60s.")
						}
						//log.Println("Timed task detection BypassFlag changes...")
						time.Sleep(10 * time.Second)
					}
				}()
			}

			rr++
		}
	}
	myApp.Run(os.Args)
}

type scavengeSession struct {
	session *smux.Session
	ts      time.Time
}

func scavenger(ch chan *smux.Session, ttl int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []scavengeSession
	for {
		select {
		case sess := <-ch:
			sessionList = append(sessionList, scavengeSession{sess, time.Now()})
			log.Println("session marked as expired", sess.RemoteAddr())
		case <-ticker.C:
			var newList []scavengeSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.NumStreams() == 0 || s.session.IsClosed() {
					log.Println("session normally closed", s.session.RemoteAddr())
					s.session.Close()
				} else if ttl >= 0 && time.Since(s.ts) >= time.Duration(ttl)*time.Second {
					log.Println("session reached scavenge ttl", s.session.RemoteAddr())
					s.session.Close()
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}
