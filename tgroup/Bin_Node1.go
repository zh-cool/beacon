// Node stack with ping/pong and API reporting
package main

import (
	"dfinity/beacon/bls"
	"dfinity/beacon/blscgo"
	"dfinity/beacon/state"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"tgroup/tools"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	p2pPort       = 1025
	ipcpath       = ".demo.ipc"
	datadirPrefix = "/tmp/.data_"
	stackW        = &sync.WaitGroup{}
	HELLO         = "HELLO"
	REPLYHELLO    = "REPLYHELLO"
	NODESINFO     = "NODESINFO"
	COMBINEADDR   = "COMBINEADDR"
	FILENAME      = "/go/src/go-ethereum/test.txt"
	GROUPS        = 5 //groups number, here we set only two groups
	THRESHOLD     = 2
	THISGROUP     = 1
	TESTINGFLAG   chan string
)

type FooPingMsg struct {
	Pong    bool
	Created time.Time
	Inmsg   string
	Type    string
}

type HelloMsg struct {
	Msgtype string
	Msg     string
	Address common.Address
	Myid    int
}

type ShareCombined struct {
	AD             common.Address
	SharesCombined []byte
}

// the service we want to offer on the node
// it must implement the node.Service interface
type fooService struct {
	pongcount int
	BlSInfo   tools.BlsInfo
	HelloMsgS map[discover.NodeID]chan HelloMsg
	Nodes     map[discover.NodeID]*tools.MemberInfo
	Members   []*tools.MemberInfo
	Chain     []*state.State
	Group     tools.GroupInfo
	RW        map[discover.NodeID]*p2p.MsgReadWriter
}

// specify API structs that carry the methods we want to use
func (self *fooService) APIs() []rpc.API {
	return []rpc.API{
		rpc.API{
			Namespace: "foo",
			Version:   "42",
			Service: &FooAPI{
				running:   true,
				pongcount: &self.pongcount,
				HelloMsgS: self.HelloMsgS,
				NodeBLS:   self.BlSInfo,
			},
			Public: true,
		},
	}
}

func check_same_group(id1, id int) bool {

	if id1%GROUPS == id%GROUPS {
		return true
	} else {
		return false
	}

}

func CheckExistance(ThisList []common.Address, ThisAddress common.Address) bool {
	for _, el := range ThisList {
		if el.String() == ThisAddress.String() {
			return true
		}
	}
	return false
}

func (self *fooService) HandleHelloPeer(msg []byte, id discover.NodeID) bool {
	var val HelloMsg
	json.Unmarshal(msg, &val)
	//fixme we force the first group to generate the signature
	//fixme add this node address to its dictionary
	ret := CheckExistance(self.BlSInfo.AddressList, val.Address)
	self.BlSInfo.AddressP2pID[val.Address] = id
	if ret == false {
		self.BlSInfo.AddressList = append(self.BlSInfo.AddressList, val.Address)
	}
	return true
}

func (self *fooService) ConstructGroup() tools.GroupInfo {
	Nodes := self.Nodes
	//we should add this node itself in this group
	m := len(Nodes) + 1
	addresses := make([]common.Address, m)
	pmap := make(map[common.Address]*tools.MemberInfo)

	//var address common.Address
	//var pmap map[common.Address]* tools.MemberInfo

	i := 0
	var MembersList []*tools.MemberInfo
	for _, p := range Nodes {
		addresses[i] = p.Reginfo.Address()
		pmap[p.Reginfo.Address()] = p
		MembersList = append(MembersList, p)
		i++
	}
	//add my self to the member
	myself := tools.MemberInfo{
		Rseed:   self.BlSInfo.Rseed,
		Sec:     self.BlSInfo.Sec,
		Reginfo: self.BlSInfo.Reginfo,
		Address: self.BlSInfo.Address(),
	}
	MembersList = append(MembersList, &myself)
	addresses[i] = self.BlSInfo.Reginfo.Address()
	pmap[self.BlSInfo.Reginfo.Address()] = &myself

	for _, each := range MembersList {
		logmsg := fmt.Sprintf("(sec)%s (seed)%x %s", each.Sec.String()[:4],
			each.Rseed.String()[:2], each.Reginfo.String())

		log.Debug("PEER BLS INFO", "peer", logmsg)
	}

	g := state.NewGroup(addresses, uint16(THRESHOLD))
	//as we have already distributed, so we donot need this function
	tools.ExchangeSeckeyShares(g, &self.BlSInfo)
	// build group pubkey
	pubs := make([]bls.Pubkey, m)
	for j, p := range MembersList {
		pubs[j] = bls.PubkeyFromSeckey(p.GetSeckeyForGroup(g))
	}
	pub := bls.AggregatePubkeys(pubs)
	g.SetPubkey(pub, uint16(THRESHOLD))
	self.BlSInfo.AggregateGroupShares(g)

	//this check is not necessary
	//ret := self.BlSInfo.NeedDoubleCheck(pub, MembersList, uint16(THRESHOLD), g)

	return tools.GroupInfo{
		Reginfo:  g,
		Proclist: MembersList,
		Procmap:  pmap,
	}
}

func reconstructBlsInfo(val tools.BLSNet, rw *p2p.MsgReadWriter) tools.MemberInfo {
	//fixme we call seckeyFrom bytes but it has restrictions of the length of the bytes
	sec := bls.SeckeyFromBytes(val.Sec)
	var rseed bls.Rand
	copy(rseed[:bls.RandLength], val.Rseed[:])
	reginfo := state.NodeFromSeckey(sec)
	ret := tools.MemberInfo{
		Sec:     sec,
		Rseed:   rseed,
		Reginfo: reginfo,
		Address: val.Address,
	}
	return ret
}

func (self *fooService) HandleNodesPeer(peer *p2p.Peer, msg []byte, rw *p2p.MsgReadWriter) {
	var val tools.BLSNet
	json.Unmarshal(msg, &val)
	member := reconstructBlsInfo(val, rw)
	logmsg := fmt.Sprintf("(sec)%s (seed)%x %s", member.Sec.String()[:4],
		member.Rseed.String()[:2], member.Reginfo.String())
	log.Debug("peer bls info", "peer", logmsg)
	self.Nodes[peer.ID()] = &member
}

func (self *fooService) do_sign(msg []byte) bls.Signature {
	sigmap := make(map[common.Address]bls.Signature)
	// get signature share from each process
	//t0 := time.Now()
	for _, p := range self.Members {
		if p.Address == self.BlSInfo.Address() {
			continue
		}
		sec := p.SharesCombined
		sigmap[p.Address] = bls.Sign(sec, msg)
	}
	mysec := self.BlSInfo.SharesCombined[self.Group.Reginfo.Address()]
	sigmap[self.BlSInfo.Address()] = bls.Sign(mysec, msg)

	/*for a,b := range sigmap{
		log.Info("AAA","ad",self.BlSInfo.Address(),"a",a.Hex(),"b",b.String())
	}*/

	sig := bls.RecoverSignatureByMap(sigmap, self.Group.Reginfo.Threshold())
	log.Debug("SIGNATURE", "sig", sig.String())
	return sig
}

func (self *fooService) Sign() {
	last_block := self.Chain[len(self.Chain)-1]
	i := last_block.Rand().Modulo(GROUPS)
	log.Info("SINGER GROUP NUMBER", "i", i)
	msg := last_block.Rand().Bytes()

	sig := self.do_sign(msg)

	//g := self.Group
	//sig := self.Group.Sign(last_block.Rand().Bytes())

	// the new state is identical to the curren tip, except that we overwrite the signature
	newstate := last_block

	// sign new state by group
	newstate.SetSignature(sig)

	// append new state
	self.Chain = append(self.Chain, newstate)

	log.Info("NEW BLOCK SIGNATURE", "sig", sig.String())
}

func (self *fooService) SendCombineVal() {
	sharedcombinedval := self.BlSInfo.SharesCombined
	a := ShareCombined{
		AD:             self.BlSInfo.Address(),
		SharesCombined: sharedcombinedval[self.Group.Reginfo.Address()].BigInt().Bytes(),
	}

	send, _ := json.Marshal(a)
	encoded := base64.StdEncoding.EncodeToString(send)

	/*for _, val := range (self.Members) {
		log.Info("aaaa", "val", val.Address.Bytes())
	}

	if self.BlSInfo.AMMember {
		log.Info("I am the member", "val", self.BlSInfo.Address().Bytes())
	}*/

	pingmsg := &FooPingMsg{
		Pong:    false,
		Inmsg:   encoded,
		Type:    COMBINEADDR,
		Created: time.Now(),
	}
	// either handler or sender should be asynchronous, otherwise we might deadlock
	for _, memb := range self.Members {
		if memb.Address == self.BlSInfo.Address() {
			continue
		}
		rw := self.RW[memb.ID]
		go p2p.Send(*rw, 0, pingmsg)
	}
}

// the p2p.Protocol to run
// sends a ping to its peer, waits pong
func (self *fooService) Protocols() []p2p.Protocol {
	return []p2p.Protocol{
		p2p.Protocol{
			Name:    "xiaoma",
			Version: 666,
			Length:  1,
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				// create the channel when a connection is made
				self.HelloMsgS[p.ID()] = make(chan HelloMsg)
				HelloMsgSount := 0

				thisblock := genesis_block()
				self.Chain = append(self.Chain, thisblock)
				CopyRw := rw
				self.RW[p.ID()] = &CopyRw

				// create the message structure
				// we don't know if we're awaiting anything at the time of the kill so this subroutine will run till the application ends
				go func() {
					for {
						// listen for new message
						msg, err := rw.ReadMsg()
						if err != nil {
							log.Warn("Receive p2p message fail", "err", err)
							break
						}
						// decode the message and check the contents
						var decodedmsg FooPingMsg
						err = msg.Decode(&decodedmsg)
						if err != nil {
							log.Error("Decode p2p message fail", "err", err)
							break
						}
						switch msgtype := decodedmsg.Type; msgtype {
						case REPLYHELLO:
							decoded, _ := base64.StdEncoding.DecodeString(decodedmsg.Inmsg)
							//var val HelloMsg
							//json.Unmarshal(t1, &val)
							self.HandleHelloPeer(decoded, p.ID())

						case HELLO:
							if true {
								log.Debug("send my bls detail")
								blsnet := tools.BLSNet{
									Sec:     self.BlSInfo.Sec.Bytes(),
									Rseed:   self.BlSInfo.Rseed.Bytes(),
									Address: self.BlSInfo.Address(),
								}
								marshed, _ := json.Marshal(blsnet)
								encoded := base64.StdEncoding.EncodeToString(marshed)
								pingmsg := &FooPingMsg{
									Pong:    true,
									Type:    NODESINFO,
									Inmsg:   encoded,
									Created: time.Now(),
								}
								err := p2p.Send(rw, 0, pingmsg)
								if err != nil {
									log.Error("Send p2p message fail", "err", err)
									break
								}
								log.Debug("sent pong", "peer", p)
							}

							msg := HelloMsg{
								Msgtype: REPLYHELLO,
								Msg:     "bin yu",
								Address: self.BlSInfo.Address(),
								Myid:    self.BlSInfo.Grouprandom,
							}

							marshed, _ := json.Marshal(msg)
							encoded := base64.StdEncoding.EncodeToString(marshed)
							// send ping
							pingmsg := &FooPingMsg{
								Pong:    false,
								Inmsg:   encoded,
								Type:    msg.Msgtype,
								Created: time.Now(),
							}

							// either handler or sender should be asynchronous, otherwise we might deadlock
							go p2p.Send(rw, 0, pingmsg)

						case NODESINFO:
							decoded, _ := base64.StdEncoding.DecodeString(decodedmsg.Inmsg)
							self.HandleNodesPeer(p, decoded, &CopyRw)

						case COMBINEADDR:
							var a ShareCombined
							decoded, _ := base64.StdEncoding.DecodeString(decodedmsg.Inmsg)
							json.Unmarshal(decoded, &a)
							val := bls.SeckeyFromBigInt(new(big.Int).SetBytes(a.SharesCombined))
							for i, each := range self.Members {
								mem := &self.Members[i]
								if each.Address == a.AD {
									(*mem).SharesCombined = val
								}
							}
						default:
							log.Info("DEFAULT")
						}

					}
				}()

				// pings are invoked through the API using a channel
				// when this channel is closed we quit the protocol
				for {
					// wait for signal to send ping
					msg, ok := <-self.HelloMsgS[p.ID()]
					if !ok {
						log.Debug("break protocol", "peer", p)
						break
					}

					marshed, _ := json.Marshal(msg)
					encoded := base64.StdEncoding.EncodeToString(marshed)
					// send ping
					pingmsg := &FooPingMsg{
						Pong:    false,
						Inmsg:   encoded,
						Type:    msg.Msgtype,
						Created: time.Now(),
					}

					// either handler or sender should be asynchronous, otherwise we might deadlock
					go p2p.Send(rw, 0, pingmsg)
					HelloMsgSount++
					log.Debug("sent ping", "peer", p, "count", HelloMsgSount)
				}

				return nil
			},
		},
	}
}

func (self *fooService) GenerateGroups() {

	chain := self.Chain[len(self.Chain)-1]
	chainhash := chain.GetHash()

	//fixme we have 5 groups here
	for i := 1; i < GROUPS; i++ {
		AddressHash, Addressmap := tools.HandleEachgroup(chainhash, self.BlSInfo, i)

		for i, each := range AddressHash {
			self.BlSInfo.AddressSortedList[Addressmap[each]] =
				append(self.BlSInfo.AddressSortedList[Addressmap[each]], i)
		}
	}

	for ad, each := range self.BlSInfo.AddressSortedList {
		log.Debug("LIST INFO", "add", self.BlSInfo.Address().Hex(), "aaaaa", ad.Hex(),
			"each", each)
	}

	//fixme we always choose the first group, and top 4 can sign on the block
	var WHICH_SIGN_GROUP = 0
	for ad, poslist := range self.BlSInfo.AddressSortedList {
		if poslist[WHICH_SIGN_GROUP] < 3 {
			member := tools.MemberInfo{
				Address: ad,
			}
			if self.BlSInfo.Address() == ad {
				self.BlSInfo.AMMember = true
			}
			//link peer id and memeber
			member.ID = self.BlSInfo.AddressP2pID[ad]
			self.Members = append(self.Members, &member)
		}
	}
}

func (self *fooService) Start(srv *p2p.Server) error {

	//routine for construct the groups
	go func() {

		<-TESTINGFLAG

		self.GenerateGroups()

		time.Sleep(time.Second * 20)
		if self.BlSInfo.AMMember {
			self.Group = self.ConstructGroup()
			self.SendCombineVal()
		}

		<-TESTINGFLAG

		if self.BlSInfo.AMMember {
			self.Sign()
		}

	}()

	return nil
}

func (self *fooService) Stop() error {
	return nil
}

// Specify the API
// in this example we don't care about who the pongs comes from, we count them all
// note it is a bit fragile; we don't check for closed channels
type FooAPI struct {
	running   bool
	pongcount *int
	HelloMsgS map[discover.NodeID]chan HelloMsg
	NodeBLS   tools.BlsInfo
}

func (api *FooAPI) Increment() {
	*api.pongcount++
}

// invoke a single ping
//func (api *FooAPI) Ping(id discover.NodeID) error {
//	if api.running {
//		api.HelloMsgS[id] <- HelloMsg{1, "bin yu", myran}
//	}
//	return nil
//}

func (api *FooAPI) SendInfo(id discover.NodeID, thisnode tools.BlsInfo) error {
	if api.running {
		api.HelloMsgS[id] <- HelloMsg{
			HELLO,
			"bin yu",
			thisnode.Reginfo.Address(),
			thisnode.Grouprandom,
		}
	}
	return nil
}

func (api *FooAPI) SendSharedCombined(id discover.NodeID, thisnode tools.BlsInfo) error {
	if api.running {
		api.HelloMsgS[id] <- HelloMsg{HELLO, "bin yu",
			thisnode.Address(),
			thisnode.Grouprandom,
		}
	}
	return nil
}

// quit the ping protocol
func (api *FooAPI) Quit(id discover.NodeID) error {

	log.Info("quiting API", "peer", id)

	if api.HelloMsgS[id] == nil {
		return fmt.Errorf("unknown peer")
	}
	api.running = false
	close(api.HelloMsgS[id])
	return nil
}

// return the amounts of pongs received
func (api *FooAPI) PongCount() (int, error) {
	return *api.pongcount, nil
}

// set up the local service node
func newServiceNode(port int, httpport int, wsport int, modules ...string) (*node.Node, error) {
	cfg := &node.DefaultConfig
	cfg.P2P.ListenAddr = fmt.Sprintf(":%d", port)
	cfg.P2P.EnableMsgEvents = true
	cfg.P2P.NoDiscovery = false
	cfg.IPCPath = ipcpath
	cfg.DataDir = fmt.Sprintf("%s%d", datadirPrefix, port)
	if httpport > 0 {
		cfg.HTTPHost = node.DefaultHTTPHost
		cfg.HTTPPort = httpport
	}
	if wsport > 0 {
		cfg.WSHost = node.DefaultWSHost
		cfg.WSPort = wsport
		cfg.WSOrigins = []string{"*"}
		for i := 0; i < len(modules); i++ {
			cfg.WSModules = append(cfg.WSModules, modules[i])
		}
	}

	stringname := "enode" +
		"://c8a0689ce43596339f51cb2569ddb902c402a9a07723adb40da3a26bb098e040313686d49dca4c856a4c01e6dea88ab871806c3e8e510c19cd4ca3ed2859f5ca@172.17.0.1:30301"
	//
	//
	NewNode := discover.MustParseNode(stringname)
	cfg.P2P.BootstrapNodes = append(cfg.P2P.BootstrapNodes, NewNode)

	stack, err := node.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("ServiceNode create fail: %v", err)
	}
	return stack, nil
}

func NewBLSNodeInfo(sec bls.Seckey, seed bls.Rand) (p tools.BlsInfo) {

	randsource := rand.NewSource(time.Now().Unix())
	randnum := rand.New(randsource)
	grouprandom := randnum.Intn(99999999)
	//fixme this is only for debug will remove in real environment
	//fixme we force it to be even number
	if grouprandom%2 == 0 {
		grouprandom += 1
	}
	BlsNode := tools.BlsInfo{
		Sec:               sec,
		Reginfo:           state.NodeFromSeckey(sec),
		Rseed:             seed,
		Grouprandom:       grouprandom,
		SharesSource:      make(map[common.Address]bls.SeckeyMap),
		SharesCombined:    bls.SeckeyMap{},
		AddressSortedList: make(map[common.Address][]int),
		AddressP2pID:      make(map[common.Address]discover.NodeID),
		AMMember:          false,
	}
	return BlsNode
}

/*
func WriteAddressFile(data []byte){
	f, _ := os.OpenFile(FILENAME, os.O_APPEND|os.O_WRONLY, 0644)
	out := base64.StdEncoding.EncodeToString(data)
	f.WriteString(out+"\n")
	f.Close()
}*/

func bls_related(i string) (p tools.BlsInfo) {

	var l, n, k, N, m uint
	var seedstr string
	var bist, vvec, timing bool
	var curve string
	flag.UintVar(&l, "l", 20, "Length of chain (number of blocks to create)")
	flag.UintVar(&n, "n", 3, "Group size")
	flag.UintVar(&k, "k", 2, "Threshold")
	flag.UintVar(&N, "N", 8, "Number of processes")
	flag.UintVar(&m, "m", 5, "Number of groups")
	flag.StringVar(&seedstr, "seed", "DFINITY", "Random seed")
	flag.BoolVar(&bist, "bist", false, "Enable Built-in self test")
	flag.BoolVar(&vvec, "vvec", false, "Enable validation against verification vector")
	flag.BoolVar(&timing, "timing", false, "Enable output of timing information")
	flag.StringVar(&curve, "curve", "bn382_1", "Pairing type")
	flag.Parse()

	if curve == "bn254" {
		fmt.Println("bn254")
		blscgo.Init(blscgo.CurveFp254BNb)
	} else if curve == "bn382_1" {
		fmt.Println("bn382_1")
		blscgo.Init(blscgo.CurveFp382_1)
	} else if curve == "bn382_2" {
		fmt.Println("bn382_2")
		blscgo.Init(blscgo.CurveFp382_2)
	} else {
		fmt.Printf("not supported curve %s\n", curve)
		return
	}
	Seed := bls.RandFromBytes([]byte(seedstr))
	Rsec := Seed.Ders("InitProcs_sec")
	Rseed := Seed.Ders("InitProcs_seed")
	ThisBls := NewBLSNodeInfo(bls.SeckeyFromRand(Rsec.Ders(i)), Rseed.Ders(i))
	logmsg := fmt.Sprintf("(sec)%s (seed)%x %s", ThisBls.Sec.String()[:4],
		ThisBls.Rseed.String()[:2], ThisBls.Reginfo.String())
	log.Info("NODE INFO", "This Node", logmsg)
	log.Info("NODE INFO", "address", ThisBls.Reginfo.Address().String())

	//WriteAddressFile(ThisBls.Reginfo.Address().Bytes())

	return ThisBls
}

func genesis_block() *state.State {
	// Build the genesis block
	genesis := state.NewState()
	genesis.SetHash("GENESIS")
	val := genesis.GetHash()
	logmsg := ""
	for _, el := range val {
		logmsg += fmt.Sprintf("%x", el)
	}
	log.Debug("GENESIS HASH", "hash=", logmsg)
	return &genesis
}

//func GetAllNodeAddresses(){
//
//	time.Sleep(time.Second*10)
//	f2, _ := os.OpenFile(FILENAME, os.O_RDONLY, 0644)
//	for true {
//		r := bufio.NewReader(f2)
//		abc, _, _ := r.ReadLine()
//		if len(abc) == 0{
//			break
//		}
//		org, _ := base64.StdEncoding.DecodeString(string(abc))
//		log.Info("reacovery", "reacovery", common.BytesToAddress(org).String())
//	}
//	f2.Close()
//}

func main() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr,
		log.TerminalFormat(false))))

	TESTINGFLAG = make(chan string)
	s2 := rand.NewSource(time.Now().Unix())
	ss := rand.New(s2)
	portRand := ss.Intn(45535)

	// create the two nodes
	stack_one, err := newServiceNode(p2pPort+portRand, 0, 0)
	if err != nil {
		log.Crit("Create servicenode #1 fail", "err", err)
		return
	}

	//fixme we use the current time as the "random"
	ThisBls := bls_related(time.Now().String())
	ThisBls.AddressList = append(ThisBls.AddressList, ThisBls.Address())
	// wrapper function for servicenode to start the service
	foosvc := func(ctx *node.ServiceContext) (node.Service, error) {
		return &fooService{
			HelloMsgS: make(map[discover.NodeID]chan HelloMsg),
			BlSInfo:   ThisBls,
			Nodes:     make(map[discover.NodeID]*tools.MemberInfo),
			RW:        make(map[discover.NodeID]*p2p.MsgReadWriter),
			Chain:     make([]*state.State, 0, 100),
		}, nil
	}

	// register adds the service to the services the servicenode starts when started
	err = stack_one.Register(foosvc)
	if err != nil {
		log.Crit("Register service in servicenode #1 fail", "err", err)
	}

	// start the nodes
	err = stack_one.Start()
	if err != nil {
		log.Crit("servicenode #1 start failed", "err", err)
	}

	// connect to the servicenode RPCs
	rpcclient_one, err := rpc.Dial(filepath.Join(stack_one.DataDir(), ipcpath))
	if err != nil {
		log.Crit("connect to servicenode #1 IPC fail", "err", err)
	}
	defer os.RemoveAll(stack_one.DataDir())

	// display that the initial pong counts are 0
	var count int
	err = rpcclient_one.Call(&count, "foo_pongCount")
	if err != nil {
		log.Crit("servicenode #1 pongcount RPC failed", "err", err)
	}
	log.Info("servicenode #1 before ping", "pongcount", count)

	// get the server instances
	srv_one := stack_one.Server()

	// subscribe to peerevents
	eventOneC := make(chan *p2p.PeerEvent)
	sub_one := srv_one.SubscribeEvents(eventOneC)

	// connect the nodes
	//p2pnode_two := srv_two.Self()
	//srv_one.AddPeer(p2pnode_two)

	// fork and do the pinging
	stackW.Add(2)
	pingmax_one := 1
	pingmax_two := 1

	go func() {
		//for true {
		//inputReader := bufio.NewReader(os.Stdin)
		//ret,_ := inputReader.ReadString('\n')
		for i := 0; i < 2; i++ {
			time.Sleep(time.Minute * 1)
			log.Info(">>>>>>>>>>>>READY TO RUN>>>>>>>>>>>", "round", i)
			//if input != ""{
			TESTINGFLAG <- "12"
			//}
			//}
		}
	}()

	go func() {

		// when we get the add event, we know we are connected
		for true {
			ev := <-eventOneC
			//if ev.Type != "add" {
			//	log.Error("server #1 expected peer add", "eventtype", ev.Type)
			//	stackW.Done()
			//	return
			//}

			if ev.Type == "add" {
				err := rpcclient_one.Call(nil, "foo_sendInfo", ev.Peer, ThisBls)
				if err != nil {
					log.Error("server #1 RPC ping fail", "err", err)
					stackW.Done()
					break
				}
			}

			log.Debug("server #1 connected", "peer", ev.Peer)

			// send the pings
			//for i := 0; i < pingmax_one; i++ {
			//	err := rpcclient_one.Call(nil, "foo_sendInfo", ev.Peer, ThisBls)
			//	if err != nil {
			//		log.Error("server #1 RPC ping fail", "err", err)
			//		stackW.Done()
			//		break
			//	}
			//}
		}

		// wait for all msgrecv events
		// pings we receive, and pongs we expect from pings we sent
		for i := 0; i < pingmax_two+pingmax_one; {
			ev := <-eventOneC
			log.Warn("msg", "type", ev.Type, "i", i)
			if ev.Type == "msgrecv" {
				i++
			}
		}

		stackW.Done()
	}()

	// wait for the two ping pong exchanges to finish
	stackW.Wait()

	// tell the API to shut down
	// this will disconnect the peers and close the channels connecting API and protocol

	// tell the API to shut down
	// this will disconnect the peers and close the channels connecting API and protocol

	err = rpcclient_one.Call(nil, "foo_quit", srv_one.PeersInfo()[0].ID)
	if err != nil {
		log.Error("server #1 RPC quit fail", "err", err)
	}

	// disconnect will generate drop events
	for {
		ev := <-eventOneC
		if ev.Type == "drop" {
			break
		}
	}

	// proudly inspect the results
	err = rpcclient_one.Call(&count, "foo_pongCount")
	if err != nil {
		log.Crit("servicenode #1 pongcount RPC failed", "err", err)
	}
	log.Info("servicenode #1 after ping", "pongcount", count)

	// bring down the servicenodes
	sub_one.Unsubscribe()

	stack_one.Stop()
}
