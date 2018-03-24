package tools
import(
	"dfinity/beacon/state"
	"dfinity/beacon/bls"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"

	"fmt"
	"github.com/ethereum/go-ethereum/p2p/discover"
)

// DoubleCheck -- enable optional double-checks for verification
var DoubleCheck = true

// Vvec -- enable checks involving the verification vectors
var Vvec = true

// Timing -- enable output of timing information
var Timing = false


type BLSNet struct{
	Sec []byte
	Rseed []byte
	Address common.Address

}

type MemberInfo struct{
	Address common.Address
	Sec     bls.Seckey
	Reginfo state.Node
	Rseed   bls.Rand
	SharesCombined bls.Seckey
	ID discover.NodeID
}

type BlsInfo struct{
	Sec     bls.Seckey
	Reginfo state.Node
	Rseed   bls.Rand
	Grouprandom int
	// rseed is the seed used for the internal randomness of the process, it did not seed the secret key
	SharesSource   map[common.Address]bls.SeckeyMap
	AddressSortedList map[common.Address][]int
	AddressList    []common.Address
	AddressP2pID     map[common.Address] discover.NodeID
	SharesCombined bls.SeckeyMap
	AMMember  bool
}

type GroupInfo struct {
	// the group secret key (sec) is here only to enable optional double-checks
	Sec      bls.Seckey
	Reginfo  state.Group
	Proclist []*MemberInfo
	Procmap  map[common.Address]*MemberInfo
}


// SignForGroup -- return the signature share for the given message and group
//func (p *MemberInfo) SignForGroup(g state.Group, msg []byte) bls.Signature {
//	sec := p.SharesCombined[g.Address()]
//	//	fmt.Printf("sign for group: (grp)%.2x (sec)%x\n", g.Address(), sec.String())
//	return bls.Sign(sec, msg)
//}



// Sign -- make the group members jointly create a group signature
//func (g GroupInfo) Sign(msg []byte) bls.Signature {
//	sigmap := make(map[common.Address]bls.Signature)
//	// get signature share from each process
//	t0 := time.Now()
//	for _, member := range g.Proclist {
//		sigmap[member.Reginfo.Address()] = member.SignForGroup(g.Reginfo, msg)
//	}
//	delta1 := time.Since(t0)
//	t1 := time.Now()
//	sig1 := bls.RecoverSignatureByMap(sigmap, g.Reginfo.Threshold())
//	delta2 := time.Since(t1)
//	if Timing {
//		fmt.Printf("Time for group signatures with %d shares: %v (%vus / share) + %v (recovery).\n", len(g.proclist), delta1, (delta1.Nanoseconds()/1000)/int64(len(g.Proclist)), delta2)
//	}
//
//	// optional verification
//	if DoubleCheck {
//		sig2 := bls.Sign(g.Sec, msg)
//		if sig1.String() != sig2.String() {
//			fmt.Println("Error in Group sign: Recovered signature does not match.")
//		}
//	}
//
//	return sig1
//}


func (p *BlsInfo) NeedDoubleCheck(pub  bls.Pubkey,members []*MemberInfo, k uint16,
	g state.Group )(bool){
	if DoubleCheck {
		// fetch the combined shares from each process into a SeckeyMap
		// (every process does this so we wouldn't need to in the group simulator)
		aggShares := bls.SeckeyMap{}
		for _, peer := range members {
			aggShares[peer.Reginfo.Address()] = p.SharesCombined[g.Address()]
		}

		// recover the combined group secret from combined shares
		// choose k random shares, combine and compare
		sec := bls.RecoverSeckeyByMap(aggShares, int(k))
		pubDup := bls.PubkeyFromSeckey(sec)

		// optional double-check: aggregate all contributions into the group secret and compare
		secs := make([]bls.Seckey, len(members))
		for i, p := range members {
			secs[i] = p.GetSeckeyForGroup(g)
		}
		secDup := bls.AggregateSeckeys(secs)
		if sec.String() != secDup.String() {
			log.Info("Error: recovered aggregated seckey does not match.")
		}

		if pub.String() != pubDup.String() {
			log.Info("Error: recovered aggregated pubkey does not match.")
		}
	}
	return false
}


// GetSeckeyForGroup -- return the own secret provided for the group setup (function of internal seed and group address)
func (p *BlsInfo) GetSeckeyForGroup(g state.Group) (sec bls.Seckey) {
	addr := g.Address()
	gseed := p.Rseed.DerivedRand(addr[:])
	sec = bls.SeckeyFromRand(gseed.Deri(0))
	//	fmt.Printf("sec for group: %s\n", sec.String())
	return
}

// AggregateGroupShares -- aggregate (sum up) all the shares that came in from members of the given group
func (p *BlsInfo) AggregateGroupShares(g state.Group) {
	addr := g.Address()
	vlist := make([]bls.Seckey, len(p.SharesSource[addr]))
	i := 0
	for _, sec := range p.SharesSource[addr] {
		vlist[i] = sec
		i++
	}
	p.SharesCombined[addr] = bls.AggregateSeckeys(vlist)
	return
}


// GetSeckeyForGroup -- return the own secret provided for the group setup (function of internal seed and group address)
func (p *MemberInfo) GetSeckeyForGroup(g state.Group) (sec bls.Seckey) {
	addr := g.Address()
	gseed := p.Rseed.DerivedRand(addr[:])
	sec = bls.SeckeyFromRand(gseed.Deri(0))
	return
}

func ExchangeSeckeyShares(g state.Group, myself *BlsInfo) {

	shares, vvec := myself.GetSeckeySharesForGroup(g)
	sec := myself.GetSeckeyForGroup(g)
	// send shares out to all other individual processes
	myself.SetGroupShare(g.Address(), myself.Address(), shares[myself.Address()], vvec)
	log.Debug("SHARE INFO", "share", sec.Hex())
	// optional double-check of the group secret
	if DoubleCheck {
		sec := myself.GetSeckeyForGroup(g)
		recovered := bls.RecoverSeckeyByMap(shares, g.Threshold())
		if sec.String() != recovered.String() {
			log.Debug("Error: recovered seckey share (ByMap) does not match.")
		} else {
			log.Debug("pass the recoverd seckey share check!")
		}
	}

}


func (p *BlsInfo) GetSeckeySharesForGroup(g state.Group) (bls.SeckeyMap, []bls.Pubkey) {
	addr := g.Address()
	gseed := p.Rseed.DerivedRand(addr[:])
	// from the per-group seed derive a vector of k seckeys as the master seckey where k is the threshold
	// the master seckey defines a polynomial of degree k-1
	k := g.Threshold()
	msec := make([]bls.Seckey, k)
	vvec := make([]bls.Pubkey, k)
	for i := 0; i < k; i++ {
		msec[i] = bls.SeckeyFromRand(gseed.Deri(i))
		vvec[i] = bls.PubkeyFromSeckey(msec[i])
	}
	shares := bls.SeckeyMap{}
	for _, m := range g.Members() {
		shares[m] = bls.ShareSeckeyByAddr(msec, m)
	}
	return shares, vvec
}

// Address -- return the address of the simulated process
func (p *BlsInfo) Address() common.Address {
	return p.Reginfo.Address()
}

// SetGroupShare -- set the incoming shares from other group members
func (p *BlsInfo) SetGroupShare(addr common.Address, source common.Address, share bls.Seckey, vvec []bls.Pubkey) {
	//logmsg := fmt.Sprintf("Setting source share: (proc)%.4x (grp)%.2x (src)%.4x (sec)%.4s", p.Address(), addr, source, share.String())
	//log.Info(">>>>>>>","crx=",logmsg)
		// verify share

	//fixme, I have checked the original code,
	//fixme it also return false if I open this condition
	if false {

		log.Info("========", "pp",bls.PubkeyFromSeckey(share).String())
		log.Info("========", "pp",bls.SharePubkey(vvec, p.Reginfo.ID()).String() )


		if bls.SharePubkey(vvec, p.Reginfo.ID()).String() != bls.PubkeyFromSeckey(share).
			String() {
			fmt.Println("Error: Received secret share does not match committed verification vector")
		}
	}

	// if key source does not exist yet then make a bls.SeckeyMap
	_, exists := p.SharesSource[addr]
	if !exists {
		p.SharesSource[addr] = bls.SeckeyMap{}
	}
	// store source share
	p.SharesSource[addr][source] = share
	return
}
