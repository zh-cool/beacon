package tools
import(
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/common"
	"dfinity/beacon/bls"


	"encoding/hex"
	"encoding/binary"
	"sort"
)


// Hex returns an EIP55-compliant hex string representation of the address.
func Hex( input []byte) string {
	unchecksummed := hex.EncodeToString(input[:])
	sha := sha3.NewKeccak256()
	sha.Write([]byte(unchecksummed))
	hash := sha.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

func HandleEachgroup(chainhash [64] byte, BlsInfo BlsInfo,
	groupnumber int) ([]string, map[string]common.Address) {

	var tmp string
	 var buf = make([]byte, 8)
    binary.BigEndian.PutUint64(buf, uint64(groupnumber))
	Addressmap := make(map[string]common.Address)
	var AddressHash []string
	for _, each := range BlsInfo.AddressList {
		hashval := append(chainhash[:], each.Bytes()...)
		interresult := bls.RandFromBytes(hashval)
		myresult := interresult.DerivedRand(buf)
		tmp = Hex(myresult.Bytes())
		Addressmap[tmp] = each
		AddressHash = append(AddressHash, tmp)
	}
	sort.Strings(AddressHash)
	return AddressHash, Addressmap
}