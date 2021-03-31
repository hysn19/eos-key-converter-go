package main

import (
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/op/go-logging"
	"golang.org/x/crypto/ripemd160"
)

var logger = logging.MustGetLogger("main.go")

func main() {
	// did document 에 들어갈 base58 pubkey, signature
	b58pubkey := "2BpopHoaibMjCNvUib1CNc74gMQBHjuNvcfcQkNMsy9YX"
	b58sig := "3qGQYmA53uc6N3v89nMTsAVZJLChCTaQMBCKnUpLxy1T6Ybtrb7wskFQLUKQJKaT3Y96c2icQSnd5QUfpNSnRLZT4"

	// eostype으로 데이터 변환
	eospubkey := genEOSPubkey(base58.Decode(b58pubkey))
	eossig := genEOSSignature(base58.Decode(b58sig))

	logger.Infof("eospubkey: %s\n", eospubkey)
	logger.Infof("eossig: %s\n", eossig)

	// base58 로 데이터 변환
	_b58pubkey := base58.Encode(genPubkey(eospubkey))
	_b58sig := base58.Encode(genSignature(eossig))

	logger.Infof("_b58pubkey: %s\n", _b58pubkey)
	logger.Infof("_b58sig: %s\n", _b58sig)
}

/**
 * b58pubkey >> eospubkey
 * 1. a : (설명) pubkey를 byte로 받는다.
 * 2. b : (설명) a를 ripemd160 hash하고 앞 4byte를 checksum으로 사용한다.
 * 3. c = base58.encode( a + b ) : (설명) pubkey byte + checksum byte를 붙여서 base58 encoding한다.
 * 4. d = "EOS" + c : (설명) prefix "EOS" 와 c를 합쳐 결과를 리턴한다.
 */
func genEOSPubkey(pubkey []byte) string {

	// ripemd160 hash to pubkey
	ripemd160 := ripemd160.New()
	ripemd160.Write(pubkey)
	hash := ripemd160.Sum(nil)

	// split 4bytes of hash data
	checksum := hash[0:4]

	// append pubkey, checksum
	data := append(pubkey, []byte(checksum)...)

	return "EOS" + base58.Encode(data)
}

/**
 * b58signature >> eossignature
 * 1. a : (설명) signature를 byte로 받는다.
 * 2. b : (설명) signature를 byte와 "K1" string byte를 붙인다.
 * 3. c : (설명) b를 ripemd160 hash하고 앞 4byte를 checksum으로 사용한다.
 * 4. d = base58.encode( a + c ) : (설명) signature byte + checksum byte를 붙여서 base58 encoding한다.
 * 5. e = "SIG_K1_" + d : (설명) prefix "SIG_K1_" d를 합쳐 결과를 리턴한다.
 */
func genEOSSignature(signature []byte) string {

	bData := append(signature, []byte("K1")...)

	// ripemd160 hash to pubkey
	ripemd160 := ripemd160.New()
	ripemd160.Write(bData)
	hash := ripemd160.Sum(nil)

	// split 4bytes of hash data
	checksum := hash[0:4]

	// append signature, checksum
	data := append(signature, []byte(checksum)...)

	return "SIG_K1_" + base58.Encode(data)
}

/**
 * eospubkey >> b58pubkey : genEOSPubkey reverse
 */
func genPubkey(pubkey string) []byte {

	// "EOS" prefix remove
	data := strings.TrimPrefix(pubkey, "EOS")

	// base58.decode
	bs := base58.Decode(data)

	// return after last 4bit remove
	return bs[0 : len(bs)-4]
}

/**
 * eossignature >> b58signature: genEOSSignature reverse
 */
func genSignature(sig string) []byte {

	// "SIG_K1_" prefix remove
	data := strings.TrimPrefix(sig, "SIG_K1_")

	// base58.decode
	bs := base58.Decode(data)

	// return after last 4bit remove
	return bs[0 : len(bs)-4]
}
