package blscgo

import (
	"testing"
	"strconv"
	"go-unitcoin/libraries/common"
)

func Test_Pop(t *testing.T) {
	err := Init(CurveFp382_2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("testPop")
	var sec SecretKey
	sec.SetByCSPRNG()
	pop := sec.GetPop()
	if !pop.VerifyPop(sec.GetPublicKey()) {
		t.Errorf("Valid Pop does not verify")
	}

	sec.SetByCSPRNG()
	if pop.VerifyPop(sec.GetPublicKey()) {
		t.Errorf("Invalid Pop verifies")
	}
}

func Test_AustoGroup(t *testing.T) {
	//members := []common.Address{common.StringToAddress("1")}

}

func Test_Group(t *testing.T) {
	err := Init(CurveFp382_2)
	if err != nil {
		t.Fatal(err)
	}

	var sec1, sec2, sec3 SecretKey
	sec1.SetHexString(common.StringToAddress("51").Hex())
	sec2.SetHexString(common.StringToAddress("105").Hex())
	sec3.SetHexString(common.StringToAddress("13").Hex())

	sec1.SetByCSPRNG()
	sec2.SetByCSPRNG()
	sec3.SetByCSPRNG()


	msk1 := sec1.GetMasterSecretKey(2)
	mpk1 := GetMasterPublicKey(msk1)
	idVec1 := make([]ID, 3)
	secVec1 := make([]SecretKey, 3)
	pubVec1 := make([]PublicKey, 3)

	idVec1[0].SetHexString(strconv.FormatInt(int64(1), 10))
	secVec1[0].Set(msk1, &idVec1[0])
	pubVec1[0].Set(mpk1, &idVec1[0])

	idVec1[1].SetHexString(strconv.FormatInt(int64(2), 10))
	secVec1[1].Set(msk1, &idVec1[1])
	pubVec1[1].Set(mpk1, &idVec1[1])

	idVec1[2].SetHexString(strconv.FormatInt(int64(3), 10))
	secVec1[2].Set(msk1, &idVec1[2])
	pubVec1[2].Set(mpk1, &idVec1[2])

	msk2 := sec2.GetMasterSecretKey(2)
	mpk2 := GetMasterPublicKey(msk2)
	idVec2 := make([]ID, 3)
	secVec2 := make([]SecretKey, 3)
	pubVec2 := make([]PublicKey, 3)

	idVec2[0].SetHexString(strconv.FormatInt(int64(2), 10))
	secVec2[0].Set(msk2, &idVec2[0])
	pubVec2[0].Set(mpk2, &idVec2[0])

	idVec2[1].SetHexString(strconv.FormatInt(int64(1), 10))
	secVec2[1].Set(msk2, &idVec2[1])
	pubVec2[1].Set(mpk2, &idVec2[1])

	idVec2[2].SetHexString(strconv.FormatInt(int64(3), 10))
	secVec2[2].Set(msk2, &idVec2[2])
	pubVec2[2].Set(mpk2, &idVec2[2])


	msk3 := sec3.GetMasterSecretKey(2)
	mpk3 := GetMasterPublicKey(msk3)
	idVec3 := make([]ID, 3)
	secVec3 := make([]SecretKey, 3)
	pubVec3 := make([]PublicKey, 3)

	idVec3[0].SetHexString(strconv.FormatInt(int64(3), 10))
	secVec3[0].Set(msk3, &idVec3[0])
	pubVec3[0].Set(mpk3, &idVec3[0])

	idVec3[1].SetHexString(strconv.FormatInt(int64(1), 10))
	secVec3[1].Set(msk3, &idVec3[1])
	pubVec3[1].Set(mpk3, &idVec3[1])

	idVec3[2].SetHexString(strconv.FormatInt(int64(2), 10))
	secVec3[2].Set(msk3, &idVec3[2])
	pubVec3[2].Set(mpk3, &idVec3[2])


	var gsec1 SecretKey
	var gpub1 PublicKey
	gsecVec1 := []SecretKey{secVec1[0], secVec2[1], secVec3[1]}
	gpubVec1 := []PublicKey{pubVec1[0], pubVec2[1], pubVec3[1]}
	gidVec1 := []ID{idVec1[0], idVec2[0], idVec3[0]}
	err = gsec1.Recover(gsecVec1, gidVec1)
	if err!=nil {
		t.Log(err)
	}
	t.Log("gsec1:", gsec1.GetHexString())
	err = gpub1.Recover(gpubVec1, gidVec1)
	if err!=nil {
		t.Log(err)
	}
	t.Log("gpub1:", gpub1.GetHexString())

	var gsec2 SecretKey
	var gpub2 PublicKey
	gsecVec2 := []SecretKey{secVec2[0], secVec1[1], secVec3[2]}
	gpubVec2 := []PublicKey{pubVec2[0], pubVec1[1], pubVec3[2]}
	gidVec2 := []ID{idVec2[0], idVec1[0], idVec3[0]}
	err = gsec2.Recover(gsecVec2, gidVec2)
	if err!=nil {
		t.Log(err)
	}
	t.Log("gsec2:", gsec2.GetHexString())
	err = gpub2.Recover(gpubVec2, gidVec2)
	if err!=nil {
		t.Log(err)
	}
	t.Log("gpub2:", gpub2.GetHexString())

	var gsec3 SecretKey
	var gpub3 PublicKey
	gsecVec3 := []SecretKey{secVec3[0], secVec1[2], secVec2[2]}
	gpubVec3 := []PublicKey{pubVec3[0], pubVec1[2], pubVec2[2]}
	gidVec3 := []ID{idVec3[0], idVec1[0], idVec2[0]}
	err = gsec3.Recover(gsecVec3, gidVec3)
	if err!=nil {
		t.Log(err)
	}
	t.Log("gsec3:", gsec3.GetHexString())
	err = gpub3.Recover(gpubVec3, gidVec3)
	if err!=nil {
		t.Log(err)
	}
	t.Log("gpub3:", gsec3.GetHexString())

	msg := "Hello"
	sign1 := gsec1.Sign(msg)
	sign3 := gsec3.Sign(msg)
	var sign Sign
	err = sign.Recover([]Sign{*sign1, *sign3}, []ID{idVec1[0], idVec3[0]})
	if err!=nil {
		t.Log(err)
	}

	var gpub PublicKey
	var gsec SecretKey
	err = gpub.Recover([]PublicKey{*sec1.GetPublicKey(), *sec2.GetPublicKey(), *sec3.GetPublicKey()}, []ID{idVec1[0], idVec2[0], idVec3[0]})
	if err!=nil {
		t.Log(err)
	}
	t.Log("gpubKey:", gpub.GetHexString())

	err = gsec.Recover([]SecretKey{sec1, sec2, sec3}, []ID{idVec1[0], idVec2[0], idVec3[0]})
	if err!=nil {
		t.Log(err)
	}
	t.Log("gsecKey:", gsec.GetHexString())

	t.Log(sign.Verify(&gpub, msg), sign.GetHexString())
	gsign := gsec.Sign(msg)
	t.Log(gsign.Verify(&gpub, msg), gsign.GetHexString())

	var csec SecretKey
	var cpub PublicKey
	err = csec.Recover([]SecretKey{gsec1, gsec3}, []ID{idVec1[0], idVec3[0]})
	if err!=nil {
		t.Log(err)
	}
	t.Log("csecKey:", csec.GetHexString())
	err = cpub.Recover([]PublicKey{gpub1, gpub3}, []ID{idVec1[0], idVec3[0]})
	if err!=nil {
		t.Log(err)
	}
	t.Log("cpubKey:", cpub.GetHexString())
}
