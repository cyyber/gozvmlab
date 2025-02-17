package fuzzing

import (
	"math/big"

	"github.com/theQRL/go-zond/common"
)

func fillBlake(gst *GstMaker, fork string) {
	// Add a contract which calls blake
	dest, err := common.NewAddressFromString("Z00000000000000000000000000000ca1100b1a7e")
	if err != nil {
		panic(err)
	}
	gst.AddAccount(dest, GenesisAccount{
		Code:    RandCallBlake(),
		Balance: new(big.Int),
		Storage: make(map[common.Hash]common.Hash),
	})
	// The transaction
	gst.SetTx(&StTransaction{
		// 8M gaslimit
		GasLimit:   []uint64{8000000},
		Value:      []string{randHex(4)},
		Data:       []string{randHex(100)},
		GasPrice:   big.NewInt(0x10),
		To:         dest.Hex(),
		Sender:     sender,
		PrivateKey: pKey,
	})
}
