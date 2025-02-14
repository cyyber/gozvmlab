// Copyright Martin Holst Swende
// This file is part of the goevmlab library.
//
// The library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the goevmlab library. If not, see <http://www.gnu.org/licenses/>.

package fuzzing

import (
	"math/big"

	"github.com/theQRL/go-zond/common"
	"github.com/theQRL/go-zond/common/hexutil"
)

func address(addr string) common.Address {
	a, _ := common.NewAddressFromString(addr)
	return a
}

func fillSstore(gst *GstMaker, fork string) {
	// The accounts which we want to be able to invoke
	addrs := []common.Address{
		address("Z00000000000000000000000000000000000000F1"),
		address("Z00000000000000000000000000000000000000F2"),
		address("Z00000000000000000000000000000000000000F3"),
		address("Z00000000000000000000000000000000000000F4"),
		address("Z00000000000000000000000000000000000000F5"),
		address("Z00000000000000000000000000000000000000F6"),
		address("Z00000000000000000000000000000000000000F7"),
		address("Z00000000000000000000000000000000000000F8"),
		address("Z00000000000000000000000000000000000000F9"),
		address("Z00000000000000000000000000000000000000FA"),
	}
	nonGenesisAddresses := []common.Address{
		address("Z0000000000000000000000000000000000000000"),
		address("Z0000000000000000000000000000000000000001"),
		address("Z0000000000000000000000000000000000000002"),
		address("Z0000000000000000000000000000000000000003"),
		address("Z0000000000000000000000000000000000000004"),
		address("Z0000000000000000000000000000000000000005"),
		address("Z0000000000000000000000000000000000000006"),
		address("Z0000000000000000000000000000000000000007"),
		address("Z0000000000000000000000000000000000000008"),
		address("Z0000000000000000000000000000000000000009"),
		address("Z000000000000000000000000000000000000000A"),
		address("Z000000000000000000000000000000000000000B"),
		address("Z000000000000000000000000000000000000000C"),
		address("Z000000000000000000000000000000000000000D"),
		address("Z000000000000000000000000000000000000000E"),
	}
	var allAddrs []common.Address
	allAddrs = append(allAddrs, addrs...)
	allAddrs = append(allAddrs, nonGenesisAddresses...)
	// make them exist in the state
	for _, addr := range nonGenesisAddresses {
		gst.AddAccount(addr, GenesisAccount{
			Balance: new(big.Int).SetUint64(1),
			Storage: make(map[common.Hash]common.Hash),
		})
	}
	for _, addr := range addrs {
		gst.AddAccount(addr, GenesisAccount{
			Code:    RandCall2200(allAddrs),
			Balance: new(big.Int),
			Storage: RandStorage(15, 20),
		})
	}
	// The transaction
	{
		tx := &StTransaction{
			// 8M gaslimit
			GasLimit:   []uint64{8000000},
			Nonce:      0,
			Value:      []string{randHex(4)},
			Data:       []string{randHex(100)},
			GasPrice:   big.NewInt(0x10),
			To:         addrs[0].Hex(),
			Sender:     sender,
			PrivateKey: hexutil.MustDecode("0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"),
		}
		gst.SetTx(tx)
	}
}
