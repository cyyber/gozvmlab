// Copyright 2019 Martin Holst Swende, Hubert Ritzdorf
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

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/theQRL/go-zond/common"
	"github.com/theQRL/go-zond/core"
	"github.com/theQRL/go-zond/core/rawdb"
	"github.com/theQRL/go-zond/core/state"
	"github.com/theQRL/go-zond/core/vm"
	"github.com/theQRL/go-zond/core/vm/runtime"
	"github.com/theQRL/go-zond/params"
	common2 "github.com/theQRL/gozvmlab/common"
	"github.com/theQRL/gozvmlab/ops"
	"github.com/theQRL/gozvmlab/program"
)

func main() {

	if err := program.RunProgram(runit); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runit() error {
	a := program.NewProgram()

	aAddr, _ := common.NewAddressFromString("Z000000000000000000000000000000000000ff0a")
	bAddr, _ := common.NewAddressFromString("Z000000000000000000000000000000000000ff0b")

	// Callling contract : call contract B, modify storage, revert
	a.DelegateCall(nil, 0xff0b, 0, 0, 0, 0)
	aBytes := a.Bytecode()
	fmt.Printf("A: %x\n", aBytes)
	b := program.NewProgram()
	b.Op(ops.CALLVALUE)
	b.Op(ops.ISZERO)
	bBytes := b.Bytecode()

	alloc := make(core.GenesisAlloc)
	alloc[aAddr] = core.GenesisAccount{
		Nonce:   0,
		Code:    a.Bytecode(),
		Balance: big.NewInt(0xffffffff),
	}
	alloc[bAddr] = core.GenesisAccount{
		Nonce:   0,
		Code:    bBytes,
		Balance: big.NewInt(0),
	}

	//-------------

	outp, err := json.MarshalIndent(alloc, "", " ")
	if err != nil {
		fmt.Printf("error : %v", err)
		os.Exit(1)
	}
	fmt.Printf("output \n%v\n", string(outp))
	//----------
	var (
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		sender     = common.BytesToAddress([]byte("sender"))
	)
	for addr, acc := range alloc {
		statedb.CreateAccount(addr)
		statedb.SetCode(addr, acc.Code)
		statedb.SetNonce(addr, acc.Nonce)
		if acc.Balance != nil {
			statedb.SetBalance(addr, acc.Balance)
		}

	}
	statedb.CreateAccount(sender)
	// TODO(rgeraldes24)
	// statedb.SetBalance(sender, uint256.NewInt(0xfffffffffffffff))

	runtimeConfig := runtime.Config{
		Value:       big.NewInt(0x1337),
		Origin:      sender,
		State:       statedb,
		GasLimit:    10000000,
		BlockNumber: new(big.Int).SetUint64(1),
		ChainConfig: &params.ChainConfig{
			ChainID: big.NewInt(1),
		},
		ZVMConfig: vm.Config{
			Tracer: &common2.PrintingTracer{},
		},
	}
	// Run with tracing
	_, _, _ = runtime.Call(aAddr, nil, &runtimeConfig)
	// Diagnose it
	runtimeConfig.ZVMConfig = vm.Config{}
	t0 := time.Now()
	_, _, err = runtime.Call(aAddr, nil, &runtimeConfig)
	t1 := time.Since(t0)
	fmt.Printf("Time elapsed: %v\n", t1)
	return err
}
