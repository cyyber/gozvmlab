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
	a.Call(nil, 0xff0b, 1, 0, 0, 0, 0)
	// Call it again, send 1 wei to signal no revert
	a.Call(nil, 0xff0b, 0, 0, 0, 0, 0)
	aBytes := a.Bytecode()
	fmt.Printf("A: %x\n", aBytes)
	b := program.NewProgram()

	b.Op(ops.CALLVALUE)
	b.Op(ops.ISZERO)
	b.Push(1) // placeholder
	b.Op(ops.JUMPI)
	// Path A
	b.Sstore(0, 2)
	b.Op(0xFE)
	// Path B
	label := b.Jumpdest()
	fmt.Printf("label: %d\n", label)
	b.Sstore(0, 1)

	bBytes := b.Bytecode()
	bBytes[3] = byte(label)

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

	runtimeConfig := runtime.Config{
		Origin:      sender,
		State:       statedb,
		GasLimit:    10000000,
		BlockNumber: new(big.Int).SetUint64(1),
		ChainConfig: &params.ChainConfig{
			ChainID: big.NewInt(1),
		},
		ZVMConfig: vm.Config{
			Tracer: &dumbTracer{},
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

type dumbTracer struct {
	common2.BasicTracer
	counter uint64
}

func (d *dumbTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if op == vm.STATICCALL {
		d.counter++
	}
	if op == vm.EXTCODESIZE {
		d.counter++
	}
}

func (d *dumbTracer) CaptureStart(env *vm.ZVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	fmt.Printf("captureStart\n")
	fmt.Printf("	from: %v\n", from.Hex())
	fmt.Printf("	to: %v\n", to.Hex())
}

func (d *dumbTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	fmt.Printf("\nCaptureEnd\n")
	fmt.Printf("Counter: %d\n", d.counter)
}
