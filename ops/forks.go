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

package ops

import (
	"fmt"
	"math/big"

	"github.com/theQRL/go-zond/common"
	"github.com/theQRL/go-zond/params"
)

type Fork struct {
	Name              string
	ValidOpcodes      []OpCode
	ActivePrecompiles []common.Address
}

var (
	shanghai = Fork{
		Name:              "Shanghai",
		ActivePrecompiles: nil,
		ValidOpcodes: []OpCode{
			STOP, ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND,
			LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR,
			KECCAK256,
			ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE, EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY, EXTCODEHASH, BLOCKHASH,
			COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE,
			POP, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, JUMP, JUMPI, PC, MSIZE, GAS, JUMPDEST,
			PUSH0, // New for Shanghai
			PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8, PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16,
			PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24, PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32,
			DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8, DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16,
			SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8, SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16,
			LOG0, LOG1, LOG2, LOG3, LOG4,
			CREATE, CALL, RETURN, DELEGATECALL, CREATE2, STATICCALL, REVERT, INVALID},
	}
	forks = []Fork{
		shanghai,
	}
)

// ValidOpcodesInFork returns the set of valid opcodes for the given fork, or
// error if the fork is not defined.
func ValidOpcodesInFork(fork string) ([]OpCode, error) {
	for _, f := range forks {
		if f.Name == fork {
			return f.ValidOpcodes, nil
		}
	}
	return nil, fmt.Errorf("fork %v not defined", fork)
}

// RandomOp returns a random (valid) opcode
func (f Fork) RandomOp(rnd byte) OpCode {
	return f.ValidOpcodes[int(rnd)%len(f.ValidOpcodes)]
}

func LookupFork(fork string) *Fork {
	for _, f := range forks {
		if f.Name == fork {
			return &f
		}
	}
	return nil
}

func LookupRules(fork string) params.Rules {
	switch fork {
	case "Shanghai":
		return params.Rules{}
	default:
		panic(fmt.Sprintf("Unsupported: %v", fork))

	}
}

// LookupChainConfig returns the params.ChainConfig for a given fork.
func LookupChainConfig(fork string) (*params.ChainConfig, error) {
	var shanghai = &params.ChainConfig{
		ChainID: big.NewInt(1),
	}

	switch fork {
	case "Shanghai":
		return shanghai, nil
	}
	return nil, fmt.Errorf("unknown fork %v", fork)
}
