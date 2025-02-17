// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package fuzzing

import (
	"encoding/json"
	"math/big"

	"github.com/theQRL/go-zond/common"
	"github.com/theQRL/go-zond/common/hexutil"
	"github.com/theQRL/go-zond/common/math"
)

var _ = (*stTransactionMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (s StTransaction) MarshalJSON() ([]byte, error) {
	type StTransaction struct {
		GasPrice   *math.HexOrDecimal256 `json:"gasPrice"`
		Nonce      math.HexOrDecimal64   `json:"nonce"`
		To         string                `json:"to"`
		Data       []string              `json:"data"`
		GasLimit   []math.HexOrDecimal64 `json:"gasLimit"`
		Value      []string              `json:"value"`
		Sender     common.Address        `json:"sender"`
		PrivateKey hexutil.Bytes         `json:"secretKey"`
	}
	var enc StTransaction
	enc.GasPrice = (*math.HexOrDecimal256)(s.GasPrice)
	enc.Nonce = math.HexOrDecimal64(s.Nonce)
	enc.To = s.To
	enc.Data = s.Data
	if s.GasLimit != nil {
		enc.GasLimit = make([]math.HexOrDecimal64, len(s.GasLimit))
		for k, v := range s.GasLimit {
			enc.GasLimit[k] = math.HexOrDecimal64(v)
		}
	}
	enc.Value = s.Value
	enc.Sender = s.Sender
	enc.PrivateKey = s.PrivateKey
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (s *StTransaction) UnmarshalJSON(input []byte) error {
	type StTransaction struct {
		GasPrice   *math.HexOrDecimal256 `json:"gasPrice"`
		Nonce      *math.HexOrDecimal64  `json:"nonce"`
		To         *string               `json:"to"`
		Data       []string              `json:"data"`
		GasLimit   []math.HexOrDecimal64 `json:"gasLimit"`
		Value      []string              `json:"value"`
		Sender     *common.Address       `json:"sender"`
		PrivateKey *hexutil.Bytes        `json:"secretKey"`
	}
	var dec StTransaction
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.GasPrice != nil {
		s.GasPrice = (*big.Int)(dec.GasPrice)
	}
	if dec.Nonce != nil {
		s.Nonce = uint64(*dec.Nonce)
	}
	if dec.To != nil {
		s.To = *dec.To
	}
	if dec.Data != nil {
		s.Data = dec.Data
	}
	if dec.GasLimit != nil {
		s.GasLimit = make([]uint64, len(dec.GasLimit))
		for k, v := range dec.GasLimit {
			s.GasLimit[k] = uint64(v)
		}
	}
	if dec.Value != nil {
		s.Value = dec.Value
	}
	if dec.Sender != nil {
		s.Sender = *dec.Sender
	}
	if dec.PrivateKey != nil {
		s.PrivateKey = *dec.PrivateKey
	}
	return nil
}
