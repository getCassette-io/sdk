package wallet

import (
	"fmt"
	"math"
	"math/big"
)

func ConvertToBigInt(amount float64, decimals int) (*big.Int, error) {
	if decimals < 0 {
		return nil, fmt.Errorf("invalid decimals: %d", decimals)
	}

	// Multiply the amount by 10^decimals
	multiplier := math.Pow(10, float64(decimals))
	bigAmount := new(big.Float).Mul(big.NewFloat(amount), big.NewFloat(multiplier))

	// Convert the floating point number to big.Int
	result := new(big.Int)
	bigAmount.Int(result)

	return result, nil
}
