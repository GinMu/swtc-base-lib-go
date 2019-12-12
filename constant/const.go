package constant

import "github.com/mr-tron/base58"

// SWTCAccountPrefix definition
const SWTCAccountPrefix uint8 = 0

// SWTCSeedfix definition
const SWTCSeedfix uint8 = 33

// SWTCAlphabet definition
var SWTCAlphabet *base58.Alphabet

func init() {
	SWTCAlphabet = base58.NewAlphabet("jpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65rkm8oFqi1tuvAxyz")
}
