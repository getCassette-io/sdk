package tokens

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSessionSignature(t *testing.T) {
	const b64TokenSignedData = `"ChCoMPSx0AlIFpZ4318hpMOgGgwI5KUBEIClARiApQEiIQIxjdjJvQQ4tpS1hEPhROxyhhfcPAhgFEh88MBE1b+cijImCAEaIgogaZ9A70l+T+S8nOyu8nhxUz8S+5Dd2KerJ5ruxoB6Elw="`
	const b64Token = `CmsKEKgw9LHQCUgWlnjfXyGkw6AaDAjkpQEQgKUBGIClASIhAjGN2Mm9BDi2lLWEQ+FE7HKGF9w8CGAUSHzwwETVv5yKMiYIARoiCiBpn0DvSX5P5Lyc7K7yeHFTPxL7kN3Yp6snmu7GgHoSXA==`
	//const b64Token = `CoIBChBydKT/Kb9EVIJuv/1hkSHeEhsKGTU401CScGlfaYFIRr1ZoDxro8IAvGoghp8aBggLEBYYISIhA51heSdua01e8WVTsWZl0KkMHKQtzFe7r9bQPTKVxj9VMiYIARoiCiCxrc3NkR8p8P9MF19Zs0OjeKmP/51cLUCroYxA4HnSeA==`
	const hexSig = "b8aca8f452c87401bc9f2aaa658a715d54b8cf4fa5e2b904c3894626329230a1fd8f9d789c105b935f10ff541d93284692fb03d61843e3f5b86ad2c24263376a" //"3d4adefd698ef4ba8be50abbc60be01fc9ce85e7d368585b805c75ba82974d7aa1c863730c6395b8fd0d881cc7ea5659a5138588f5aa76bcd9846efd3e006a47"
	const hexPubKey = "031ad3c83a6b1cbab8e19df996405cb6e18151a14f7ecd76eb4f51901db1426f0b"                                                            //"0382fcb005ae7652401fbe1d6345f77110f98db7122927df0f3faf3b62d1094071"
	const hexSalt = "531103313a65fb5b0284af637342772b"                                                                                                //"b1adb053cda9fd8ecaf8849e6a22678f"

	bSig, err := hex.DecodeString(hexSig)
	require.NoError(t, err)

	bPubKey, err := hex.DecodeString(hexPubKey)
	require.NoError(t, err)

	bSalt, err := hex.DecodeString(hexSalt)
	require.NoError(t, err)

	var pubKey neofsecdsa.PublicKeyWalletConnect
	require.NoError(t, pubKey.Decode(bPubKey))

	bToken, err := base64.StdEncoding.DecodeString(b64Token)
	require.NoError(t, err)

	var sessionToken session.Container
	require.NoError(t, sessionToken.Unmarshal(bToken))

	require.False(t, sessionToken.VerifySignature())
	s := neofscrypto.NewStaticSigner(neofscrypto.ECDSA_WALLETCONNECT, append(bSig, bSalt...), &pubKey)
	err = sessionToken.Sign(user.NewSigner(s, user.ResolveFromECDSAPublicKey(ecdsa.PublicKey(pubKey))))
	require.NoError(t, err)

	require.True(t, sessionToken.VerifySignature())
}
