// Command gg18fixtures emits JSON test vectors from the Go tss-lib so the Rust
// `ecdsatss` port can validate byte-for-byte / value-for-value compatibility.
//
// Big integers are emitted as decimal strings (the Rust loader parses them into
// BoxedUint). Run: `go run . > ../src/ecdsatss/testdata/gg18.json`
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/dlnproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

func s(n *big.Int) string { return n.String() }

type encVec struct {
	M, X, C string
}

func main() {
	out := map[string]any{}

	// --- bn vectors (validate gcd / jacobi / safe-prime vs Go math/big) ----
	gcds := []map[string]string{}
	for _, ab := range [][2]int64{{48, 36}, {17, 5}, {0, 9}, {1071, 462}} {
		a, b := big.NewInt(ab[0]), big.NewInt(ab[1])
		g := new(big.Int).GCD(nil, nil, a, b)
		gcds = append(gcds, map[string]string{"a": s(a), "b": s(b), "g": s(g)})
	}
	jacs := []map[string]any{}
	for _, an := range [][2]int64{{2, 15}, {7, 15}, {3, 15}, {1001, 9907}, {19, 45}} {
		a, n := big.NewInt(an[0]), big.NewInt(an[1])
		jacs = append(jacs, map[string]any{"a": s(a), "n": s(n), "j": big.Jacobi(a, n)})
	}
	out["bn"] = map[string]any{"gcd": gcds, "jacobi": jacs}

	// --- small Paillier key (fixed primes) for enc/dec/homo arithmetic -----
	P, Q := big.NewInt(107), big.NewInt(113)
	smallSK := mkSK(P, Q)
	smallPK := &smallSK.PublicKey
	var encs []encVec
	var ms []*big.Int
	var cs []*big.Int
	for _, mi := range []int64{0, 1, 42, 9000} {
		m := big.NewInt(mi)
		c, x, err := smallPK.EncryptAndReturnRandomness(rand.Reader, m)
		ck(err)
		encs = append(encs, encVec{M: s(m), X: s(x), C: s(c)})
		ms = append(ms, m)
		cs = append(cs, c)
	}
	// HomoAdd(enc(42), enc(9000)) decrypts to 9042.
	addC, err := smallPK.HomoAdd(cs[2], cs[3])
	ck(err)
	// HomoMult(7, enc(42)) decrypts to 294.
	multC, err := smallPK.HomoMult(big.NewInt(7), cs[2])
	ck(err)
	out["paillier_small"] = map[string]any{
		"n": s(smallPK.N), "p": s(P), "q": s(Q),
		"lambda": s(smallSK.LambdaN), "phi": s(smallSK.PhiN),
		"enc":       encs,
		"homo_add":  map[string]string{"c": s(addC), "m": s(big.NewInt(9042))},
		"homo_mult": map[string]string{"c": s(multC), "m": s(big.NewInt(294))},
	}

	// --- real Paillier key + proof (small-factor-free N, proof verifies) ---
	realSK, realPK, err := paillier.GenerateKeyPair(context.Background(), rand.Reader, 1024)
	ck(err)
	d := big.NewInt(0).SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x9a})
	ecdsaPub := crypto.ScalarBaseMult(tss.S256(), d)
	k := big.NewInt(0).SetBytes([]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03})
	pf, err := realSK.Proof(k, ecdsaPub)
	ck(err)
	ok, err := pf.Verify(realPK.N, k, ecdsaPub)
	ck(err)
	if !ok {
		panic("self-check: Go proof did not verify")
	}
	pis := make([]string, len(pf))
	for i, v := range pf {
		pis[i] = s(v)
	}
	out["paillier_proof"] = map[string]any{
		"n": s(realPK.N), "p": s(realSK.P), "q": s(realSK.Q),
		"k": s(k), "ecdsa_x": s(ecdsaPub.X()), "ecdsa_y": s(ecdsaPub.Y()),
		"pi": pis,
	}

	// --- DLN proof. NTilde = safeP·safeQ with safeP=2p'+1; the QR group has
	// order p'·q', so NewDLNProof takes the Sophie-Germain primes (p', q'). ---
	pp, safeP := sophieGermain(256)
	qp, safeQ := sophieGermain(256)
	ntilde := new(big.Int).Mul(safeP, safeQ)
	ord := new(big.Int).Mul(pp, qp) // QR-subgroup order
	// h1 = f^2 mod NTilde (a quadratic residue); x random < ord; h2 = h1^x.
	f, _ := rand.Int(rand.Reader, ntilde)
	h1 := new(big.Int).Exp(f, big.NewInt(2), ntilde)
	x, _ := rand.Int(rand.Reader, ord)
	h2 := new(big.Int).Exp(h1, x, ntilde)
	dln := dlnproof.NewDLNProof(h1, h2, x, pp, qp, ntilde, rand.Reader)
	if !dln.Verify(h1, h2, ntilde) {
		panic("self-check: Go DLN proof did not verify")
	}
	alphas := make([]string, dlnproof.Iterations)
	ts := make([]string, dlnproof.Iterations)
	for i := 0; i < dlnproof.Iterations; i++ {
		alphas[i] = s(dln.Alpha[i])
		ts[i] = s(dln.T[i])
	}
	out["dlnproof"] = map[string]any{
		"ntilde": s(ntilde), "h1": s(h1), "h2": s(h2),
		"alpha": alphas, "t": ts,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	ck(enc.Encode(out))
}

func genPrime(bits int) *big.Int {
	p, err := rand.Prime(rand.Reader, bits)
	ck(err)
	return p
}

// sophieGermain returns (p', 2p'+1) where both are prime.
func sophieGermain(bits int) (pp, safe *big.Int) {
	for {
		pp = genPrime(bits)
		safe = new(big.Int).Add(new(big.Int).Lsh(pp, 1), big.NewInt(1))
		if safe.ProbablyPrime(20) {
			return
		}
	}
}

func mkSK(P, Q *big.Int) *paillier.PrivateKey {
	N := new(big.Int).Mul(P, Q)
	pm1 := new(big.Int).Sub(P, big.NewInt(1))
	qm1 := new(big.Int).Sub(Q, big.NewInt(1))
	phi := new(big.Int).Mul(pm1, qm1)
	g := new(big.Int).GCD(nil, nil, pm1, qm1)
	lambda := new(big.Int).Div(phi, g)
	return &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{N: N},
		LambdaN:   lambda, PhiN: phi, P: P, Q: Q,
	}
}

func ck(err error) {
	if err != nil {
		panic(err)
	}
}
