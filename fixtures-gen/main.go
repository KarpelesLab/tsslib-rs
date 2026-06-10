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
	"github.com/KarpelesLab/tss-lib/v2/crypto/facproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/modproof"
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
	realSK, realPK, err := paillier.GenerateKeyPair(context.Background(), rand.Reader, 2048)
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

	// --- facproof (N0 = product of two primes), against ring-Pedersen
	// (NCap=ntilde, s=h1, t=h2). N0/N0p/N0q reuse the real Paillier key. -----
	session := []byte("ecdsatss-fixture-session")
	fac, err := facproof.NewProof(session, tss.S256(), realPK.N, ntilde, h1, h2, realSK.P, realSK.Q, rand.Reader)
	ck(err)
	facBz := fac.Bytes()
	fac2, err := facproof.NewProofFromBytes(facBz[:])
	ck(err)
	if !fac2.Verify(session, tss.S256(), realPK.N, ntilde, h1, h2) {
		panic("self-check: Go facproof byte-roundtrip did not verify")
	}
	out["facproof"] = map[string]any{
		"session": "ecdsatss-fixture-session",
		"n0":      s(realPK.N), "ncap": s(ntilde), "s": s(h1), "t": s(h2),
		"v_sign": fac.V.Sign(),
		"P":      s(fac.P), "Q": s(fac.Q), "A": s(fac.A), "B": s(fac.B),
		"T": s(fac.T), "Sigma": s(fac.Sigma), "Z1": s(fac.Z1), "Z2": s(fac.Z2),
		"W1": s(fac.W1), "W2": s(fac.W2), "V": s(fac.V),
	}

	// --- modproof (N = P·Q Blum integer, P,Q ≡ 3 mod 4) -------------------
	mp1 := blumPrime(512)
	mq1 := blumPrime(512)
	modN := new(big.Int).Mul(mp1, mq1)
	mProof, err := modproof.NewProof(session, modN, mp1, mq1, rand.Reader)
	ck(err)
	if !mProof.Verify(session, modN) {
		panic("self-check: Go modproof did not verify")
	}
	mxs := make([]string, modproof.Iterations)
	mzs := make([]string, modproof.Iterations)
	for i := 0; i < modproof.Iterations; i++ {
		mxs[i] = s(mProof.X[i])
		mzs[i] = s(mProof.Z[i])
	}
	out["modproof"] = map[string]any{
		"session": "ecdsatss-fixture-session",
		"n":       s(modN), "p": s(mp1), "q": s(mq1),
		"W": s(mProof.W), "A": s(mProof.A), "B": s(mProof.B),
		"X": mxs, "Z": mzs,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	ck(enc.Encode(out))
}

// blumPrime returns a prime ≡ 3 (mod 4).
func blumPrime(bits int) *big.Int {
	for {
		p := genPrime(bits)
		if new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 {
			return p
		}
	}
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
