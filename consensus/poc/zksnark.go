package poc

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/arnaucube/go-snark"
	"github.com/arnaucube/go-snark/circuitcompiler"
	"github.com/arnaucube/go-snark/groth16"
	"github.com/arnaucube/go-snark/r1csqap"
	"github.com/stretchr/testify/assert"
)

func Groth16MinimalFlowGenProof(t *testing.T, code string, privateIn int64, publicSig int64, para ...interface{}) (groth16.Proof, error) {
	// circuit function
	// y = x^3 + x + 5
	//code := `
	//func main(private s0, public s1):
	//	s2 = s0 * s0
	//	s3 = s2 * s0
	//	s4 = s3 + s0
	//	s5 = s4 + 5
	//	equals(s1, s5)
	//	out = 1 * 1
	//`
	assert := assert.New(t)
	fmt.Print("\ncode of the circuit:")

	// parse the code
	parser := circuitcompiler.NewParser(strings.NewReader(code))
	circuit, err := parser.Parse()
	assert.Nil(err)

	b3 := big.NewInt(privateIn)
	privateInputs := []*big.Int{b3}
	b35 := big.NewInt(publicSig)
	publicSignals := []*big.Int{b35}

	// wittness
	w, err := circuit.CalculateWitness(privateInputs, publicSignals)
	assert.Nil(err)

	// code to R1CS
	fmt.Println("\ngenerating R1CS from code")
	a, b, c := circuit.GenerateR1CS()
	fmt.Println("\nR1CS:")
	fmt.Println("a:", a)
	fmt.Println("b:", b)
	fmt.Println("c:", c)

	// R1CS to QAP
	// TODO zxQAP is not used and is an old impl, TODO remove
	alphas, betas, gammas, _ := snark.Utils.PF.R1CSToQAP(a, b, c)
	fmt.Println("qap")
	assert.Equal(8, len(alphas))
	assert.Equal(8, len(alphas))
	assert.Equal(8, len(alphas))
	assert.True(!bytes.Equal(alphas[1][1].Bytes(), big.NewInt(int64(0)).Bytes()))

	ax, bx, cx, px := snark.Utils.PF.CombinePolynomials(w, alphas, betas, gammas)
	assert.Equal(7, len(ax))
	assert.Equal(7, len(bx))
	assert.Equal(7, len(cx))
	assert.Equal(13, len(px))

	// ---
	// from here is the GROTH16
	// ---
	// calculate trusted setup
	fmt.Println("groth")
	setup, err := groth16.GenerateTrustedSetup(len(w), *circuit, alphas, betas, gammas)
	assert.Nil(err)
	fmt.Println("\nt:", setup.Toxic.T)

	hx := snark.Utils.PF.DivisorPolynomial(px, setup.Pk.Z)
	div, rem := snark.Utils.PF.Div(px, setup.Pk.Z)
	assert.Equal(hx, div)
	assert.Equal(rem, r1csqap.ArrayOfBigZeros(6))

	// hx==px/zx so px==hx*zx
	assert.Equal(px, snark.Utils.PF.Mul(hx, setup.Pk.Z))

	// check length of polynomials H(x) and Z(x)
	assert.Equal(len(hx), len(px)-len(setup.Pk.Z)+1)

	proof, err := groth16.GenerateProofs(*circuit, setup.Pk, w, px)
	assert.Nil(err)

	fmt.Println("\n proofs:")
	fmt.Println(proof)
	return proof, err
}

func Groth16MinimalFlowVerifProof(setupvk groth16.Vk, proof groth16.Proof, publicSig int64, para ...interface{}) bool {
	b35Verif := big.NewInt(publicSig)
	publicSignalsVerif := []*big.Int{b35Verif}
	before := time.Now()
	ispass := groth16.VerifyProof(setupvk, proof, publicSignalsVerif, true)
	fmt.Println("verify proof time elapsed:", time.Since(before))
	return ispass
}