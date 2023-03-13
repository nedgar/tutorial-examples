package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	merkletree "github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

func main() {

	fmt.Println("Create issuer identity...")

	// 1. BabyJubJub key

	// generate babyJubjub private key randomly
	babyJubjubPrivKey := babyjub.NewRandPrivKey()

	// generate public key from private key
	babyJubjubPubKey := babyJubjubPrivKey.Public()

	// print public key
	fmt.Println("BJJ public key:", babyJubjubPubKey)

	// 2. Sparse Merkle Tree

	ctx := context.Background()

	// Tree storage
	// store := memory.NewMemoryStorage()
 
	// // Generate a new MerkleTree with 32 levels
	// mt, _ := merkletree.NewMerkleTree(ctx, store, 32)
 
	// // Add a leaf to the tree with index 1 and value 10
	// index1 := big.NewInt(1)
	// value1 := big.NewInt(10)
	// mt.Add(ctx, index1, value1)
 
	// // Add another leaf to the tree
	// index2 := big.NewInt(2)
	// value2 := big.NewInt(15)
	// mt.Add(ctx, index2, value2)
 
	// // Proof of membership of a leaf with index 1
	// proofExist, value, _ := mt.GenerateProof(ctx, index1, mt.Root())
 
	// fmt.Println("Proof of membership of index=1:", proofExist.Existence, ", siblings:", proofExist.AllSiblings())
	// fmt.Println("Value corresponding to the queried index:", value)
 
	// // Proof of non-membership of a leaf with index 4
	// proofNotExist, _, _ := mt.GenerateProof(ctx, big.NewInt(4), mt.Root())
 
	// fmt.Println("Proof of membership of missing index=4:", proofNotExist.Existence, ", siblings:", proofNotExist.AllSiblings())

	// 3.1. Create a Generic Claim

	fmt.Println()
	fmt.Println("Issuing age claim...")

	// set claim expiration date to 2361-03-21 12:25:21 UTC
	t := time.Date(2361, 3, 21, 12, 25, 21, 0, time.UTC)

	// set schema
	ageSchema, _ := core.NewSchemaHashFromHex("2e2d1c11ad3e500de68d7ce16a0a559e")

	// define data slots
	birthday := big.NewInt(19960424)
	documentType := big.NewInt(1)

	// set revocation nonce
	revocationNonce := uint64(1909830690)

	// set ID of the claim subject
	subjectId, _ := core.IDFromString("2qGKMXEQ53gNohAfxqYNPz6Kg1xYsBSN7ZQGG8tYMc") // from Nick's Polygon ID wallet

	// create claim
	claim, _ := core.NewClaim(ageSchema, core.WithExpirationDate(t), core.WithRevocationNonce(revocationNonce), core.WithIndexID(subjectId), core.WithIndexDataInts(birthday, documentType))

	// transform claim from bytes array to json
	claimToMarshal, _ := json.Marshal(claim)

	fmt.Println("Generic claim JSON:", string(claimToMarshal))
	// 3.2. Create Auth Claim

	// Add revocation nonce. Used to invalidate the claim. This may be a random number in the real implementation.
	revNonce := uint64(1)

	authClaim, _ := core.NewClaim(core.AuthSchemaHash,
		core.WithIndexDataInts(babyJubjubPubKey.X, babyJubjubPubKey.Y),
		core.WithRevocationNonce(revNonce))

	authClaimToMarshal, _ := json.Marshal(authClaim)

	fmt.Println("Auth claim JSON:", string(authClaimToMarshal))

	// 4.1. Generate identity trees

	// Create empty Claims tree
	clt, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)

	// Create empty Revocation tree
	ret, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)

	// Create empty Roots tree
	rot, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)

	// Get the Index of the claim and the Value of the authClaim
	hIndex, hValue, _ := authClaim.HiHv()

	// add auth claim to claims tree with value hValue at index hIndex
	clt.Add(ctx, hIndex, hValue)

	// print the roots
	fmt.Printf("Merkle tree roots -- claims: 0x%s, revocations: 0x%s, roots: 0x%s\n", clt.Root().BigInt(), ret.Root().BigInt(), rot.Root().BigInt())

	// 4.2. Retrieve identity state

	state, _ := merkletree.HashElems(
		clt.Root().BigInt(),
		ret.Root().BigInt(),
		rot.Root().BigInt())

	fmt.Println("Identity state (hash of tree roots): 0x", state.BigInt())

	// 4.3. Retrieve Identifier (ID)

	id, _ := core.IdGenesisFromIdenState(core.TypeDefault, state.BigInt())

	fmt.Println("ID:", id)
	fmt.Println("as int:", id.BigInt())

	// 5. Issuing Claim by Signature

	// Retrieve indexHash and valueHash of the claim
	indexHash, valueHash, _ := claim.HiHv()

	// Poseidon Hash the indexHash and the valueHash together to get the claimHash
	claimHash, _ := merkletree.HashElems(indexHash, valueHash)
	fmt.Println("Claim hash:", claimHash.Hex())

	// Sign the claimHash with the private key of the issuer
	claimSignature := babyJubjubPrivKey.SignPoseidon(claimHash.BigInt())

	fmt.Printf("Claim signature R8.x: %s, R8.y: %s, S: %s\n", claimSignature.R8.X, claimSignature.R8.Y, claimSignature.S)

	// // 6. Issuing Claim by adding it to the Merkle Tree
 
	// // GENESIS STATE:
 
	// // 1. Generate Merkle Tree Proof for authClaim at Genesis State
	// authMTPProof, _, _ := clt.GenerateProof(ctx, hIndex, nil)

	// // 2. Generate the Non-Revocation Merkle tree proof for the authClaim at Genesis State
	// authNonRevMTPProof, _, _ := ret.GenerateProof(ctx, new(big.Int).SetUint64(revNonce), nil)

	// // Snapshot of the Genesis State
	// genesisTreeState := circuits.TreeState{
	// 	State:          state,
	// 	ClaimsRoot:     clt.Root(),
	// 	RevocationRoot: ret.Root(),
	// 	RootOfRoots:    rot.Root(),
	// }

	// // STATE 1:

	// // Before updating the claims tree, add the claims tree root at Genesis state to the Roots tree.
	// rot.Add(ctx, clt.Root().BigInt(), big.NewInt(0))

	// // Get hash Index and hash Value of the new claim
	// hi, hv, _ := claim.HiHv()

	// // Add claim to the Claims tree
	// clt.Add(ctx, hi, hv)

	// // Fetch the new Identity State
	// newState, _ := merkletree.HashElems(
	// 	clt.Root().BigInt(),
	// 	ret.Root().BigInt(),
	// 	rot.Root().BigInt())

	// // Snapshot of the new tree State
	// newTreeState := circuits.TreeState{
	// 	State:          newState,
	// 	ClaimsRoot:     clt.Root(),
	// 	RevocationRoot: ret.Root(),
	// 	RootOfRoots:    rot.Root(),
	// }

	// // Sign a message (hash of the genesis state + the new state) using your private key
	// hashOldAndNewStates, _ := poseidon.Hash([]*big.Int{state.BigInt(), newState.BigInt()})

	// signature := babyJubjubPrivKey.SignPoseidon(hashOldAndNewStates)

	// authClaimNewStateIncMtp, _, _ := clt.GenerateProof(ctx, hIndex, newTreeState.ClaimsRoot)

	// // Generate state transition inputs
	// stateTransitionInputs := circuits.StateTransitionInputs{
	// 	ID:                      id,
	// 	OldTreeState:            genesisTreeState,
	// 	NewTreeState:            newTreeState,
	// 	IsOldStateGenesis:       true,
	// 	AuthClaim:               authClaim,
	// 	AuthClaimIncMtp:         authMTPProof,
	// 	AuthClaimNonRevMtp:      authNonRevMTPProof,
	// 	AuthClaimNewStateIncMtp: authClaimNewStateIncMtp,
	// 	Signature:               signature,
	// }

	// // Perform marshalling of the state transition inputs
	// inputBytes, _ := stateTransitionInputs.InputsMarshal()

	// fmt.Println(string(inputBytes))
}
