package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// Function to generate the public key from a private key
func derivePublicKey(privKey *secp256k1.PrivateKey) *secp256k1.PublicKey {
	return privKey.PubKey()
}

// Function to compute the hash160 (RIPEMD-160 of SHA-256)
func hash160(data []byte) []byte {
	sha256Hash := sha256.New()
	sha256Hash.Write(data)
	sha256Digest := sha256Hash.Sum(nil)

	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(sha256Digest)
	return ripemd160Hash.Sum(nil)
}

// Function to generate the Bitcoin address from the public key
func publicKeyToAddress(pubKey *secp256k1.PublicKey) string {
	pubKeyBytes := pubKey.SerializeCompressed()
	pubKeyHash160 := hash160(pubKeyBytes)
	address := base58.CheckEncode(pubKeyHash160, 0x00) // Mainnet
	return address
}

// Function to generate the WIF key from a private key
func generateWIF(privKey *secp256k1.PrivateKey) (string, error) {
	privKeyBytes := privKey.Serialize()
	version := byte(0x80) // Mainnet
	compressed := append([]byte{version}, privKeyBytes...)
	compressed = append(compressed, 0x01)

	// Perform double SHA-256
	sha := sha256.New()
	sha.Write(compressed)
	checksum := sha.Sum(nil)
	sha.Reset()
	sha.Write(checksum)
	checksum = sha.Sum(nil)[:4]

	wif := append(compressed, checksum...)
	return base58.Encode(wif), nil
}

func main() {
	// Private key to debug
	privKeyHex := "000000000000000000000000000000000000000000000000000000000001764f"

	// Convert hex to bytes
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		log.Fatal(err)
	}

	// Generate private key from bytes
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	// Generate public key from private key
	pubKey := derivePublicKey(privKey)

	// Generate Bitcoin address from public key
	address := publicKeyToAddress(pubKey)

	// Generate WIF from private key
	wif, err := generateWIF(privKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Private Key: %s\n", privKeyHex)
	fmt.Printf("Public Key (Compressed): %x\n", pubKey.SerializeCompressed())
	fmt.Printf("Bitcoin Address: %s\n", address)
	fmt.Printf("WIF: %s\n", wif)

	// Compare with expected values
	expectedPubKey := "033f688bae8321b8e02b7e6c0a55c2515fb25ab97d85fda842449f7bfa04e128c3"
	expectedAddress := "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm"

	if hex.EncodeToString(pubKey.SerializeCompressed()) != expectedPubKey {
		fmt.Println("Public key does not match the expected value.")
	} else {
		fmt.Println("Public key matches the expected value.")
	}

	if address != expectedAddress {
		fmt.Println("Bitcoin address does not match the expected value.")
		// Additional debugging information
		pubKeyBytes := pubKey.SerializeCompressed()
		pubKeyHash160 := hash160(pubKeyBytes)
		fmt.Printf("Public Key Bytes: %x\n", pubKeyBytes)
		fmt.Printf("Public Key Hash160: %x\n", pubKeyHash160)
		fmt.Printf("Base58 Check Encoded Address: %s\n", base58.CheckEncode(pubKeyHash160, 0x00))
	} else {
		fmt.Println("Bitcoin address matches the expected value.")
	}
}
