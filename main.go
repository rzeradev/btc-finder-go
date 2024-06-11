package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/manifoldco/promptui"
	"github.com/rzeradev/btc-finder-go/config"
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

// Worker function for goroutines
func worker(start, end *big.Int, targetAddress string, wg *sync.WaitGroup, found chan *secp256k1.PrivateKey, addressesGenerated *big.Int, mu *sync.Mutex, shouldStop chan struct{}, logWg *sync.WaitGroup) {
	defer wg.Done()
	current := new(big.Int).Set(start)
	one := big.NewInt(1)

	for current.Cmp(end) <= 0 {
		select {
		case <-shouldStop:
			return
		default:
			// Generate private key
			privKey := secp256k1.PrivKeyFromBytes(current.Bytes())
			pubKey := derivePublicKey(privKey)

			// Generate address from the public key
			address := publicKeyToAddress(pubKey)

			// Check if the address matches the target address
			if address == targetAddress {
				found <- privKey
				logMatchFound(privKey, pubKey, address, addressesGenerated, logWg)
				return
			}

			// Increment the private key
			current.Add(current, one)

			// Increment the addresses generated counter
			mu.Lock()
			addressesGenerated.Add(addressesGenerated, one)
			mu.Unlock()
		}
	}
}

func logMatchFound(privKey *secp256k1.PrivateKey, pubKey *secp256k1.PublicKey, address string, addressesGenerated *big.Int, logWg *sync.WaitGroup) {
	logWg.Add(1)
	go func() {
		defer logWg.Done()

		file, err := os.OpenFile("matches.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open matches file: %v", err)
		}
		defer file.Close()

		wif, err := generateWIF(privKey)
		if err != nil {
			log.Fatalf("Failed to generate WIF: %v", err)
		}

		elapsed := time.Since(startTime)
		elapsedMicroseconds := elapsed.Microseconds()
		var rate float64
		if elapsedMicroseconds > 0 {
			rate, _ = new(big.Float).Quo(new(big.Float).SetInt(addressesGenerated), big.NewFloat(elapsed.Seconds())).Float64()
		} else {
			rate = 0
		}

		logLine := fmt.Sprintf("Generated: %s addresses, Rate: %.2f addresses/second, Time elapsed: %s, Private Key: %x, Public Key: %x, Address: %s, WIF: %s\n",
			addressesGenerated.String(),
			rate,
			elapsed.String(),
			privKey.Serialize(),
			pubKey.SerializeCompressed(),
			address,
			wif)
		if _, err := file.WriteString(logLine); err != nil {
			log.Fatalf("Failed to write to matches file: %v", err)
		}
	}()
}

var startTime time.Time

func main() {
	// Import ranges and addresses
	ranges := config.Ranges
	addresses := config.Addresses

	// Handle interrupt signals
	shouldStop := make(chan struct{})
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		close(shouldStop)
	}()

	// Prompt user to select a puzzle wallet
	prompt := promptui.Prompt{
		Label: "Choose a puzzle wallet (1 - 144)",
		Validate: func(input string) error {
			i, err := strconv.Atoi(input)
			if err != nil || i < 1 || i > len(ranges) {
				return fmt.Errorf("invalid option")
			}
			return nil
		},
	}

	result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}

	index, _ := strconv.Atoi(result)
	selectedRange := ranges[index-1]
	targetAddress := addresses[index-1]

	fmt.Printf("Original Min: %s\n", selectedRange.Min)
	fmt.Printf("Original Max: %s\n", selectedRange.Max)

	min := new(big.Int)
	min.SetString(selectedRange.Min, 16)

	max := new(big.Int)
	max.SetString(selectedRange.Max, 16)

	fmt.Printf("Chosen Wallet: %d Min: %s Max: %s\n", index, selectedRange.Min, selectedRange.Max)
	fmt.Printf("Wallet Address: %s\n", targetAddress)

	// Ensure max is greater than min
	if min.Cmp(max) > 0 {
		log.Fatalf("Error: min value is greater than max value")
	}

	// Calculate total number of addresses in the range (inclusive)
	totalAddresses := new(big.Int).Sub(max, min)
	totalAddresses.Add(totalAddresses, big.NewInt(1))

	// Debug print statements
	fmt.Printf("min: %s\n", min.String())
	fmt.Printf("max: %s\n", max.String())
	fmt.Printf("Total addresses in range: %s\n", totalAddresses.String())

	// Prompt user to select a starting option
	prompt = promptui.Prompt{
		Label: "Choose an option (1 - Start from the beginning, 2 - Choose a percentage, 3 - Choose a minimum range value)",
		Validate: func(input string) error {
			i, err := strconv.Atoi(input)
			if err != nil || i < 1 || i > 3 {
				return fmt.Errorf("invalid option")
			}
			return nil
		},
	}

	result, err = prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}

	startOption, _ := strconv.Atoi(result)

	if startOption == 2 {
		// Prompt user to select a percentage
		prompt = promptui.Prompt{
			Label: "Choose a number between 0 e 1",
			Validate: func(input string) error {
				f, err := strconv.ParseFloat(input, 64)
				if err != nil || f < 0 || f > 1 {
					return fmt.Errorf("invalid number")
				}
				return nil
			},
		}

		result, err = prompt.Run()
		if err != nil {
			log.Fatalf("Prompt failed %v\n", err)
		}

		percentage, _ := strconv.ParseFloat(result, 64)
		rangeSize := new(big.Int).Sub(max, min)
		percentBigInt := new(big.Int).Mul(rangeSize, big.NewInt(int64(percentage*1e18)))
		percentBigInt.Div(percentBigInt, big.NewInt(1e18))
		min.Add(min, percentBigInt)
		fmt.Printf("Starting at: 0x%s\n", min.Text(16))

		// Recalculate total addresses after updating min
		totalAddresses = new(big.Int).Sub(max, min)
		totalAddresses.Add(totalAddresses, big.NewInt(1))
		fmt.Printf("Total addresses in new range: %s\n", totalAddresses.String())

	} else if startOption == 3 {
		// Prompt user to select a minimum value
		prompt = promptui.Prompt{
			Label: "Enter the minimun range (in hexadecimal)",
			Validate: func(input string) error {
				_, success := new(big.Int).SetString(input, 16)
				if !success {
					return fmt.Errorf("invalid hexadecimal number")
				}
				return nil
			},
		}

		result, err = prompt.Run()
		if err != nil {
			log.Fatalf("Prompt failed %v\n", err)
		}

		newMin := new(big.Int)
		newMin.SetString(result, 16)
		min = newMin
		fmt.Printf("Starting at: 0x%s\n", min.Text(16))

		// Recalculate total addresses after updating min
		totalAddresses = new(big.Int).Sub(max, min)
		totalAddresses.Add(totalAddresses, big.NewInt(1))
		fmt.Printf("Total addresses in new range: %s\n", totalAddresses.String())
	}

	// Number of goroutines
	numGoroutines := runtime.NumCPU()
	runtime.GOMAXPROCS(numGoroutines)

	// If total addresses is less than numGoroutines, set numGoroutines to total addresses
	if totalAddresses.Cmp(big.NewInt(int64(numGoroutines))) < 0 {
		numGoroutines = int(totalAddresses.Int64())
	}

	// Ensure numGoroutines is never zero
	if numGoroutines == 0 {
		log.Fatalf("Error: number of goroutines is zero")
	}

	// Calculate range per goroutine
	rangePerGoroutine := new(big.Int).Div(totalAddresses, big.NewInt(int64(numGoroutines)))

	// Ensure range per goroutine is at least 1
	if rangePerGoroutine.Cmp(big.NewInt(1)) < 0 {
		rangePerGoroutine = big.NewInt(1)
	}

	// Debug print statements
	fmt.Printf("Range per goroutine: %s\n", rangePerGoroutine.String())

	// Channel to signal when a match is found
	found := make(chan *secp256k1.PrivateKey)
	var wg sync.WaitGroup
	var logWg sync.WaitGroup

	// Track the number of addresses generated
	addressesGenerated := new(big.Int)
	var mu sync.Mutex

	// Start time for performance tracking
	startTime = time.Now()

	for i := 0; i < numGoroutines; i++ {
		start := new(big.Int).Add(min, new(big.Int).Mul(rangePerGoroutine, big.NewInt(int64(i))))
		end := new(big.Int).Add(start, rangePerGoroutine)
		if i == numGoroutines-1 {
			end = max
		}

		wg.Add(1)
		go worker(start, end, targetAddress, &wg, found, addressesGenerated, &mu, shouldStop, &logWg)
	}

	// Track performance and print updates
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				mu.Lock()
				generated := new(big.Int).Set(addressesGenerated)
				mu.Unlock()
				var rate, remainingTime float64
				if elapsed > 0 {
					rate, _ = new(big.Float).Quo(new(big.Float).SetInt(generated), big.NewFloat(elapsed)).Float64()
					remaining := new(big.Int).Sub(totalAddresses, generated)
					remainingTime, _ = new(big.Float).Quo(new(big.Float).SetInt(remaining), new(big.Float).SetFloat64(rate)).Float64()
				} else {
					rate = 0
					remainingTime = 0
				}

				fmt.Printf("Generated: %s addresses, Rate: %.2f addresses/second, Time elapsed: %s, Time remaining: %s\n",
					generated.String(),
					rate,
					time.Duration(elapsed*float64(time.Second)).String(),
					time.Duration(remainingTime*float64(time.Second)).String())
			case <-done:
				fmt.Println("Ticker goroutine exiting")
				return
			}
		}
	}()

	// Wait for a goroutine to find a match
	go func() {
		wg.Wait()
		close(found)
	}()

	// Handle the found private key
	privKey, ok := <-found
	close(done)
	if ok {
		wif, err := generateWIF(privKey)
		if err != nil {
			log.Fatal(err)
		}

		pubKey := derivePublicKey(privKey)
		fmt.Println("Matching private key found!")
		fmt.Printf("Private Key: %x\n", privKey.Serialize())
		fmt.Printf("Public Key: %x\n", pubKey.SerializeCompressed())
		fmt.Printf("WIF: %s\n", wif)
	} else {
		fmt.Println("No matching private key found")
	}

	// Wait for all log operations to complete
	logWg.Wait()
}
