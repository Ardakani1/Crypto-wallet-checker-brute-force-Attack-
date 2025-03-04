package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/time/rate"
)

const (
	totalCombos        = 15000000               // Generate 15 million mnemonics
	checkThreshold     = 1.0                    // 1 USD
	concurrencyLimit   = 10                     // Concurrency limit for balance checks
	rateLimitPerSecond = 5                      // Rate limit for mnemonic generation
	maxRetries         = 5                      // Maximum number of retries for database operations
	retryDelay         = 100 * time.Millisecond // Delay between retries
)

var (
	dbFile          = getEnv("DB_FILE", "bip39_wallets.db")
	cryptoDbFile    = getEnv("CRYPTO_DB_FILE", "crypto_wallets.db")
	outputFile      = getEnv("OUTPUT_FILE", "valid_wallets.txt")
	encryptionKey   = []byte(getEnv("ENCRYPTION_KEY", "thisis32bitlongpassphraseimusing"))
	rateLimiter     = rate.NewLimiter(rate.Limit(rateLimitPerSecond), rateLimitPerSecond)
	dbMutex         sync.Mutex
	mnemonicChannel = make(chan string, 1000) // Buffered channel
	shutdownChannel = make(chan os.Signal, 1)
	wg              sync.WaitGroup
)

func main() {
	signal.Notify(shutdownChannel, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	// Start the mnemonic generation and storage in a separate goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		storeMnemonics(ctx)
	}()

	// Start the wallet checking and storage in another separate goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		checkAndStoreWallets(ctx)
	}()

	// Wait for shutdown signal
	<-shutdownChannel
	log.Println("Shutting down...")
	cancel()
	wg.Wait()
}

func setupDatabase(dbFile string) *sql.DB {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	// Enable WAL mode
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		log.Fatal("Error enabling WAL mode:", err)
	}

	return db
}

func storeMnemonics(ctx context.Context) {
	db := setupDatabase(dbFile)
	defer db.Close()

	for i := 0; i < totalCombos; i++ {
		err := rateLimiter.Wait(ctx)
		if err != nil {
			log.Fatal("Rate limiter error:", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
			mnemonic := generateMnemonic()
			mnemonicChannel <- mnemonic // Send to channel
		}
	}
	close(mnemonicChannel) // Close the channel after sending all mnemonics
}

func processMnemonics(db *sql.DB) {
	stmt, err := db.Prepare("INSERT OR IGNORE INTO mnemonics(phrase) VALUES(?)")
	if err != nil {
		log.Fatal("Error preparing query:", err)
	}
	defer stmt.Close()

	tx, err := db.Begin()
	if err != nil {
		log.Fatal("Error beginning transaction:", err)
	}

	for mnemonic := range mnemonicChannel {
		dbMutex.Lock()
		_, err = executeStmtWithRetry(tx, stmt, mnemonic)
		dbMutex.Unlock()
		if err != nil {
			log.Println("Error storing mnemonic:", err)
		} else {
			log.Printf("Mnemonic stored: %s", mnemonic)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatal("Error committing transaction:", err)
	}
}

func generateMnemonic() string {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Fatal("Error generating entropy:", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatal("Error generating mnemonic:", err)
	}

	return mnemonic
}

func checkAndStoreWallets(ctx context.Context) {
	sourceDb := setupDatabase(dbFile)
	defer sourceDb.Close()

	cryptoDb := setupDatabase(cryptoDbFile)
	defer cryptoDb.Close()

	go processMnemonics(sourceDb)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			rows, err := sourceDb.Query("SELECT id, phrase FROM mnemonics")
			if err != nil {
				log.Fatal("Error reading mnemonics:", err)
			}
			defer rows.Close()

			stmt, err := cryptoDb.Prepare("INSERT OR IGNORE INTO crypto_wallets(phrase, balance) VALUES(?, ?)")
			if err != nil {
				log.Fatal("Error preparing crypto query:", err)
			}
			defer stmt.Close()

			var wg sync.WaitGroup
			sem := make(chan struct{}, concurrencyLimit)

			for rows.Next() {
				var id int
				var phrase string
				err = rows.Scan(&id, &phrase)
				if err != nil {
					log.Println("Error scanning mnemonic:", err)
					continue
				}

				wg.Add(1)
				sem <- struct{}{}
				go func(phrase string) {
					defer wg.Done()
					defer func() { <-sem }()
					balance := checkWalletBalance(phrase)
					if balance.Cmp(big.NewFloat(checkThreshold)) > 0 {
						dbMutex.Lock()
						_, err = executeStmtWithRetry(nil, stmt, phrase, balance.String())
						dbMutex.Unlock()
						if err != nil {
							log.Println("Error storing crypto wallet:", err)
						} else {
							log.Printf("High balance wallet stored: %s, %s", phrase, balance.String())
							saveToTextFile(phrase, balance.String())
						}
					}
				}(phrase)
			}
			wg.Wait()
			time.Sleep(10 * time.Second)
		}
	}
}

func checkWalletBalance(phrase string) *big.Float {
	// Placeholder: Replace with actual API call logic
	address := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	url := fmt.Sprintf("https://api.blockchair.com/bitcoin/dashboards/address/%s", address)

	resp, err := http.Get(url)
	if err != nil {
		log.Println("Error fetching wallet balance:", err)
		return big.NewFloat(0)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Println("Error decoding API response:", err)
		return big.NewFloat(0)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		log.Println("Invalid data format")
		return big.NewFloat(0)
	}

	addressData, ok := data[address].(map[string]interface{})
	if !ok {
		log.Println("Invalid address data format")
		return big.NewFloat(0)
	}

	balance, ok := addressData["balance"].(float64)
	if !ok {
		log.Println("Invalid balance format")
		return big.NewFloat(0)
	}

	return big.NewFloat(balance / 1e8) // Convert satoshi to BTC
}

func executeWithRetry(db *sql.DB, query string) (sql.Result, error) {
	var err error
	var result sql.Result
	for i := 0; i < maxRetries; i++ {
		result, err = db.Exec(query)
		if err == nil {
			return result, nil
		}
		if err.Error() == "database is locked" {
			time.Sleep(retryDelay)
			continue
		}
		return result, err
	}
	return result, err
}

func executeStmtWithRetry(tx *sql.Tx, stmt *sql.Stmt, args ...interface{}) (sql.Result, error) {
	var err error
	var result sql.Result
	for i := 0; i < maxRetries; i++ {
		if tx != nil {
			result, err = tx.Stmt(stmt).Exec(args...)
		} else {
			result, err = stmt.Exec(args...)
		}
		if err == nil {
			return result, nil
		}
		if err.Error() == "database is locked" {
			time.Sleep(retryDelay)
			continue
		}
		return result, err
	}
	return result, err
}

func saveToTextFile(phrase, balance string) {
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("Phrase: %s, Balance: %s\n", phrase, balance))
	if err != nil {
		log.Println("Error writing to file:", err)
	} else {
		log.Printf("Written to file: Phrase: %s, Balance: %s", phrase, balance)
	}
}

func encrypt(text, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(text, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
