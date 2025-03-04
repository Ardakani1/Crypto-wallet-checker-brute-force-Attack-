# Crypto Wallet Checker

A Go application that generates, stores, and checks BIP39 mnemonic phrases for cryptocurrency wallets. The application uses SQLite for data storage and performs balance checks via an external API. It includes features such as rate limiting, concurrency control, and retry mechanisms for database operations.

## Features

- Generates BIP39 mnemonic phrases
- Stores mnemonic phrases in SQLite
- Checks wallet balances via an external API
- Implements rate limiting and concurrency control
- Securely handles mnemonic phrases with encryption
- Provides structured error handling and logging
- Configurable via environment variables

## Requirements

- Go 1.16+
- SQLite

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/Ardakani1/crypto-wallet-checker.git
   cd crypto-wallet-checker
   ```

2. Copy the `.env.example` file to `.env` and configure your environment variables:
   ```sh
   cp .env.example .env
   ```

3. Build the project:
   ```sh
   go build -o crypto-wallet-checker main.go
   ```

4. Run the application:
   ```sh
   ./crypto-wallet-checker
   ```

## Configuration

The application can be configured via environment variables. Create a `.env` file in the project root with the following variables:

```
DB_FILE=bip39_wallets.db
CRYPTO_DB_FILE=crypto_wallets.db
OUTPUT_FILE=valid_wallets.txt
ENCRYPTION_KEY=thisis32bitlongpassphraseimusing
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
