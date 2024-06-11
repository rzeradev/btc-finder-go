# BTC Finder Go

BTC Finder Go is a Go application that searches for a Bitcoin private key that matches a given address within specified ranges. The application uses multiple goroutines to parallelize the search process and improve performance.

## Features

- Generate public keys from private keys.
- Compute the hash160 (RIPEMD-160 of SHA-256) of the public key.
- Generate Bitcoin addresses from public keys.
- Generate Wallet Import Format (WIF) keys from private keys.
- Parallelized address generation using goroutines.
- Logging of found keys and performance statistics.

## Prerequisites

- [Go](https://golang.org/dl/) (1.16 or higher)
- MinGW (for compiling resource files if you're adding a custom icon on Windows)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/rzeradev/btc-finder-go.git
   cd btc-finder-go
   ```

2. Install the required Go packages:

   ```bash
   go mod tidy
   ```

## Usage

1. Run the application:

   ```bash
   go run main.go
   ```

2. Follow the prompts to select a puzzle wallet and specify the range or percentage to start the search.

### Building the Application

#### For Windows

1. To build the application for Windows:

   ```bash
   GOOS=windows GOARCH=amd64 go build -o btc-finder-go.exe
   ```

2. (Optional) To add a custom icon, create a `resource.rc` file and compile it:

   ```bash
   echo '1 ICON "icon.ico"' > resource.rc
   windres -i resource.rc -o resource.syso
   ```

3. Move the `resource.syso` file to the project directory and build the application again.

#### For Linux

1. To build the application for Linux:

   ```bash
   GOOS=linux GOARCH=amd64 go build -o btc-finder-go
   ```

#### For macOS

1. To build the application for macOS:

   ```bash
   GOOS=darwin GOARCH=amd64 go build -o btc-finder-go
   ```

2. To build the application for macOS with ARM architecture (Apple Silicon):

   ```bash
   GOOS=darwin GOARCH=arm64 go build -o btc-finder-go
   ```

### Logging

- The application logs matched private keys to `matches.log`.
- The progress and performance statistics are printed to the console every second.

### Handling Interrupts

The application handles interrupt signals (e.g., Ctrl+C) to gracefully stop the search and log the progress.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.
