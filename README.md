# CTShield - Certificate Transparency Browser Extension

Advanced SSL/TLS certificate verification using Certificate Transparency (CT) logs with Merkle proof validation and real-time Man-in-the-Middle attack detection.

## Overview

CTShield is a browser extension that enhances web security by verifying SSL/TLS certificates against Certificate Transparency logs. The extension uses cryptographic Merkle proof verification to ensure certificate authenticity and detect potential security threats.

Certificate Transparency is an open framework designed to fix structural flaws in the SSL/TLS certificate ecosystem by providing an open framework for monitoring and auditing SSL certificates. CTShield implements CT verification using industry-standard cryptographic methods including Merkle Tree structures and Signed Certificate Timestamps (SCT).

## Key Features

### Real-Time Certificate Verification

CTShield performs real-time verification of SSL/TLS certificates when users visit websites. The extension extracts certificate information from the browser's security context and verifies it against Certificate Transparency logs.

### Merkle Proof Verification

Implements cryptographic Merkle Tree proof verification to ensure certificates are present in CT logs without requiring full log downloads. This provides cryptographic guarantees of certificate authenticity with minimal computational overhead.

### Signed Certificate Timestamp (SCT) Validation

Validates Signed Certificate Timestamps embedded in certificates to ensure they were logged to CT logs at issuance time. SCT validation provides additional security guarantees beyond basic certificate chain validation.

### Man-in-the-Middle Detection

Detects potential Man-in-the-Middle (MitM) attacks by comparing presented certificates with CT log entries. Certificates not found in CT logs or with invalid Merkle proofs trigger security warnings.

### Certificate Details Display

Provides detailed certificate information including:

- SHA-256 certificate fingerprint
- Certificate validation status
- Merkle root hash from CT logs
- SCT validation status
- Certificate timestamp
- Security threat assessment

### Verification History

Maintains a local history of certificate verifications for audit purposes, allowing users to review past certificate checks and track security status over time.

## Architecture

### Components

**Browser Extension**

- Chrome extension implementing the user interface
- Service worker for background certificate processing
- Content scripts for certificate extraction
- WebAssembly module for cryptographic operations

**CT Service Backend**

- Node.js/Express server managing CT log operations
- Merkle Tree data structure implementation
- Certificate fingerprint calculation
- SCT generation and validation

**WASM Verification Module**

- Rust-compiled WebAssembly module
- Merkle proof verification algorithms
- SHA-256 cryptographic hashing
- Certificate fingerprint validation

### Data Flow

1. User initiates certificate verification via extension popup
2. Extension extracts domain and certificate information from active tab
3. Background service worker sends certificate data to CT service
4. CT service calculates certificate fingerprint and queries CT logs
5. CT service generates Merkle proof if certificate is found
6. WASM module cryptographically verifies Merkle proof
7. Results are displayed in extension popup with security assessment

## Installation

### Prerequisites

- Node.js (v14 or higher)
- Rust toolchain (latest stable version)
- wasm-pack (for WebAssembly compilation)
- Chrome or Chromium-based browser

### Build Instructions

1. Clone the repository:

```bash
git clone https://github.com/haidang24/extension_tls-
cd tls-extension
```

2. Install CT service dependencies:

```bash
cd ct-service
npm install
```

3. Build WebAssembly module:

```bash
cd ../wasm-verifier
wasm-pack build --target web --out-dir ../extension/pkg
```

4. Install extension in Chrome:
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable Developer mode
   - Click "Load unpacked"
   - Select the `extension` directory

### Running the CT Service

Start the CT service server:

```bash
cd ct-service
npm start
```

The service runs on `http://localhost:4000` by default.

## Usage

1. Open the extension popup by clicking the CTShield icon in the browser toolbar
2. Click "Verify Certificate" to check the current website's certificate
3. Review the verification results:
   - Certificate fingerprint
   - Validation status
   - Merkle root hash
   - SCT validation status
   - Security threat assessment
4. Access verification history by scrolling to the history section

## Security Features

### Certificate Transparency

CTShield leverages Certificate Transparency logs to provide public auditability of SSL/TLS certificates. All certificates issued by Certificate Authorities are logged to publicly auditable CT logs, preventing unauthorized certificate issuance.

### Merkle Tree Cryptography

Merkle Trees provide efficient cryptographic proofs of certificate inclusion in CT logs. CTShield implements Merkle proof verification using SHA-256 hashing to ensure certificate authenticity without requiring full log downloads.

### Certificate Fingerprinting

SHA-256 certificate fingerprints provide unique identification of certificates. CTShield uses standard certificate fingerprinting to match certificates against CT log entries.

### Real-Time Threat Detection

The extension performs real-time certificate verification on every verification request, immediately detecting certificate anomalies or potential security threats.

## API Reference

### CT Service Endpoints

**POST /ct-check**
Verifies a certificate against CT logs.

Request:

```json
{
  "domain": "example.com",
  "certificate": "..."
}
```

Response:

```json
{
  "domain": "example.com",
  "fingerprint": "SHA256:...",
  "status": "valid",
  "mitm_status": "safe",
  "merkle_root": "...",
  "merkle_proof": {...},
  "sct_valid": true,
  "timestamp": "2025-01-XX..."
}
```

**GET /merkle-root**
Returns the current Merkle root hash and CT log statistics.

**GET /health**
Service health check endpoint.

**GET /ct-logs**
Lists all CT log entries.

## Technical Specifications

### Cryptographic Algorithms

- SHA-256 for certificate fingerprinting
- Merkle Tree structures for proof generation
- Standard CT log format compliance

### WebAssembly Module

The WASM module implements:

- Merkle proof verification
- SHA-256 hashing operations
- Certificate fingerprint validation
- Cryptographic proof validation

### Browser Compatibility

- Chrome 88+
- Chromium-based browsers
- Firefox support planned

## Security Considerations

### Certificate Validation

CTShield validates certificates using multiple security layers:

1. Certificate chain validation (browser native)
2. CT log verification
3. Merkle proof validation
4. SCT validation

### Privacy

Certificate verification occurs locally in the browser and extension. Certificate fingerprints are sent to the CT service, but full certificate data is processed locally.

### Limitations

- Current implementation uses mock CT logs for demonstration
- Production deployment requires integration with real CT log APIs
- Certificate fetching requires browser debugger API permissions
- Network connectivity required for CT service communication

## Development

### Project Structure

```
tls-extension/
├── extension/              # Browser extension files
│   ├── manifest.json       # Extension configuration
│   ├── popup.html          # Extension UI
│   ├── popup.js            # UI logic
│   ├── background.js       # Service worker
│   ├── wasm_loader.js      # WASM module loader
│   ├── content.js          # Content script
│   └── pkg/                # Compiled WASM files
├── ct-service/             # CT service backend
│   ├── server.js           # Express server
│   └── package.json        # Dependencies
└── wasm-verifier/          # Rust/WASM module
    ├── src/
    │   └── lib.rs          # Verification logic
    └── Cargo.toml          # Rust dependencies
```

### Building from Source

1. Install Rust dependencies:

```bash
cd wasm-verifier
cargo build --release --target wasm32-unknown-unknown
```

2. Compile WebAssembly:

```bash
wasm-pack build --target web --out-dir ../extension/pkg
```

3. Start development server:

```bash
cd ct-service
npm run dev
```

## References

- Certificate Transparency: https://certificate.transparency.dev/
- RFC 6962: Certificate Transparency specification
- Google CT Logs: https://ct.googleapis.com/
- Merkle Tree: https://en.wikipedia.org/wiki/Merkle_tree

## License

MIT License

## Contact

For questions, issues, or contributions, please refer to the project repository.
