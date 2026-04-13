# Blockchain-Based-Digital-Passport
# ⛓ ChainPass — Blockchain Digital Passport System

A fully functional blockchain-powered digital passport authority built as a 
single self-contained HTML file. No dependencies, no backend, no build step.

## Features

- **Blockchain Engine** — Real SHA-256 hashing via Web Crypto API with proof-of-work mining
- **Issue Passports** — Mint passports with biometric hashing, committed to the chain
- **Verify Passports** — Cryptographic validation of hash integrity, chain links, expiry & revocation
- **Revoke Passports** — Immutable revocation records written to the chain
- **Transfer Records** — Inter-agency record transfers, permanently logged on-chain
- **Blockchain Explorer** — Full block inspection with hash, nonce, and chain links
- **MRZ Generation** — ICAO 9303 Machine Readable Zone output per passport
- **Audit Log** — Timestamped activity trail with JSON export

## Tech Stack

- Vanilla HTML / CSS / JavaScript
- Web Crypto API (SHA-256)
- No frameworks, no npm, no build tools

## Live Demo

🔗 [chainpass.vercel.app](https://blockchain-based-digital-passport.vercel.app/)

## Run Locally

Just open `index.html` in any modern browser. That's it.

## Deployment

Deployed as a static site on Vercel. See `vercel.json` for config.

## License

MIT
