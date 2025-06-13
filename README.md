# Spotify Account Generator

**By @DudeGeorges**

## Overview

This project is an advanced Spotify account generator with:

* Automatic temporary email generation using Mail.tm.
* CAPTCHA solving with CapSolver.
* Proxy support (`user:pass@host:port`).
* Multi-threaded execution for high efficiency.

> **Educational purposes only. Use responsibly.**

## Features

* Generates valid Spotify accounts automatically
* Uses temporary emails — no Gmail or Yahoo needed
* Solves CAPTCHA automatically with CapSolver
* Proxy support (HTTP(S) format)
* Auto-saves generated accounts to `saved/accounts.txt`

## Folder Structure

```
.
├── data/
│   └── proxies.txt      # Your proxies (one per line)
├── modules/
│   ├── faker.py         # Random data generator
│   ├── mail_service.py  # Mail.tm API module
├── saved/
│   └── accounts.txt     # Generated accounts (auto-created)
├── main.py              # Main generator script
└── README.md            # This file
```

## Requirements

* Python 3.9+
* Working proxies (`user:pass@host:port` format recommended)
* Valid CapSolver API key

## Installation

1. Clone this repo:

```bash
git clone https://github.com/YourUser/spotify-generator.git
cd spotify-generator
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

**Typical dependencies:**

```
httpx
capsolver
colorama
faker
```

3. Prepare proxies:

Add your proxies to `data/proxies.txt`:

```
user:pass@host:port
```

## Usage

Run the generator:

```bash
python main.py
```

You’ll be prompted for your CapSolver API key:

```
[x] Input CapSolver Key: YOUR_API_KEY_HERE
```

The generator will:

* Load proxies
* Spawn multiple threads
* Create Spotify accounts
* Solve CAPTCHAs automatically
* Save accounts to `saved/accounts.txt`

## Important Notes

* Proxies are strongly recommended to avoid IP bans.
* Use high-quality residential proxies for best results.
* Accounts are saved in `saved/accounts.txt` in `email:password` format.

## Credits

* Coded by **@DudeGeorges**
* Uses Mail.tm for disposable emails
* Uses CapSolver for CAPTCHA bypass

## Disclaimer

This tool is for educational and research purposes only.
The developer is not responsible for any misuse.

## Happy Generating!

Star the repo if you find it helpful!
