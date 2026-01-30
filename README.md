# Threat Intelligence Tool 🛡️

A comprehensive, modular CLI tool to query multiple threat intelligence APIs (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise, UrlScan.io) and present a unified, beautiful dashboard.

![Dashboard Preview](https://via.placeholder.com/800x400?text=Dashboard+Preview) 
*(Screenshots coming soon)*

## 🚀 Features

*   **Multi-Source Intelligence**: Aggregates data from 6+ top-tier security APIs.
*   **Smart Detection**: Automatically detects if the target is an IP, Domain, or File Hash.
*   **Rich Dashboard**: Visual grid layout with color-coded risk verdicts.
*   **Deep Enrichment**:
    *   **VirusTotal**: Community votes, tags, filenames, network CIDR.
    *   **Shodan**: Open ports, hostnames, vulnerabilities.
    *   **GreyNoise**: RIOT (benign) status, actor/bot identification.
    *   **AlienVault**: Threat pulses and community reports.
*   **Risk Scoring**: Intelligent verdict system (Safe / Suspicious / High Risk) based on thresholds.
*   **Localization**: Full support for **Portuguese (PT-BR)** and English (EN).

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/nilsonpmjr/Threat-Intelligence-Tool.git
    cd Threat-Intelligence-Tool
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🔑 Configuration

Set your API keys as environment variables. You can add these to your `.bashrc`, `.zshrc`, or run them in your session:

```bash
export VT_API_KEY='your_key'
export ABUSEIPDB_API_KEY='your_key'
export SHODAN_API_KEY='your_key'
export OTX_API_KEY='your_key'
export GREYNOISE_API_KEY='your_key'
export URLSCAN_API_KEY='your_key'
```

*Note: The tool gracefully handles missing keys by skipping those services.*

## 💻 Usage

**Basic Scan (Dashboard Mode):**
```bash
./threat_check.py 8.8.8.8 --dashboard
```

**Scan a Domain:**
```bash
./threat_check.py google.com --dashboard
```

**Scan a File Hash:**
```bash
./threat_check.py 44d88612fea8a8f36de82e1278abb02f --dashboard
```

**Plain Text Output (Good for logs):**
```bash
./threat_check.py 1.1.1.1
```

**Switch Language to English:**
```bash
./threat_check.py 1.1.1.1 --lang en
```

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📝 License

[MIT](https://choosealicense.com/licenses/mit/)
