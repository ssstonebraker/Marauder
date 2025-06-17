# Marauder - Dark Web Threat Intelligence Platform

Marauder is a **security research tool** designed to help cybersecurity professionals analyze and extract threat intelligence from the dark web. It provides automated scanning capabilities for ransomware groups, dark web forums, and onion services.

⚠️ **This tool is currently in beta and under active development.** Features may be incomplete or unstable. This project is being shared to gather feedback and encourage community involvement.

## 🎯 Purpose

Marauder serves as a comprehensive platform for:
- **Ransomware group monitoring** - Track and analyze ransomware operations
- **Dark web forum intelligence** - Gather intelligence from underground forums  
- **Onion service discovery** - Scan and catalog .onion services
- **Threat pattern analysis** - Identify and track threat indicators
- **Data visualization** - Generate network graphs and threat intelligence reports

## 🔧 Features

### Core Capabilities
- **Database Management** - SQLite-based storage for threat intelligence data
- **Multi-source Seeding** - Integrate data from RansomWatch, DeepDarkCTI, and other sources
- **Automated Scanning** - Continuous monitoring of dark web services
- **Content Caching** - Store and analyze web content for offline analysis
- **Pattern Recognition** - Identify threat indicators and IOCs
- **Network Visualization** - Generate interactive threat landscape maps

### Scanners
- **SimpleOmniScanner** - General-purpose dark web content scanner
- **PlayRansomwareScanner** - Specialized ransomware group tracker
- **Concurrent Processing** - Multi-threaded scanning for efficiency

## 📋 Prerequisites

### System Requirements
- **Python 3.8+**
- **Tor proxy** running on port 9051 (can also use TOR browser)
- **Linux/macOS** (recommended) or Windows with WSL

### Tor Setup
```bash
# Ubuntu/Debian
sudo apt update &&  sudo apt install tor

# Configure Tor for SOCKS proxy
sudo nano /etc/tor/torrc

# Add these lines:
SocksPort 9051
ControlPort 9051

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor

# Verify Tor is running
sudo netstat -tlnp | grep 9051

## Installation

### Clone Repository
```
git clone https://github.com/SecOpsEng/Marauder.git
cd Marauder
```

### Create Virtual Environment
```
python3 -m venv marauder_env
source marauder_env/bin/activate  # Linux/Mac
# marauder_env\Scripts\activate   # Windows
```
### Install Dependencies
```
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

### Database Operations
Create new database:

```
python3 marauder.py build_db threat_intel.db
```

Create database with sample data:
```
python3 marauder.py build_db threat_intel.db -s
```

Create and seed database with threat intelligence:
```
#### Seed with all sources
python3 marauder.py build_db threat_intel.db -S

#### Seed with specific source
python3 marauder.py build_db threat_intel.db -S ransomwatch
python3 marauder.py build_db threat_intel.db -S deepdarkCTI
```

### Threat Intelligence Seeding
Add threat intelligence to existing database:
```
python3 marauder.py seed threat_intel.db
```

This populates the database with:
- Ransomware group data from multiple sources
- Dark web forum information
- Known onion services and IOCs


#### Scanning Operations
Run all scanners:
```
python marauder.py run_scan threat_intel.db
```

#### Run specific scanner:
```
# General dark web scanner
python marauder.py run_scan threat_intel.db SimpleOmniScanner

# Ransomware-focused scanner
python marauder.py run_scan threat_intel.db PlayRansomwareScanner
```

## Example Workflow

```
# 1. Setup database with threat intelligence
python3 marauder.py build_db my_threat_db.db -S

# 2. Run comprehensive scans
python3 marauder.py run_scan my_threat_db.db

# 3. Add additional seed data
python3 marauder.py seed my_threat_db.db
```

# 4. Run targeted ransomware scanning
python marauder.py run_scan my_threat_db.db PlayRansomwareScanner

