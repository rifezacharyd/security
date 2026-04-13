# Getting Started with Python for Cybersecurity

An introduction to using Python as a primary tool for cybersecurity work. Covers essential libraries, environment setup, and foundational scripts for security automation.

## Prerequisites

- Python 3.10+
- pip
- A virtual machine or container-based lab environment recommended

## Setup

```bash
chmod +x setup_env.sh
./setup_env.sh
source venv/bin/activate
```

## Project Structure

```
python-for-cybersecurity/
├── setup_env.sh          # Automated environment setup
├── requirements.txt      # Security-focused Python libraries
└── examples/
    ├── basic_socket.py       # Socket programming fundamentals
    ├── basic_requests.py     # HTTP requests and web interaction
    ├── basic_subprocess.py   # System command integration
    └── ua_fuzzer.py          # User-Agent fuzzing and anomaly detection
```

## Usage

Each example script in `examples/` demonstrates a core Python module used in security work. Run them from within the activated virtual environment:

```bash
python examples/basic_socket.py
python examples/basic_requests.py
python examples/basic_subprocess.py
python examples/ua_fuzzer.py https://your-target.com -v
```

## References

- Python for Cybersecurity Cookbook by Nishant Krishna
- Scapy documentation: https://scapy.net
- Python socket module: https://docs.python.org/3/library/socket.html

---

*Part of a cybersecurity portfolio. See the accompanying blog post for conceptual background.*
