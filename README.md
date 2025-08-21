# Py3Proxy

**Py3Proxy** is a POP3 proxy written in Python 3 that allows access to IMAP/IMAPS mailboxes through the POP3 protocol, while providing advanced security features.  

The project originates as a fork/derivative of [python-pop3server](https://github.com/nuddelaug/python-pop3server/), extending its capabilities.

---

## ✨ Key Features

- ✅ **POP3 client support** → IMAP/IMAPS backend  
- ✅ **Antivirus scanning** with [ClamAV](https://www.clamav.net/) via `clamd`  
- ✅ **Attachment sanitization** with [PyCIRCLeanMail](https://github.com/CIRCL/PyCIRCLeanMail) (KittenGroomer)  
- ✅ **Detailed logging** to both file and console (`/tmp/Py3Proxy.log`)  
- ✅ **Multi-threading support** for multiple simultaneous client connections  
- ✅ **Custom email headers** are added:
  - `X-ClamAV-Status: Clean | Infected | Error`  
  - `X-PyCIRCLeanMail-Status: Clean | Sanitized`  

---

## 📦 Installation

Prerequisites
- *Python 3.6+*
- *A running ClamAV daemon* (clamd) accessible from the network.
- **kittengroomer_email** (from PyCIRCLeanMail)

Install the necessary Python dependencies:
```bash
pip install imapclient python-daemon socketserver lockfile
```

##  ⚙️ Usage
Run the proxy with an IMAPS backend:
```bash
py3proxy --port 110 -d
```

---
## ⚠️ Troubleshooting
- Encoding issues (e.g., 'ascii' codec can't encode character '\u2739'): This is a known issue with the PyCIRCLeanMail library's handling of non-ASCII Unicode characters. The code has been modified to handle the error and return the original message to prevent the proxy from crashing.

---

## 📜 License

This project is licensed under the GNU GPLv2 — see the LICENSE file for details.
Original work derived from python-pop3server](https://github.com/nuddelaug/python-pop3server/).
