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
*Configuration Options*

```
--backend_address	The address of the backend IMAP/IMAPS server
     normally obtained during the authentication process by splitting the pop3 USER command ( USER pippo@pluto.tt backend_address = pluto.tt )
--backend_port	The port of the IMAP/IMAPS server	993
--clamd_host	The host address of the ClamAV daemon	None
--clamd_port	The port of the ClamAV daemon	3310
-l, --listen	The POP3 proxy's listening address	127.0.0.1
-p, --port	The POP3 proxy's listening port	110
--timeout	The backend socket timeout (in seconds)	10.0
-d, --debug	Enables debug logging	False
--daemon	Runs the proxy in daemon mode	False
```

---
## ⚠️ Troubleshooting
- Encoding issues (e.g., 'ascii' codec can't encode character '\u2739'): This is a known issue with the PyCIRCLeanMail library's handling of non-ASCII Unicode characters.
- The code has been modified to handle the error and return the original message to prevent the proxy from crashing.

---

## ⚠️ Disclaimer

This software is provided **as-is**, without any warranty of any kind.  
The authors and contributors are **not responsible** for any data loss, email corruption, service disruption, or other damages resulting from the use of this software.

**Py3Proxy is intended for testing, research, and educational purposes only**.  
It is **not recommended for production environments** or critical email infrastructure.

---

## 📜 License

This project is licensed under the GNU GPLv2 — see the LICENSE file for details.

Original work derived from python-pop3server](https://github.com/nuddelaug/python-pop3server/).

Special thanks to the libraries PyCIRCLeanMail, ClamAV, and python-daemon for their valuable contributions.
