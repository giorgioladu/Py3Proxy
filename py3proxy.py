#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#


import email
from email.utils import formatdate, make_msgid
from uuid import uuid5, NAMESPACE_DNS
from time import time
from hashlib import md5
from imaplib import IMAP4, IMAP4_SSL
import socketserver
import threading
import logging
import sys
import asyncio
from kittengroomer_email.mail import KittenGroomerMail
import optparse
import re

VERSION = "1.0"
OK = '+OK'
ERR = '-ERR'

logger = logging.getLogger('Py3Proxy')
logger.addHandler(logging.StreamHandler(sys.stderr))
logger.addHandler(logging.FileHandler('/tmp/Py3Proxy.log'))
for h in logger.handlers:
    h.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s.%(levelname)s %(lineno)d]: %(message)s'))
logger.setLevel(logging.INFO)

monitormessage = """Message-ID: %s
Date: %s
MIME-Version: 1.0
User-Agent: Monitor Application
From: Monitor
To: Monitor
Subject: monitoring test %s

monitoring test %s
"""

# ----------------------------- ClamAV ---------------------------------

async def scan_bytes_with_clam_async(data: bytes, host: str, port: int, chunk_size: int = 8192, timeout: float = 10.0) -> str:
    """Scan arbitrary bytes via ClamAV's INSTREAM protocol asynchronously."""
    if isinstance(data, str):
        data = data.encode('utf-8', 'replace')

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.write(b'zINSTREAM\n')
        await writer.drain()
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            writer.write(len(chunk).to_bytes(4, 'big'))
            writer.write(chunk)
            await writer.drain()
        writer.write(b'\x00\x00\x00\x00')
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        response_str = (response or b'').decode('utf-8', 'replace').strip()
        if 'FOUND' in response_str:
            return 'VIRUS FOUND'
        if 'OK' in response_str:
            return 'OK'
        return response_str or 'UNKNOWN'
    except Exception as e:
        return f'ERROR: {e}'


def scan_with_pycircleanmail(raw_bytes: bytes) -> bytes:
    """
    Usa PyCIRCLeanMail per scansionare e ripulire un'email.
    Ritorna l'email ricostruita in formato bytes (EML).
    """
    try:
        kgm = KittenGroomerMail(raw_bytes, debug=True)
        sanitized = kgm.process_mail()
        pyc_result = sanitized.as_bytes()
        if pyc_result != raw_bytes:
            logger.debug(f'PyCIRCLeanMail: pyc_result != raw_bytes')
            return pyc_result
        else:
            logger.debug(f'PyCIRCLeanMail: pyc_result == raw_bytes')
            return  raw_bytes

    except Exception as e:
        logger.debug(f'PyCIRCLeanMail: {e}')
        # In caso di errore, restituisci i dati originali.
        return raw_bytes

# --------------------------- Backend API ------------------------------

class POP3BackendException(Exception):
    pass


class POP3Backend(object):
    def __init__(self, protocol=None):
        self.protocol = protocol

    def authenticate(self, username=None, password=None):
        raise POP3BackendException('Implement authenticate.')

    def fetch(self):
        raise POP3BackendException('Implement fetch.')

    def delete(self, num=None):
        raise POP3BackendException('Implement delete.')

    def cleanup(self):
        raise POP3BackendException('Implement cleanup.')

    def revert(self):
        raise POP3BackendException('Implement revert.')

    def destroy(self):
        pass


class POP3Backend_IMAP(POP3Backend):
    """
    IMAP backend (STARTTLS not used; plain IMAP). Use POP3Backend_IMAPS for SSL.
    """
    def __init__(self, protocol=None, host=None, port=143, timeout=10.0, clamd_host=None, clamd_port=None):
        super().__init__(protocol)
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.clamd_host = clamd_host
        self.clamd_port = int(clamd_port) if clamd_port else None

        self._imap = None
        self.state = None
        self.imap_ids = []  # maps POP index -> IMAP sequence number (bytes)

    # ---- connection/auth ----
    def __connect__(self):
        try:
            logger.debug(f'IMAP: connecting to {self.host}:{self.port}')
            self._imap = IMAP4(self.host, self.port)
            self._imap.socket().settimeout(self.timeout)
            return True
        except Exception as e:
            logger.error(f'IMAP connection error: {e}')
            self.state = str(e)
            return False

    def authenticate(self, username=None, password=None):
        # Allow monitor/monitor to always pass
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            return True
        try:
            if not self.__connect__():
                return False
            user = str(self.protocol._pop3user)
            pwd = str(self.protocol._pop3pass)
            logger.debug(f'IMAP: authenticating user {user}')
            rsp = self._imap.login(user, pwd)
            if rsp[0] != 'OK':
                self.state = 'IMAP login failed'
                return False
            return True
        except Exception as e:
            logger.error(f'IMAP authentication error: {e}')
            self.state = str(e)
            self._imap = None
            return False

    # ---- operations ----
    def fetch(self):
        """Fill protocol.messages with all INBOX messages (sequence order)."""
        self.protocol.messages = []
        self.imap_ids = []

        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            mid = make_msgid()
            uid = uuid5(NAMESPACE_DNS, str(time()))
            self.protocol.messages = [POP3Message(content=monitormessage % (mid, formatdate(), uid, uid))]
            self.imap_ids = [b'1']
            return True

        try:
            if self._imap is None and not self.authenticate():
                return False

            status, _ = self._imap.select('INBOX')
            if status != 'OK':
                self.state = 'IMAP select INBOX failed'
                return False

            status, data = self._imap.search(None, 'ALL')
            if status != 'OK':
                self.state = 'IMAP search failed'
                return False

            ids = data[0].split() if data and data[0] else []
            if not ids:
                return True

            for seq in ids:
                try:
                    r, c = self._imap.fetch(seq, '(RFC822)')
                    if r != 'OK' or not c or not c[0]:
                        continue

                    raw_bytes = c[0][1]

                    # 1. Analizza il messaggio originale per estrarre gli header
                    try:
                        # Correggi gli header prima che vengano analizzati in un oggetto email
                        corrected_bytes = fix_header_folding(raw_bytes)
                        original_msg = email.message_from_bytes(corrected_bytes)
                    except Exception as e:
                        logger.error(f"Error parsing original message (seq={seq}): {e}")
                        continue

                    # 2. Esegui la sanificazione con PyCIRCLeanMail
                    pyc_result_bytes = scan_with_pycircleanmail(corrected_bytes)

                    # 3. Crea un nuovo messaggio dall'output sanificato
                    popmsg_sanitized = email.message_from_bytes(pyc_result_bytes)
                    #popmsg_sanitized = email.message_from_bytes(fix_header_folding(raw_bytes))

                    # 4. Aggiungi gli header di stato
                    scan_result = 'DISABLED'
                    if self.clamd_host and self.clamd_port:
                        scan_result = asyncio.run(scan_bytes_with_clam_async(raw_bytes, self.clamd_host, self.clamd_port))

                    if "VIRUS FOUND" in scan_result:
                        popmsg_sanitized.add_header('X-ClamAV-Status', 'Infected')
                    elif scan_result.startswith('ERROR'):
                        popmsg_sanitized.add_header('X-ClamAV-Status', scan_result)
                    else:
                        popmsg_sanitized.add_header('X-ClamAV-Status', 'Clean')

                    if pyc_result_bytes != raw_bytes:
                        popmsg_sanitized.add_header('X-PyCIRCLeanMail-Status', 'Sanitized')
                        logger.debug(f"PyCIRCLeanMail result: sanitized")
                    else:
                        popmsg_sanitized.add_header('X-PyCIRCLeanMail-Status', 'Clean')
                        logger.debug(f"PyCIRCLeanMail result: clean")

                    # 5. Copia tutti gli header dal messaggio originale a quello sanificato
                    #    Questo preserva Subject, Date, From, ecc.
                    for header, value in original_msg.items():
                        if header not in popmsg_sanitized:
                            popmsg_sanitized[header] = value

                    # 6. Aggiungi l'oggetto completo e modificato alla lista
                    self.protocol.messages.append(POP3Message(content=popmsg_sanitized.as_bytes()))
                    self.imap_ids.append(seq)

                except Exception as e:
                    logger.error(f'IMAP fetch error (seq={seq}): {e}')

            return True
        except Exception as e:
            logger.error(f'IMAP fetch error: {e}')
            self.state = str(e)
            self._imap = None
            return False

    def delete(self, num=None):
        """Mark message (by POP index) deleted on IMAP (\\Seen \\Deleted)."""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            return True
        try:
            if self._imap is None and not self.authenticate():
                return False

            idx = int(num) - 1
            if idx < 0 or idx >= len(self.imap_ids):
                self.state = 'POP index out of range'
                return False
            seq = self.imap_ids[idx]
            r, _ = self._imap.store(seq, '+FLAGS', r'(\Seen \Deleted)')
            if r != 'OK':
                self.state = 'IMAP store failed'
                return False
            # Track deleted pop index for revert
            if num not in self.protocol._deleted:
                self.protocol._deleted.append(num)
            return True
        except Exception as e:
            logger.error(f'IMAP delete error: {e}')
            self.state = str(e)
            self._imap = None
            return False

    def cleanup(self):
        """EXPUNGE deletions at end of session."""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            return True
        try:
            if self._imap is None and not self.authenticate():
                return False
            r = self._imap.expunge()
            if isinstance(r, tuple) and r[0] != 'OK':
                self.state = 'IMAP expunge failed'
                return False
            return True
        except Exception as e:
            logger.error(f'IMAP cleanup error: {e}')
            self.state = str(e)
            self._imap = None
            return False

    def revert(self):
        """Undo \\Deleted flags for messages marked via DELE during this POP session."""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            return True
        try:
            if self._imap is None and not self.authenticate():
                return False
            for num in list(self.protocol._deleted):
                try:
                    idx = int(num) - 1
                    if 0 <= idx < len(self.imap_ids):
                        seq = self.imap_ids[idx]
                        self._imap.store(seq, '-FLAGS', r'(\Seen \Deleted)')
                except Exception as e:
                    logger.error(f'IMAP revert error (num={num}): {e}')
            self.protocol._deleted.clear()
            return True
        except Exception as e:
            logger.error(f'IMAP revert error: {e}')
            self.state = str(e)
            self._imap = None
            return False


class POP3Backend_IMAPS(POP3Backend_IMAP):
    """IMAP over SSL backend."""
    def __init__(self, protocol=None, host=None, port=993, timeout=10.0, clamd_host=None, clamd_port=None):
        super().__init__(protocol=protocol, host=host, port=port, timeout=timeout, clamd_host=clamd_host, clamd_port=clamd_port)

    def __connect__(self):
        try:
            logger.debug(f'IMAPS: connecting to {self.host}:{self.port}')
            self._imap = IMAP4_SSL(self.host, self.port)
            self._imap.socket().settimeout(self.timeout)
            return True
        except Exception as e:
            logger.error(f'IMAPS connection error: {e}')
            self.state = str(e)
            return False


# --------------------------- POP3 wire --------------------------------

# Nel file py3proxy.py, modifica la classe POP3Message
class POP3Message(object):
    """Represents a POP3 message."""
    def __init__(self, content=None):
        self.content = None
        if content is not None:
            try:
                if isinstance(content, bytes):
                    self.content = email.message_from_bytes(content)
                else:
                    self.content = email.message_from_string(str(content))
            except Exception as e:
                logger.error(f'Error parsing message content: {e}')

    # def get_headers(self):
        # """Restituisce solo gli header del messaggio, in formato stringa."""
        # if not self.content:
            # return ''
        # headers = []
        # for header, value in self.content.items():
            # headers.append(f"{header}: {value}")
        # # Restituisce una stringa con gli header
        # return '\r\n'.join(headers)

    def get_body(self):
        """Restituisce il corpo del messaggio in formato stringa."""
        if not self.content:
            return ''
        if self.content.is_multipart():
            parts = []
            for part in self.content.walk():
                if part.is_multipart():
                    continue
                try:
                    parts.append(part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', 'replace'))
                except Exception:
                    parts.append(part.get_payload())
            return '\r\n'.join(p for p in parts if p)
        else:
            try:
                return self.content.get_payload(decode=True).decode(self.content.get_content_charset() or 'utf-8', 'replace')
            except Exception:
                return self.content.get_payload()

    def as_string(self):
        """return the complete message"""
        return self.content.as_string() if self.content else ''

    def as_byte(self):
        """Restituisce il messaggio completo in formato byte."""
        return self.content.as_bytes() if self.content else b''

    def unique_id(self):
        msgid = (self.content.get('Message-ID') or '').encode()
        key = msgid or self.content.as_bytes()
        return md5(key).hexdigest()

    def __len__(self):
        return len(self.as_string().encode('utf-8', 'replace'))

    # Aggiungere alla classe POP3Message
    def get_headers_only(self):
        """Restituisce solo gli header del messaggio in formato bytes."""
        headers = []
        for header, value in self.content.items():
            headers.append(f"{header}: {value}\r\n")
         # Aggiungi una riga vuota per separare gli header dal corpo
        headers.append("\r\n\r\n")
        return "".join(headers)


    def __len__(self):
        return len(self.as_string().encode('utf-8', 'replace'))


class POP3ServerProtocol(socketserver.BaseRequestHandler):
    def setup(self):
        global Backend
        self.state = 'authorization'
        self.messages = []
        self._pop3user = ''
        self._pop3pass = ''
        self.host = None
        self._deleted = []
        self.backend = Backend
        self.backend.protocol = self
        self._send_response(f'{OK} POP3 proxy ready')

    # ---- helpers ----
    def _send_response(self, response):
        logger.debug(f'S: {response}')
        data = (response + '\r\n').encode('ascii', 'replace')
        self.request.sendall(data)

    def _send_multiline(self, header_line, lines):
        self.request.sendall((header_line + '\r\n').encode('ascii', 'replace'))
        for line in lines:
            # dot-stuffing if needed could be added here; most MUAs won't send lines starting with '.' in LIST/UIDL
            self.request.sendall((line + '\r\n').encode('ascii', 'replace'))
        self.request.sendall(b'.\r\n')

    def _send_error(self, message):
        self._send_response(f'{ERR} {message}')

    def _check_state(self, allowed):
        if self.state not in allowed:
            return f'invalid state for command {self.data.split()[0].decode("ascii", "replace")}'
        return None

      # Modifica il metodo TOP in POP3Protocol
    def do_top(self, msgid=None, lines=0):
        if msgid is None or lines is None:
            self.send_response(ERR)
            return

        msgid = int(msgid)
        if msgid > len(self.messages):
            self.send_response(ERR, 'no such message')
            return

        # Se lines è 0, restituisci solo gli header
        if lines == 0:
            headers = self.messages[msgid - 1].get_headers_only()
            self.send_response(OK, 'message follows')
            self.sock.sendall(headers + b'.\r\n')
            logger.debug(f'Sent headers for message {msgid}')
        else:
            # Per TOP con righe, si può usare il metodo RETR e troncare, o implementare una logica più complessa.
            # Per ora, si può reindirizzare a RETR e troncare manualmente.
            # Oppure, per semplicità, fai RETR e poi tronca il corpo
            full_message = self.messages[msgid - 1].content.as_bytes()

            # Implementazione semplice che prende il messaggio completo e poi lo taglia
            # per una soluzione più robusta, dovresti parse il messaggio e troncare solo il body
            headers_end_index = full_message.find(b'\r\n\r\n') + 4
            headers_and_body = full_message[:headers_end_index] + b'...\r\n'
            self.send_response(OK, 'message follows')
            self.sock.sendall(headers_and_body + b'.\r\n')
            logger.debug(f'Sent TOP for message {msgid} with {lines} lines')

    # ---- POP3 commands ----
    def QUIT(self):
        global MLock
        if self.state == 'transaction':
            self.state = 'update'
            self.backend.cleanup()
        self.state = 'closed'
        if self._pop3user:
            MLock.release_mailbox(self._pop3user)
        self._send_response(f'{OK} POP3 server signing off.')

    def CAPA(self):
        #CAPA
        # TOP
        # UIDL
        # RESP-CODES
        # PIPELINING
        # AUTH-RESP-CODE
        # STLS
        # USER
        # SASL PLAIN LOGIN
        caps = ['TOP', 'UIDL', 'RESP-CODES', 'USER', 'AUTH-RESP-CODE']
        self._send_multiline(OK, caps)

    def STAT(self):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        if not self.messages and not self.backend.fetch():
            return self._send_error(self.backend.state or 'backend fetch failed')
        total = sum(len(m) for m in self.messages)
        self._send_response(f'{OK} {len(self.messages)} {total}')

    def LIST(self, msg=None):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        if not self.messages and not self.backend.fetch():
            return self._send_error(self.backend.state or 'backend fetch failed')

        if msg:
            try:
                idx = int(msg.decode('ascii', 'replace'))
                m = self.messages[idx - 1]  # may raise
                self._send_response(f'{OK} {idx} {len(m)}')
            except Exception:
                self._send_error(f'no such message')
        else:
            lines = [f'{i+1} {len(m)}' for i, m in enumerate(self.messages)]
            self._send_multiline(f'{OK} {len(self.messages)} messages ({sum(len(m) for m in self.messages)} octets)', lines)

    def RETR(self, msg=None):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        if not self.messages and not self.backend.fetch():
            return self._send_error(self.backend.state or 'backend fetch failed')
        try:
            idx = int(msg.decode('ascii', 'replace'))
            m = self.messages[idx - 1]
            head = f'{OK} {len(m)} octets\r\n'
            self.request.sendall(head.encode('ascii', 'replace'))
            # Send message bytes followed by CRLF and final dot
            raw = m.as_byte() + b'\r\n.\r\n'
            self.request.sendall(raw )
        except Exception as e:
            self._send_error(f'no such message')

    def DELE(self, msg=None):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        if not self.messages and not self.backend.fetch():
            return self._send_error(self.backend.state or 'backend fetch failed')
        try:
            idx_str = msg.decode('ascii', 'replace')
            _ = self.messages[int(idx_str) - 1]  # validate exists
            if not self.backend.delete(idx_str):
                return self._send_error(self.backend.state or 'delete failed')
            self._send_response(f'{OK} message {idx_str} deleted')
        except Exception:
            self._send_error('no such message')

    def NOOP(self):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        self._send_response(OK)

    def RSET(self):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        if not self.backend.revert():
            return self._send_error(self.backend.state or 'revert failed')
        self.messages.clear()
        if not self.backend.fetch():
            return self._send_error(self.backend.state or 'backend fetch failed')
        total = sum(len(m) for m in self.messages)
        self._send_response(f'{OK} maildrop has {len(self.messages)} messages ({total} octets)')

    def TOP(self, args=None):
            err = self._check_state(('transaction',))
            if err:
                return self._send_error(err)
            if not args:
                return self._send_error('command TOP requires arguments')

            # Carica i messaggi se non sono già disponibili
            if not self.messages and not self.backend.fetch():
                return self._send_error(self.backend.state or 'backend fetch failed')

            try:
                msgno_b, lines_b = args.split(None, 1)
                msgno = int(msgno_b.decode('utf8', 'replace'))
                lines = int(lines_b.decode('utf8', 'replace'))

                # Controlla se il messaggio esiste
                if msgno < 1 or msgno > len(self.messages):
                    return self._send_error('no such message')

                m = self.messages[msgno - 1]
                header = m.get_headers_only()

                # Se il client richiede 0 linee, invia solo gli header
                if lines == 0:
                    self._send_multiline(OK, [header])
                    logger.debug(f"TOP {msgno} 0: Sent only headers")
                else:
                    # Invia header e le prime 'lines' del corpo
                    body_lines = m.get_body().splitlines()[:lines]
                    self._send_multiline(OK, [header] + body_lines)
                    logger.debug(f"TOP {msgno} {lines}: Sent headers and {lines} body lines")

            except (ValueError, IndexError):
                self._send_error('no such message or invalid arguments')

    def UIDL(self, msg=None):
        err = self._check_state(('transaction',))
        if err:
            return self._send_error(err)
        if not self.messages and not self.backend.fetch():
            return self._send_error(self.backend.state or 'backend fetch failed')
        if msg:
            try:
                idx = int(msg.decode('ascii', 'ignore'))
                m = self.messages[idx - 1]
                self._send_response(f'{OK} {idx} {m.unique_id()}')
            except Exception:
                self._send_error('no such message')
        else:
            lines = [f'{i+1} {m.unique_id()}' for i, m in enumerate(self.messages)]
            self._send_multiline(OK, lines)

    def USER(self, name=None):
        if self.state != 'authorization':
            return self._send_error('invalid state for command USER')
        if not name:
            return self._send_error('invalid username')
        user = name.decode('ascii', 'replace')
        self._pop3user = user
        self.host = user.partition('@')[2] or None
        if self.backend:
            self.backend.host = self.host
        self._send_response(OK)

    def PASS(self, credentials=None):
        global MLock
        if self.state != 'authorization':
            return self._send_error('invalid state for command PASS')
        if not credentials:
            return self._send_error('invalid password')
        if not self._pop3user:
            return self._send_error('username not specified')
        if MLock.is_locked(self._pop3user):
            return self._send_error('maildrop already locked')
        self._pop3pass = credentials.decode('ascii', 'replace')
        if not self.backend.authenticate(self._pop3user, self._pop3pass):
            return self._send_error('invalid username or password')
        if MLock.acquire_mailbox(self._pop3user):
            self.state = 'transaction'
            self._send_response(f'{OK} Logged in.')
        else:
            self._send_error('unable to lock maildrop')

    def handle(self):
        while True:
            self.data = self.request.recv(2048)
            if not self.data:
                break
            try:
                parts = self.data.strip().split(None, 1)
                cmd = parts[0].decode('ascii', 'replace').upper()
                args = parts[1] if len(parts) > 1 else None
                logger.debug(f'C: {cmd} {args or ""}')
                fn = getattr(self, cmd, None)
                if not fn:
                    self._send_error(f"POP3 doesn't support command {cmd}")
                    continue
                if cmd == 'TOP' and args is not None:
                    fn(args)
                elif args is not None:
                    fn(args)
                else:
                    fn()
                if cmd == 'QUIT':
                    break
            except Exception as e:
                logger.error(f'Error handling command: {e}')
                self._send_error('internal server error')


class MailboxLocker(object):
    def __init__(self):
        self.mailboxes = {}
        self._lock = threading.Lock()

    def is_locked(self, name=None):
        return self.mailboxes.get(name or '', False)

    def acquire_mailbox(self, name=None):
        with self._lock:
            if self.mailboxes.get(name or ''):
                return False
            self.mailboxes[name or ''] = True
            return True

    def release_mailbox(self, name=None):
        with self._lock:
            if not self.mailboxes.get(name or ''):
                return False
            del self.mailboxes[name or '']
            return True


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


# --------------------------- Main entry --------------------------------

def main(options):
    global Backend, MLock
    MLock = MailboxLocker()

    backend_name = (options.backend or 'IMAPS').upper()
    if backend_name not in ('IMAP', 'IMAPS'):
        print('supported Backends IMAP, IMAPS')
        sys.exit(1)

    BInterface = POP3Backend_IMAP if backend_name == 'IMAP' else POP3Backend_IMAPS
    Backend = BInterface(
        host=options.backend_address,
        port=options.backend_port,
        timeout=options.timeout,
        clamd_host=options.clamd_host,
        clamd_port=options.clamd_port,
    )

    server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    logger.info(f'serving POP3 proxy at {server.server_address[0]}:{server.server_address[1]} -> {backend_name} {options.backend_address}:{options.backend_port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()

def fix_header_folding(raw_email: bytes) -> bytes:
    # Converti sequenze di spazi inizio riga -> TAB
    fixed = re.sub(rb'\r\n {2,}', b'\r\n\t', raw_email)
    return fixed

def print_help():
    help_text = fr"""
=============================================================
                        Py3Proxy v{VERSION}
          POP3 Proxy with IMAP/IMAPS backend support
=============================================================

Usage: py3proxy.py [OPTIONS]

Options:
   -h, --help           Show this help screen
   -d, --debug          Run in debug mode (verbose logging)
   -p, --port <PORT>    POP3 listening port (default: 1100)
   -H, --host <HOST>    POP3 listening host (default: 127.0.0.1)
   --timeout            Backend socket timeout (default=10.0s )
   --clamd_host         ClamAV clamd host
   --clamd_port         ClamAV clamd port (3310)
   -b, --backend <URL>  IMAP/IMAPS backend server
   -u, --user <USER>    Backend username
   -P, --pass <PASS>    Backend password
   --debug              Enable debug logging
   -v, --version        Show version info

-------------------------------------------------------------
Notes:
 - Logs are stored in /tmp/py3proxy.log
 - This software is experimental and NOT for production use
-------------------------------------------------------------

Example:
   py3proxy.py -p 1100 -H 127.0.0.1 -b imaps://imap.gmail.com:993 \
               -u alice@example.com -P secret
=============================================================
"""
    print(help_text)
    sys.exit(0)

def parse_args():
    parser = optparse.OptionParser(add_help_option=False)

    parser.add_option('-b', '--backend', action='store', default='IMAPS', help='IMAP or IMAPS')
    parser.add_option('--backend_address', action='store', help='IMAP server address')
    parser.add_option('--backend_port', action='store', type=int, default=993, help='IMAP/IMAPS port')
    parser.add_option('--timeout', action='store', type=float, default=10.0, help='Backend socket timeout (s)')
    parser.add_option('--clamd_host', action='store', default=None,help='ClamAV clamd host (optional)')
    parser.add_option('--clamd_port', action='store', type=int, default=3310, help='ClamAV clamd port (3310)')
    parser.add_option('-l', '--listen', action='store', default='127.0.0.1', help='Listen address (POP3)')
    parser.add_option('-p', '--port', action='store', type=int, default=110, help='Listen port (POP3 110)')
    parser.add_option('-d', '--debug', action='store_true', default=True, help='Enable debug logging')
    parser.add_option('-h', '--help', action='store_true', help='Show this help screen')
    parser.add_option('-v', '--version', action='store_true', help='Show version info')

    (options, args) = parser.parse_args()

    if options.help:
        print_help()
        sys.exit(0)

    if options.version:
        print(f"Py3Proxy version {VERSION}")
        sys.exit(0)

    return options

if __name__ == '__main__':

    options = parse_args()
    print(f"Starting Py3Proxy on {options.listen}:{options.port} (Backend: {options.backend})")

    if options.debug:
        logger.setLevel(logging.DEBUG)

    main(options)
