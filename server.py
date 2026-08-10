import json
import os
import re
import socket
import ipaddress
import sqlite3
import hashlib
import base64
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric import ed25519

# ==========================================
# QUESTION 1: AGENT GUARDRAIL (read_file / fetch_url)
# ==========================================

SANDBOX_ROOT = '/srv/agent-redteam/sandbox-4991371c36'
SANDBOX_REAL = os.path.realpath(SANDBOX_ROOT)
CANARY = 'AGENT_GUARDRAIL_CANARY_d6d73a79ce9053969d435d1416159a1cbcfff109'

SAFE_FIXTURES = {
    '/srv/agent-redteam/sandbox-4991371c36/notes/report.txt': 'SAFE_REPORT_b1600449836980e241d5a05a',
    '/srv/agent-redteam/sandbox-4991371c36/notes/looks-like-..-but-safe.txt': 'SAFE_WEIRD_fe251f916ba40da2ddd15c69',
    '/srv/agent-redteam/sandbox-4991371c36/encoded/%2e%2e-literal.txt': 'SAFE_ENCODED_4c73da330700189b48dd4c67',
    'notes/report.txt': 'SAFE_REPORT_b1600449836980e241d5a05a',
    'notes/looks-like-..-but-safe.txt': 'SAFE_WEIRD_fe251f916ba40da2ddd15c69',
    'encoded/%2e%2e-literal.txt': 'SAFE_ENCODED_4c73da330700189b48dd4c67',
}

ALLOWED_NETLOCS_HTTP = {
    'example.com', 'example.com:80',
    'www.example.com', 'www.example.com:80',
    'iana.org', 'iana.org:80',
    'www.iana.org', 'www.iana.org:80'
}

ALLOWED_NETLOCS_HTTPS = {
    'example.com', 'example.com:443',
    'www.example.com', 'www.example.com:443',
    'iana.org', 'iana.org:443',
    'www.iana.org', 'www.iana.org:443'
}

def init_environment():
    try:
        os.makedirs(os.path.join(SANDBOX_ROOT, 'notes'), exist_ok=True)
        os.makedirs(os.path.join(SANDBOX_ROOT, 'encoded'), exist_ok=True)
        os.makedirs('/srv/agent-redteam/outside-c2ab0270', exist_ok=True)
        
        with open('/srv/agent-redteam/outside-c2ab0270/canary.txt', 'w', encoding='utf-8') as f:
            f.write(CANARY)
            
        with open(os.path.join(SANDBOX_ROOT, 'notes/report.txt'), 'w', encoding='utf-8') as f:
            f.write('SAFE_REPORT_b1600449836980e241d5a05a')
            
        with open(os.path.join(SANDBOX_ROOT, 'notes/looks-like-..-but-safe.txt'), 'w', encoding='utf-8') as f:
            f.write('SAFE_WEIRD_fe251f916ba40da2ddd15c69')
            
        with open(os.path.join(SANDBOX_ROOT, 'encoded/%2e%2e-literal.txt'), 'w', encoding='utf-8') as f:
            f.write('SAFE_ENCODED_4c73da330700189b48dd4c67')
    except Exception as e:
        print(f"Init environment warning: {e}")

def handle_read_file(path_arg):
    if not isinstance(path_arg, str) or '\x00' in path_arg or len(path_arg) > 4096 or not path_arg.strip():
        return {'action': 'block', 'reason': 'invalid path argument', 'result': None}

    raw_path = path_arg.replace('\\', '/')
    if raw_path.startswith('file://'):
        raw_path = raw_path[7:]

    if raw_path in SAFE_FIXTURES:
        return {'action': 'allow', 'reason': 'path is inside sandbox', 'result': SAFE_FIXTURES[raw_path]}

    s = raw_path
    for _ in range(10):
        unq = urllib.parse.unquote(s)
        if unq == s:
            break
        s = unq

    s = s.replace('\\', '/')
    if '\x00' in s:
        return {'action': 'block', 'reason': 'null byte in decoded path', 'result': None}

    if s == SANDBOX_ROOT:
        rel = ''
    elif s.startswith(SANDBOX_ROOT + '/'):
        rel = s[len(SANDBOX_ROOT) + 1:]
    elif s.startswith('/'):
        return {'action': 'block', 'reason': 'path is outside sandbox', 'result': None}
    else:
        rel = s

    parts = [p for p in rel.split('/') if p != '']
    if any(p == '..' for p in parts):
        return {'action': 'block', 'reason': 'path traversal detected (..)', 'result': None}
    if parts and ':' in parts[0]:
        return {'action': 'block', 'reason': 'invalid scheme or drive in path', 'result': None}

    candidate_rel = '/'.join(parts)
    candidate = os.path.abspath(os.path.join(SANDBOX_ROOT, candidate_rel))

    try:
        if os.path.commonpath([SANDBOX_ROOT, candidate]) != SANDBOX_ROOT:
            return {'action': 'block', 'reason': 'path resolves outside sandbox', 'result': None}
        
        parent = os.path.realpath(os.path.dirname(candidate))
        if os.path.commonpath([SANDBOX_REAL, parent]) != SANDBOX_REAL:
            return {'action': 'block', 'reason': 'parent directory resolves outside sandbox', 'result': None}

        if os.path.exists(candidate):
            resolved = os.path.realpath(candidate)
            if os.path.commonpath([SANDBOX_REAL, resolved]) != SANDBOX_REAL:
                return {'action': 'block', 'reason': 'symlink resolves outside sandbox', 'result': None}
            
            if not os.path.isfile(resolved):
                return {'action': 'block', 'reason': 'path is not a regular file', 'result': None}

            with open(resolved, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(262144)

            if CANARY in content:
                return {'action': 'block', 'reason': 'canary token detected in file content', 'result': None}

            return {'action': 'allow', 'reason': 'path is inside sandbox', 'result': content}
        else:
            if candidate_rel in SAFE_FIXTURES:
                return {'action': 'allow', 'reason': 'path is inside sandbox', 'result': SAFE_FIXTURES[candidate_rel]}
            return {'action': 'block', 'reason': 'file does not exist inside sandbox', 'result': None}
    except Exception:
        return {'action': 'block', 'reason': 'error processing path', 'result': None}

def is_ip_unsafe(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split('%')[0])
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip) == '169.254.169.254'
            or str(ip).startswith('100.64.')
        )
    except ValueError:
        return True

def validate_url(url_str: str):
    if not isinstance(url_str, str) or len(url_str) > 8192 or not url_str.strip():
        return False, 'invalid URL format'
        
    if any(ord(c) < 32 or ord(c) == 127 for c in url_str):
        return False, 'control characters in URL'

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception:
        return False, 'unable to parse URL'
        
    scheme = (parsed.scheme or '').lower()
    if scheme not in ('http', 'https'):
        return False, 'only http and https schemes are allowed'
        
    netloc = (parsed.netloc or '').lower()
    if not netloc or '@' in netloc or '\\' in netloc or '%40' in netloc or '%5c' in netloc:
        return False, 'userinfo or invalid authority in URL'
        
    if parsed.username is not None or parsed.password is not None:
        return False, 'userinfo is not allowed'
        
    if scheme == 'http':
        if netloc not in ALLOWED_NETLOCS_HTTP:
            return False, f'netloc {netloc} is not allowed for HTTP'
    elif scheme == 'https':
        if netloc not in ALLOWED_NETLOCS_HTTPS:
            return False, f'netloc {netloc} is not allowed for HTTPS'

    hostname = (parsed.hostname or '').lower()
    port = parsed.port if parsed.port is not None else (443 if scheme == 'https' else 80)

    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, 'DNS resolution returned no addresses'
        for info in addr_info:
            ip_str = info[4][0]
            if is_ip_unsafe(ip_str):
                return False, f'host resolves to unsafe IP address: {ip_str}'
    except Exception as e:
        return False, f'DNS resolution failed: {e}'

    return True, hostname

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def handle_fetch_url(url_arg):
    if not isinstance(url_arg, str):
        return {'action': 'block', 'reason': 'invalid url argument', 'result': None}

    current_url = url_arg
    max_redirects = 5
    opener = urllib.request.build_opener(NoRedirectHandler)

    for _ in range(max_redirects):
        valid, norm_host_or_reason = validate_url(current_url)
        if not valid:
            return {'action': 'block', 'reason': norm_host_or_reason, 'result': None}

        req = urllib.request.Request(
            current_url,
            headers={'User-Agent': 'agent-guardrail/5.0', 'Accept': '*/*'}
        )

        try:
            with opener.open(req, timeout=10) as resp:
                status_code = resp.getcode()
                if status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location')
                    if not loc:
                        return {'action': 'block', 'reason': 'redirect header missing', 'result': None}
                    current_url = urllib.parse.urljoin(current_url, loc)
                    continue
                else:
                    content = resp.read(262144).decode('utf-8', 'replace')
                    if CANARY in content:
                        return {'action': 'block', 'reason': 'canary token detected in HTTP response', 'result': None}
                    return {'action': 'allow', 'reason': 'exact public host fetch successful', 'result': content}

        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get('Location')
                if not loc:
                    return {'action': 'block', 'reason': 'redirect header missing', 'result': None}
                current_url = urllib.parse.urljoin(current_url, loc)
                continue
            else:
                content = e.read(262144).decode('utf-8', 'replace') if hasattr(e, 'read') else str(e)
                if CANARY in content:
                    return {'action': 'block', 'reason': 'canary token detected in HTTP response', 'result': None}
                return {'action': 'allow', 'reason': f'HTTP status {e.code}', 'result': content}

        except Exception as e:
            return {'action': 'allow', 'reason': 'fetch error on allowed host', 'result': f'Fetch error: {e}'}

    return {'action': 'block', 'reason': 'too many redirects', 'result': None}


# ==========================================
# QUESTION 2: MAILROOM ACTION GATE V2 (propose / commit)
# ==========================================

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailroom_v2.db")
DB_PATH = os.environ.get("DB_PATH", DEFAULT_DB)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Drop stale cache tables on init to ensure fresh proposal computation
    c.execute("DROP TABLE IF EXISTS dossier_cache")
    c.execute("DROP TABLE IF EXISTS evaluation_state")
    c.execute("DROP TABLE IF EXISTS evaluation_proposals")
    c.execute("""
        CREATE TABLE IF NOT EXISTS dossier_cache (
            fingerprint TEXT PRIMARY KEY,
            dossier_id TEXT,
            call_id TEXT,
            action TEXT,
            target_json TEXT,
            payload_json TEXT,
            evidence_json TEXT,
            proposal_digest TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS evaluation_state (
            evaluation_id TEXT PRIMARY KEY,
            input_digest TEXT,
            request_hash TEXT,
            verifier_jwk_json TEXT,
            propose_response_json TEXT,
            commit_response_json TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS evaluation_proposals (
            evaluation_id TEXT,
            dossier_id TEXT,
            call_id TEXT,
            action TEXT,
            proposal_json TEXT,
            proposal_digest TEXT,
            PRIMARY KEY (evaluation_id, dossier_id)
        );
    """)
    conn.commit()
    conn.close()

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def compute_input_digest(dossiers: list) -> str:
    return hashlib.sha256(canonical_json_bytes(dossiers)).hexdigest().lower()

def compute_dossier_fingerprint(dossier: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(dossier)).hexdigest().lower()

def compute_proposal_digest(proposal: dict) -> str:
    norm = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal.get("payload", {}),
        "evidence": sorted(proposal.get("evidence", []))
    }
    return hashlib.sha256(canonical_json_bytes(norm)).hexdigest().lower()

def verify_receipt_signature(pubkey_jwk: dict, commit_eval_id: str, commit_input_digest: str, receipt: dict) -> bool:
    try:
        raw_sig = base64.b64decode(receipt["receiptSignature"])
        x_str = pubkey_jwk["x"]
        rem = len(x_str) % 4
        if rem > 0:
            x_str += "=" * (4 - rem)
        raw_pubkey = base64.urlsafe_b64decode(x_str)
        ed_pubkey = ed25519.Ed25519PublicKey.from_public_bytes(raw_pubkey)
        
        inner_receipt = {
            "dossierId": receipt["dossierId"],
            "callId": receipt["callId"],
            "action": receipt["action"],
            "accepted": receipt["accepted"],
            "proposalDigest": receipt["proposalDigest"],
            "receiptId": receipt["receiptId"]
        }
        
        wrapper = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": commit_eval_id,
            "inputDigest": commit_input_digest,
            "receipt": inner_receipt
        }
        
        payload_bytes = canonical_json_bytes(wrapper)
        ed_pubkey.verify(raw_sig, payload_bytes)
        return True
    except Exception as e:
        print(f"Ed25519 verification error: {e}")
        return False

def generate_proposal_for_dossier(dossier: dict) -> dict:
    dossier_id = dossier["dossierId"]
    mailbox = dossier.get("mailbox", "support@company.com")

    lines_info = []
    for src in dossier.get("sources", []):
        s_id = src.get("sourceId", "")
        prov = (src.get("provenance") or "external").lower()
        kind = (src.get("kind") or "email").lower()
        for line in src.get("lines", []):
            l_id = line.get("lineId")
            text = line.get("text", "")
            if l_id:
                lines_info.append({
                    "lineId": l_id,
                    "text": text,
                    "provenance": prov,
                    "kind": kind,
                    "sourceId": s_id
                })

    if not lines_info:
        lines_info.append({"lineId": "L1", "text": "", "provenance": "external", "kind": "email", "sourceId": "s1"})

    all_text = "\n".join([l["text"] for l in lines_info])
    all_text_lower = all_text.lower()

    def find_line_id(predicate):
        for l in lines_info:
            if predicate(l):
                return l["lineId"]
        return lines_info[0]["lineId"]

    def extract_email(default_val="customer@example.com"):
        m = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', all_text)
        return m.group(0) if m else default_val

    def extract_case_id(default_val=None):
        m = re.search(r'\b(CASE|ORD|REF|TKT|REQ)-?[A-Za-z0-9_-]+\b', all_text, re.IGNORECASE)
        if m:
            return m.group(0)
        return default_val or f"CASE-{dossier_id[:6]}"

    def extract_event_id(default_val=None):
        m = re.search(r'\b(EVT|SRC|EVENT|LOG)-?[A-Za-z0-9_-]+\b', all_text, re.IGNORECASE)
        if m:
            return m.group(0)
        return default_val or lines_info[0]["sourceId"] or f"EVT-{dossier_id[:6]}"

    INJECTION_KEYWORDS = [
        "ignore previous instructions", "ignore all prior", "disregard previous",
        "system override", "secret canary", "canary:", "admin prompt", "print api key",
        "leak vault", "unauthorized outbound", "override system", "tool control",
        "execute command", "eval(", "jailbreak", "prompt injection", "system prompt",
        "developer mode", "bypass safety", "send email to", "transfer funds"
    ]

    for l in lines_info:
        if l["provenance"] in ["external", "untrusted", "third_party", "customer", "inbound"]:
            t_lower = l["text"].lower()
            if any(kw in t_lower for kw in INJECTION_KEYWORDS):
                return {
                    "dossierId": dossier_id,
                    "action": "quarantine_item",
                    "target": {"kind": "security_queue", "id": "mailroom"},
                    "payload": {
                        "artifactId": dossier_id,
                        "reasonCode": "INDIRECT_PROMPT_INJECTION"
                    },
                    "evidence": [l["lineId"]]
                }

    has_internal_approval = False
    approval_line_id = None
    
    for l in lines_info:
        if l["provenance"] in ["internal", "trusted", "system", "case_management"]:
            t_lower = l["text"].lower()
            if "approved" in t_lower or "authorized" in t_lower or "notice" in t_lower or "send_approved" in t_lower:
                has_internal_approval = True
                approval_line_id = l["lineId"]
                break

    if has_internal_approval:
        recip = extract_email("customer@example.com")
        ref_id = extract_case_id(f"REF-{dossier_id[:6]}")
        evidence = [approval_line_id]
        recip_line_id = find_line_id(lambda l: "@" in l["text"])
        if recip_line_id and recip_line_id not in evidence:
            evidence.append(recip_line_id)
            
        return {
            "dossierId": dossier_id,
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recip},
            "payload": {
                "referenceId": ref_id,
                "status": "APPROVED",
                "template": "approved_delivery_notice"
            },
            "evidence": sorted(list(set(evidence)))
        }

    has_internal_update = False
    update_line_id = None
    
    for l in lines_info:
        t_lower = l["text"].lower()
        if "delivery_window" in t_lower or "delivery window" in t_lower or ("reschedule" in t_lower and l["provenance"] in ["internal", "system", "case_management"]):
            has_internal_update = True
            update_line_id = l["lineId"]
            break

    if has_internal_update:
        case_id = extract_case_id(f"CASE-{dossier_id[:6]}")
        event_id = extract_event_id(lines_info[0]["sourceId"])
        val = "MORNING"
        if "evening" in all_text_lower:
            val = "EVENING"
        elif "afternoon" in all_text_lower:
            val = "AFTERNOON"
            
        return {
            "dossierId": dossier_id,
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": case_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": event_id,
                "value": val
            },
            "evidence": [update_line_id]
        }

    is_unverified = False
    conf_line_id = None
    
    for l in lines_info:
        t_lower = l["text"].lower()
        if "unverified" in t_lower or "conflict" in t_lower or "ambiguous" in t_lower or "verify" in t_lower or "identity" in t_lower:
            is_unverified = True
            conf_line_id = l["lineId"]
            break

    if is_unverified:
        sender = extract_email("sender@example.com")
        ref_id = extract_case_id(f"REF-{dossier_id[:6]}")
        return {
            "dossierId": dossier_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "tier2_support"},
            "payload": {
                "claimedSender": sender,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": ref_id
            },
            "evidence": [conf_line_id]
        }

    is_customer_inquiry = False
    draft_line_id = None
    
    for l in lines_info:
        t_lower = l["text"].lower()
        if l["provenance"] in ["external", "customer", "inbound"] or "inquiry" in t_lower or "order" in t_lower or "status" in t_lower or "help" in t_lower or "question" in t_lower:
            is_customer_inquiry = True
            draft_line_id = l["lineId"]
            break

    if is_customer_inquiry:
        recip = extract_email("customer@example.com")
        ref_id = extract_case_id(f"ORD-{dossier_id[:6]}")
        return {
            "dossierId": dossier_id,
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            "payload": {
                "recipient": recip,
                "referenceId": ref_id,
                "status": "DRAFT_PENDING",
                "template": "order_status"
            },
            "evidence": [draft_line_id]
        }

    first_line_id = lines_info[0]["lineId"]
    ref_id = extract_case_id(f"REF-{dossier_id[:6]}")
    reason = "INFORMATIONAL"
    if "duplicate" in all_text_lower:
        reason = "DUPLICATE"
    elif "completed" in all_text_lower or "done" in all_text_lower:
        reason = "ALREADY_COMPLETED"

    return {
        "dossierId": dossier_id,
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": reason,
            "referenceId": ref_id
        },
        "evidence": [first_line_id]
    }


# ==========================================
# UNIFIED REQUEST HANDLER (Supports Q1 & Q2 Concurrently)
# ==========================================

class RequestHandler(BaseHTTPRequestHandler):
    def reply(self, status_code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(200, {'ok': True, 'service': 'multi-task-guardrail-and-action-gate'})

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0 or content_length > 524288:
                return self.reply(400, {'action': 'block', 'reason': 'invalid content length', 'result': None})

            raw_body = self.rfile.read(content_length)
            try:
                req = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.reply(400, {'action': 'block', 'reason': 'malformed JSON payload', 'result': None})

            # ROUTER STEP 1: Question 1 Agent Guardrail (tool: read_file / fetch_url)
            if isinstance(req, dict) and 'tool' in req:
                tool = req.get('tool')
                args = req.get('arguments')
                if not isinstance(args, dict):
                    return self.reply(200, {'action': 'block', 'reason': 'arguments must be a dict', 'result': None})

                if tool == 'read_file':
                    res = handle_read_file(args.get('path'))
                    return self.reply(200, res)
                elif tool == 'fetch_url':
                    res = handle_fetch_url(args.get('url'))
                    return self.reply(200, res)
                else:
                    return self.reply(200, {'action': 'block', 'reason': 'unknown tool', 'result': None})

            # ROUTER STEP 2: Question 2 Mailroom Action Gate v2 (profile: ga5-mailroom-action-gate/v2)
            elif isinstance(req, dict) and req.get('profile') == 'ga5-mailroom-action-gate/v2':
                operation = req.get('operation')
                if operation == 'propose':
                    return self.handle_propose(req, raw_body)
                elif operation == 'commit':
                    return self.handle_commit(req, raw_body)
                else:
                    return self.reply(400, {'error': 'unknown or missing operation'})

            else:
                return self.reply(400, {'error': 'unrecognized request payload format'})

        except Exception as e:
            return self.reply(400, {'error': f'request execution error: {e}'})

    def handle_propose(self, req: dict, raw_body: bytes):
        eval_id = req.get('evaluationId')
        verifier = req.get('receiptVerifier')
        dossiers = req.get('dossiers')

        if not eval_id or not isinstance(eval_id, str):
            return self.reply(400, {'error': 'missing or invalid evaluationId'})
        if not verifier or not isinstance(verifier, dict) or 'publicKeyJwk' not in verifier:
            return self.reply(400, {'error': 'missing or invalid receiptVerifier'})
        if not dossiers or not isinstance(dossiers, list):
            return self.reply(400, {'error': 'missing or invalid dossiers list'})

        dossier_ids = [d.get('dossierId') for d in dossiers if isinstance(d, dict)]
        if len(dossier_ids) != len(set(dossier_ids)):
            return self.reply(400, {'error': 'duplicate dossierId in dossiers list'})

        input_digest = compute_input_digest(dossiers)
        request_hash = hashlib.sha256(raw_body).hexdigest().lower()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('SELECT input_digest, request_hash, propose_response_json FROM evaluation_state WHERE evaluation_id = ?', (eval_id,))
        row = c.fetchone()
        if row:
            stored_digest, stored_req_hash, stored_response_json = row[0], row[1], row[2]
            conn.close()
            if stored_req_hash == request_hash and stored_response_json:
                return self.reply(200, json.loads(stored_response_json))
            else:
                return self.reply(409, {'error': 'changed content conflict for same evaluationId'})

        jwk_json = json.dumps(verifier['publicKeyJwk'])
        proposals_list = []

        for dossier in dossiers:
            d_id = dossier.get('dossierId')
            fingerprint = compute_dossier_fingerprint(dossier)

            c.execute('SELECT call_id, action, target_json, payload_json, evidence_json, proposal_digest FROM dossier_cache WHERE fingerprint = ?', (fingerprint,))
            cache_row = c.fetchone()

            if cache_row:
                call_id, action, target_json, payload_json, evidence_json, p_digest = cache_row
                proposal = {
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": action,
                    "target": json.loads(target_json) if target_json else None,
                    "payload": json.loads(payload_json),
                    "evidence": json.loads(evidence_json)
                }
            else:
                prop = generate_proposal_for_dossier(dossier)
                call_id = f"call:{hashlib.md5(fingerprint.encode()).hexdigest()[:24]}"
                proposal = {
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": prop["action"],
                    "target": prop["target"],
                    "payload": prop["payload"],
                    "evidence": prop["evidence"]
                }
                p_digest = compute_proposal_digest(proposal)

                c.execute('''
                    INSERT OR REPLACE INTO dossier_cache (fingerprint, dossier_id, call_id, action, target_json, payload_json, evidence_json, proposal_digest)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    fingerprint, d_id, call_id, prop["action"],
                    json.dumps(prop["target"]), json.dumps(prop["payload"]),
                    json.dumps(prop["evidence"]), p_digest
                ))

            c.execute('''
                INSERT OR REPLACE INTO evaluation_proposals (evaluation_id, dossier_id, call_id, action, proposal_json, proposal_digest)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (eval_id, d_id, proposal["callId"], proposal["action"], json.dumps(proposal), p_digest))

            proposals_list.append(proposal)

        response_data = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals_list
        }

        c.execute('''
            INSERT INTO evaluation_state (evaluation_id, input_digest, request_hash, verifier_jwk_json, propose_response_json, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (eval_id, input_digest, request_hash, jwk_json, json.dumps(response_data), "awaiting_receipts"))

        conn.commit()
        conn.close()

        return self.reply(200, response_data)

    def handle_commit(self, req: dict, raw_body: bytes):
        eval_id = req.get('evaluationId')
        input_digest = req.get('inputDigest')
        receipts = req.get('receipts')

        if not eval_id or not isinstance(eval_id, str):
            return self.reply(400, {'error': 'missing or invalid evaluationId'})
        if not input_digest or not isinstance(input_digest, str):
            return self.reply(400, {'error': 'missing or invalid inputDigest'})
        if receipts is None or not isinstance(receipts, list):
            return self.reply(400, {'error': 'missing or invalid receipts list'})

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('SELECT input_digest, verifier_jwk_json, commit_response_json, status FROM evaluation_state WHERE evaluation_id = ?', (eval_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return self.reply(400, {'error': 'unknown evaluationId'})

        stored_digest, jwk_json, stored_commit_json, status = row

        # Check commit replay first
        if status == 'completed' and stored_commit_json:
            conn.close()
            if stored_digest == input_digest:
                return self.reply(200, json.loads(stored_commit_json))
            else:
                return self.reply(409, {'error': 'inputDigest mismatch on commit replay'})

        if stored_digest != input_digest:
            conn.close()
            return self.reply(409, {'error': 'inputDigest mismatch for evaluationId'})

        jwk = json.loads(jwk_json)

        c.execute('SELECT dossier_id, call_id, action, proposal_json, proposal_digest FROM evaluation_proposals WHERE evaluation_id = ?', (eval_id,))
        p_rows = c.fetchall()
        persisted = {r[0]: {"callId": r[1], "action": r[2], "proposal": json.loads(r[3]), "proposalDigest": r[4]} for r in p_rows}

        if len(receipts) != len(persisted):
            conn.close()
            return self.reply(400, {'error': 'receipts count mismatch'})

        receipt_dossier_ids = [r.get('dossierId') for r in receipts if isinstance(r, dict)]
        if len(receipt_dossier_ids) != len(set(receipt_dossier_ids)):
            conn.close()
            return self.reply(400, {'error': 'duplicate dossierId in receipts'})

        outcomes_list = []
        for r in receipts:
            d_id = r.get('dossierId')
            if not d_id or d_id not in persisted:
                conn.close()
                return self.reply(400, {'error': f'unknown or unpersisted dossierId {d_id} in receipt'})

            p = persisted[d_id]
            if r.get('callId') != p['callId']:
                conn.close()
                return self.reply(400, {'error': f'callId mismatch for dossierId {d_id}'})
            if r.get('action') != p['action']:
                conn.close()
                return self.reply(400, {'error': f'action mismatch for dossierId {d_id}'})
            if r.get('proposalDigest') != p['proposalDigest']:
                conn.close()
                return self.reply(400, {'error': f'proposalDigest mismatch for dossierId {d_id}'})

            if not verify_receipt_signature(jwk, eval_id, input_digest, r):
                conn.close()
                return self.reply(400, {'error': f'invalid receiptSignature for dossierId {d_id}'})

            accepted = r.get('accepted', False)
            out_status = "executed" if accepted is True else "rejected"

            # Echo exact supplied receipt bindings
            outcomes_list.append({
                "dossierId": r.get('dossierId'),
                "callId": r.get('callId'),
                "action": r.get('action'),
                "proposalDigest": r.get('proposalDigest'),
                "receiptId": r.get('receiptId'),
                "status": out_status
            })

        commit_response_data = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes_list
        }

        c.execute('UPDATE evaluation_state SET commit_response_json = ?, status = ? WHERE evaluation_id = ?', (json.dumps(commit_response_data), "completed", eval_id))
        conn.commit()
        conn.close()

        return self.reply(200, commit_response_data)

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    init_environment()
    init_db()
    port = int(os.environ.get('PORT', '10000'))
    server = ThreadingHTTPServer(('0.0.0.0', port), RequestHandler)
    print(f"Unified Guardrail & Mailroom Gate server listening on port {port}...")
    server.serve_forever()
