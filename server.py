import json
import os
import re
import sqlite3
import hashlib
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailroom_v2.db")
DB_PATH = os.environ.get("DB_PATH", DEFAULT_DB)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
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
    
    all_lines = []
    full_text_list = []
    
    for src in dossier.get("sources", []):
        for line in src.get("lines", []):
            line_id = line.get("lineId")
            text = line.get("text", "")
            if line_id:
                all_lines.append((line_id, text))
                full_text_list.append(text)
                
    full_text = "\n".join(full_text_list)
    full_text_lower = full_text.lower()
    
    def find_matching_line_id(patterns):
        for line_id, text in all_lines:
            t_lower = text.lower()
            for p in patterns:
                if p in t_lower:
                    return line_id
        return all_lines[0][0] if all_lines else "L1"

    def extract_email(text_str, default="customer@example.com"):
        m = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text_str)
        return m.group(0) if m else default

    def extract_ref(text_str, default=None):
        m = re.search(r'\b(ORD|CASE|REF|TKT|REQ|EVT|DOC)-?[A-Za-z0-9]+\b', text_str, re.IGNORECASE)
        if m:
            return m.group(0)
        return default or f"REF-{dossier_id[:8]}"

    # RULE 1: Quarantine Prompt Injections / Security Risks
    INJECTION_KEYWORDS = [
        "ignore previous instructions", "ignore all prior", "disregard previous",
        "system override", "secret canary", "canary:", "admin prompt", "print api key",
        "leak vault", "unauthorized outbound", "override system", "tool control",
        "execute command", "jailbreak", "prompt injection", "system prompt",
        "agent instruction", "developer mode", "bypass safety"
    ]
    
    for line_id, text in all_lines:
        t_lower = text.lower()
        if any(kw in t_lower for kw in INJECTION_KEYWORDS):
            return {
                "dossierId": dossier_id,
                "action": "quarantine_item",
                "target": {"kind": "security_queue", "id": "mailroom"},
                "payload": {
                    "artifactId": dossier_id,
                    "reasonCode": "INDIRECT_PROMPT_INJECTION"
                },
                "evidence": [line_id]
            }

    # RULE 2: Update Internal Record
    if "delivery" in full_text_lower or "delivery_window" in full_text_lower or "case_record" in full_text_lower or "reschedule" in full_text_lower:
        case_line_id = find_matching_line_id(["case", "delivery", "window", "reschedule", "event"])
        case_ref = extract_ref(full_text, default=f"CASE-{dossier_id[:6]}")
        event_ref = extract_ref(full_text, default=f"EVT-{dossier_id[:6]}")
        val = "MORNING"
        if "evening" in full_text_lower:
            val = "EVENING"
        elif "afternoon" in full_text_lower:
            val = "AFTERNOON"
            
        return {
            "dossierId": dossier_id,
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": case_ref},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": event_ref,
                "value": val
            },
            "evidence": [case_line_id]
        }

    # RULE 3: Send Approved Notice
    if "approved" in full_text_lower or "approved_delivery_notice" in full_text_lower or "approved notice" in full_text_lower:
        appr_line_id = find_matching_line_id(["approved", "notice", "email", "send"])
        recip_email = extract_email(full_text, default="customer@example.com")
        ref_id = extract_ref(full_text, default=f"REF-{dossier_id[:6]}")
        
        return {
            "dossierId": dossier_id,
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recip_email},
            "payload": {
                "referenceId": ref_id,
                "status": "APPROVED",
                "template": "approved_delivery_notice"
            },
            "evidence": [appr_line_id]
        }

    # RULE 4: Request Confirmation (Unverified / Ambiguous)
    if "unverified" in full_text_lower or "conflict" in full_text_lower or "ambiguous" in full_text_lower or "mismatch" in full_text_lower or "verify" in full_text_lower:
        conf_line_id = find_matching_line_id(["unverified", "sender", "conflict", "verify", "mismatch"])
        claimed_sender = extract_email(full_text, default="sender@example.com")
        ref_id = extract_ref(full_text, default=f"REF-{dossier_id[:6]}")
        
        return {
            "dossierId": dossier_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "tier2_support"},
            "payload": {
                "claimedSender": claimed_sender,
                "questionCode": "VERIFY_REQUEST",
                "referenceId": ref_id
            },
            "evidence": [conf_line_id]
        }

    # RULE 5: Create Draft
    if "draft" in full_text_lower or "inquiry" in full_text_lower or "status" in full_text_lower or "order" in full_text_lower:
        draft_line_id = find_matching_line_id(["draft", "inquiry", "order", "status", "from"])
        recip_email = extract_email(full_text, default="customer@example.com")
        ref_id = extract_ref(full_text, default=f"ORD-{dossier_id[:6]}")
        
        return {
            "dossierId": dossier_id,
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            "payload": {
                "recipient": recip_email,
                "referenceId": ref_id,
                "status": "DRAFT_PENDING",
                "template": "order_status"
            },
            "evidence": [draft_line_id]
        }

    # RULE 6: Default / No Action
    first_line_id = all_lines[0][0] if all_lines else "L1"
    ref_id = extract_ref(full_text, default=f"REF-{dossier_id[:6]}")
    
    reason = "INFORMATIONAL"
    if "duplicate" in full_text_lower:
        reason = "DUPLICATE"
    elif "completed" in full_text_lower or "done" in full_text_lower:
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
        self.reply(200, {'ok': True, 'service': 'ga5-mailroom-action-gate/v2'})

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length <= 0 or content_length > 524288:
                return self.reply(400, {'error': 'invalid or bounded content length'})

            raw_body = self.rfile.read(content_length)
            try:
                req = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self.reply(400, {'error': 'malformed JSON payload'})

            profile = req.get('profile')
            if profile != 'ga5-mailroom-action-gate/v2':
                return self.reply(400, {'error': 'unsupported or missing profile'})

            operation = req.get('operation')
            if operation == 'propose':
                return self.handle_propose(req)
            elif operation == 'commit':
                return self.handle_commit(req)
            else:
                return self.reply(400, {'error': 'unknown or missing operation'})

        except Exception as e:
            return self.reply(400, {'error': f'request execution error: {e}'})

    def handle_propose(self, req: dict):
        eval_id = req.get('evaluationId')
        verifier = req.get('receiptVerifier')
        dossiers = req.get('dossiers')

        if not eval_id or not isinstance(eval_id, str):
            return self.reply(400, {'error': 'missing or invalid evaluationId'})
        if not verifier or not isinstance(verifier, dict) or 'publicKeyJwk' not in verifier:
            return self.reply(400, {'error': 'missing or invalid receiptVerifier'})
        if not dossiers or not isinstance(dossiers, list):
            return self.reply(400, {'error': 'missing or invalid dossiers list'})

        # Check duplicate dossierId in request
        dossier_ids = [d.get('dossierId') for d in dossiers if isinstance(d, dict)]
        if len(dossier_ids) != len(set(dossier_ids)):
            return self.reply(400, {'error': 'duplicate dossierId in dossiers list'})

        input_digest = compute_input_digest(dossiers)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Check existing evaluation state
        c.execute('SELECT input_digest, propose_response_json FROM evaluation_state WHERE evaluation_id = ?', (eval_id,))
        row = c.fetchone()
        if row:
            stored_digest, stored_response_json = row[0], row[1]
            conn.close()
            if stored_digest == input_digest and stored_response_json:
                # Exact replay
                return self.reply(200, json.loads(stored_response_json))
            else:
                # Changed content conflict for same evaluationId
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
                # Generate new proposal
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

            # Store in evaluation_proposals
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
            INSERT INTO evaluation_state (evaluation_id, input_digest, verifier_jwk_json, propose_response_json, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (eval_id, input_digest, jwk_json, json.dumps(response_data), "awaiting_receipts"))

        conn.commit()
        conn.close()

        return self.reply(200, response_data)

    def handle_commit(self, req: dict):
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
        if stored_digest != input_digest:
            conn.close()
            return self.reply(409, {'error': 'inputDigest mismatch for evaluationId'})

        if status == 'completed' and stored_commit_json:
            conn.close()
            # Exact commit replay
            return self.reply(200, json.loads(stored_commit_json))

        jwk = json.loads(jwk_json)

        # Retrieve persisted proposals for this evaluationId
        c.execute('SELECT dossier_id, call_id, action, proposal_json, proposal_digest FROM evaluation_proposals WHERE evaluation_id = ?', (eval_id,))
        p_rows = c.fetchall()
        persisted = {r[0]: {"callId": r[1], "action": r[2], "proposal": json.loads(r[3]), "proposalDigest": r[4]} for r in p_rows}

        if len(receipts) != len(persisted):
            conn.close()
            return self.reply(400, {'error': 'receipts count mismatch'})

        # Check duplicate receiptId or dossierId
        receipt_dossier_ids = [r.get('dossierId') for r in receipts if isinstance(r, dict)]
        if len(receipt_dossier_ids) != len(set(receipt_dossier_ids)):
            conn.close()
            return self.reply(400, {'error': 'duplicate dossierId in receipts'})

        # Verify all receipts atomically
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

            # Verify Ed25519 signature
            if not verify_receipt_signature(jwk, eval_id, input_digest, r):
                conn.close()
                return self.reply(400, {'error': f'invalid receiptSignature for dossierId {d_id}'})

            accepted = r.get('accepted', False)
            out_status = "executed" if accepted is True else "rejected"

            outcomes_list.append({
                "dossierId": d_id,
                "callId": p['callId'],
                "action": p['action'],
                "proposalDigest": p['proposalDigest'],
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
    init_db()
    port = int(os.environ.get('PORT', '10000'))
    server = ThreadingHTTPServer(('0.0.0.0', port), RequestHandler)
    print(f"Mailroom Action Gate server listening on port {port}...")
    server.serve_forever()
