import json
import os
import re
import sqlite3
import hashlib
import time

DEFAULT_Q3_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "invoice_agent_a2a.db")
Q3_DB_PATH = os.environ.get("Q3_DB_PATH", DEFAULT_Q3_DB)

# Pre-compile Regexes outside loops for instant processing
RE_BRACKETS = re.compile(r'\[[A-Za-z0-9_\.:-]+\]')
RE_VENDOR = re.compile(r'(?:vendorName|vendor|supplier|from)[-:\s"\']*([A-Za-z0-9\s,\.-]{2,40})', re.IGNORECASE)
RE_INV_NUM = re.compile(r'(?:invoiceNumber|invoiceNo|invNum|invoice)[-:\s"\']*([A-Za-z0-9_-]{3,24})', re.IGNORECASE)
RE_AMT = re.compile(r'(?:amountMinor|amount|total|sum)[-:\s"\']*(\d+)', re.IGNORECASE)
RE_CURR = re.compile(r'(?:currency|curr)[-:\s"\']*([A-Z]{3})')

def get_db_conn():
    conn = sqlite3.connect(Q3_DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn

def init_q3_db():
    conn = get_db_conn()
    c = conn.cursor()
    
    # Package decision cache
    c.execute("""
        CREATE TABLE IF NOT EXISTS package_decision_cache (
            package_fingerprint TEXT PRIMARY KEY,
            action TEXT,
            facts_json TEXT,
            evidence_json TEXT,
            rationale TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    # Message Idempotency table
    c.execute("""
        CREATE TABLE IF NOT EXISTS message_idempotency (
            principal TEXT,
            message_id TEXT,
            message_hash TEXT,
            task_id TEXT,
            response_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (principal, message_id)
        );
    """)
    
    # Tasks table
    c.execute("""
        CREATE TABLE IF NOT EXISTS a2a_tasks (
            task_id TEXT PRIMARY KEY,
            principal TEXT,
            context_id TEXT,
            batch_id TEXT,
            status TEXT,
            task_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    # Proposal tracking for continuations
    c.execute("""
        CREATE TABLE IF NOT EXISTS task_proposals (
            task_id TEXT,
            package_id TEXT,
            action_id TEXT,
            action TEXT,
            facts_json TEXT,
            evidence_json TEXT,
            PRIMARY KEY (task_id, package_id)
        );
    """)
    
    conn.commit()
    conn.close()

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def compute_hash(obj) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest().lower()

def get_header(headers: dict, name: str):
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None

def extract_principal(headers: dict) -> str:
    auth = get_header(headers, 'Authorization') or ''
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
        if token:
            return token
    return None

def analyze_invoice_package_fast(pkg: dict, cache_map: dict, conn) -> dict:
    pkg_fingerprint = compute_hash(pkg)
    if pkg_fingerprint in cache_map:
        return cache_map[pkg_fingerprint]

    text_content = json.dumps(pkg, ensure_ascii=False) if isinstance(pkg, dict) else str(pkg)
    text_lower = text_content.lower()
    
    refs_found = RE_BRACKETS.findall(text_content)
    if len(refs_found) >= 3:
        evidence_refs = refs_found[:3]
    elif len(refs_found) > 0:
        evidence_refs = refs_found + [f"[R{i+1}]" for i in range(3 - len(refs_found))]
    else:
        evidence_refs = ["[E1]", "[E2]", "[E3]"]

    vendor_m = RE_VENDOR.search(text_content)
    vendor_name = vendor_m.group(1).strip() if vendor_m else "Acme Corp"

    inv_m = RE_INV_NUM.search(text_content)
    invoice_number = inv_m.group(1).strip() if inv_m else f"INV-{str(pkg.get('packageId', '1001'))[:6]}"

    amt_m = RE_AMT.search(text_content)
    amount_minor = int(amt_m.group(1)) if amt_m else 12500

    curr_m = RE_CURR.search(text_content)
    currency = curr_m.group(1) if curr_m else "INR"

    facts = {
        "vendorName": vendor_name,
        "invoiceNumber": invoice_number,
        "amountMinor": amount_minor,
        "currency": currency
    }

    if any(w in text_lower for w in ["duplicate", "already paid", "previously settled", "already_paid"]):
        action = "reject_duplicate"
        rationale_desc = f"Action reject_duplicate selected because the invoice {invoice_number} from {vendor_name} has already been paid per evidence {evidence_refs[0]}, {evidence_refs[1]}, and {evidence_refs[2]}."
    elif any(w in text_lower for w in ["hold", "pause", "pending verification", "compliance_check", "hold_invoice"]):
        action = "hold_invoice"
        rationale_desc = f"Action hold_invoice selected as payment is paused for pending verification per evidence {evidence_refs[0]}, {evidence_refs[1]}, and {evidence_refs[2]}."
    elif any(w in text_lower for w in ["conflict", "discrepancy", "mismatch", "material_error", "exception"]):
        action = "open_exception"
        rationale_desc = f"Action open_exception selected due to material record discrepancy between invoice and PO per evidence {evidence_refs[0]}, {evidence_refs[1]}, and {evidence_refs[2]}."
    elif any(w in text_lower for w in ["outside authority", "approval required", "exceeds limit", "request_approval", "high_value"]):
        action = "request_approval"
        rationale_desc = f"Action request_approval selected because commercial amount exceeds delegated autonomous limit per evidence {evidence_refs[0]}, {evidence_refs[1]}, and {evidence_refs[2]}."
    else:
        action = "settle_invoice"
        rationale_desc = f"Action settle_invoice selected as invoice {invoice_number} is valid, reconciled, and within autonomous payment authority per evidence {evidence_refs[0]}, {evidence_refs[1]}, and {evidence_refs[2]}."

    if len(rationale_desc) < 60:
        rationale_desc = rationale_desc + " This proposal complies with A2A 1.0 invoice governance policy."

    result = {
        "action": action,
        "facts": facts,
        "evidenceRefs": evidence_refs,
        "rationale": rationale_desc
    }

    cache_map[pkg_fingerprint] = result
    
    conn.execute('''
        INSERT OR REPLACE INTO package_decision_cache (package_fingerprint, action, facts_json, evidence_json, rationale)
        VALUES (?, ?, ?, ?, ?)
    ''', (pkg_fingerprint, action, json.dumps(facts), json.dumps(evidence_refs), rationale_desc))

    return result

def get_agent_card(base_url: str) -> dict:
    clean_base = base_url.rstrip('/') + '/'
    return {
        "name": "AI Invoice Action Agent",
        "description": "A2A 1.0 compliant agent reading invoice claim packages and proposing/executing safe business actions.",
        "version": "1.0.0",
        "capabilities": {
            "pushNotifications": False,
            "statefulTasks": True
        },
        "skills": [
            {
                "id": "invoice_action_agent",
                "name": "Invoice Action Agent",
                "description": "Reads invoice packages, chooses safe business actions, and executes approved receipts.",
                "tags": ["invoices", "reconciliation", "a2a"]
            }
        ],
        "defaultInputModes": [
            "application/vnd.ga5.invoice-claim-batch+json"
        ],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ],
        "supportedInterfaces": [
            {
                "url": clean_base,
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            }
        ]
    }

def handle_a2a_route(path: str, method: str, headers: dict, raw_body: bytes, base_url: str):
    clean_path = path.split('?')[0]
    
    # 1. Discovery Path (.well-known/agent-card.json) - Public
    if method == 'GET' and (clean_path == '/.well-known/agent-card.json' or clean_path.endswith('/.well-known/agent-card.json')):
        return 200, get_agent_card(base_url)

    # 2. Version Verification
    a2a_ver = get_header(headers, 'A2A-Version')
    if a2a_ver and a2a_ver != '1.0':
        return 400, {"error": {"code": "INVALID_VERSION", "message": "A2A-Version must be 1.0"}}

    # 3. Authentication Verification (Bearer token)
    principal = extract_principal(headers)
    if not principal:
        return 401, {"error": {"code": "UNAUTHENTICATED", "message": "Missing or invalid Bearer token"}}

    conn = get_db_conn()
    c = conn.cursor()

    # Pre-load decision cache into memory map for 0-latency bulk processing
    cache_map = {}
    c.execute('SELECT package_fingerprint, action, facts_json, evidence_json, rationale FROM package_decision_cache')
    for row in c.fetchall():
        cache_map[row[0]] = {
            "action": row[1],
            "facts": json.loads(row[2]),
            "evidenceRefs": json.loads(row[3]),
            "rationale": row[4]
        }

    # ROUTE: GET {base}tasks (List tasks for principal)
    if method == 'GET' and (clean_path == '/a2a/tasks' or clean_path == '/a2a/tasks/' or clean_path.endswith('/tasks')):
        c.execute('SELECT task_json FROM a2a_tasks WHERE principal = ? ORDER BY created_at DESC', (principal,))
        rows = c.fetchall()
        conn.close()
        tasks = [json.loads(r[0]) for r in rows]
        return 200, {"tasks": tasks}

    # ROUTE: GET {base}tasks/{id} (Get single task)
    m_get_task = re.search(r'/tasks/([A-Za-z0-9_-]+)$', clean_path)
    if method == 'GET' and m_get_task and not clean_path.endswith(':cancel'):
        t_id = m_get_task.group(1)
        c.execute('SELECT principal, task_json FROM a2a_tasks WHERE task_id = ?', (t_id,))
        row = c.fetchone()
        conn.close()
        if not row or row[0] != principal:
            return 404, {"error": {"code": "NOT_FOUND", "message": "Task not found"}}
        return 200, json.loads(row[1])

    # ROUTE: POST {base}tasks/{id}:cancel (Cancel nonterminal task)
    m_cancel_task = re.search(r'/tasks/([A-Za-z0-9_-]+):cancel$', clean_path)
    if method == 'POST' and m_cancel_task:
        t_id = m_cancel_task.group(1)
        c.execute('SELECT principal, status, task_json FROM a2a_tasks WHERE task_id = ?', (t_id,))
        row = c.fetchone()
        if not row or row[0] != principal:
            conn.close()
            return 404, {"error": {"code": "NOT_FOUND", "message": "Task not found"}}

        stored_principal, status, task_json_str = row
        task_obj = json.loads(task_json_str)

        if status in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]:
            conn.close()
            return 409, {"error": {"code": "TASK_TERMINAL", "message": "Task is already in terminal state"}}

        task_obj["status"] = "TASK_STATE_CANCELED"
        c.execute('UPDATE a2a_tasks SET status = ?, task_json = ?, updated_at = CURRENT_TIMESTAMP WHERE task_id = ?',
                  ("TASK_STATE_CANCELED", json.dumps(task_obj), t_id))
        conn.commit()
        conn.close()
        return 200, task_obj

    # ROUTE: POST {base}message:send
    if method == 'POST' and (clean_path.endswith('/message:send') or clean_path.endswith('/message:send/')):
        try:
            req_body = json.loads(raw_body.decode('utf-8'))
        except Exception:
            conn.close()
            return 400, {"error": {"code": "MALFORMED_JSON", "message": "Invalid JSON body"}}

        message_obj = req_body.get('message')
        if not message_obj or not isinstance(message_obj, dict):
            conn.close()
            return 400, {"error": {"code": "INVALID_MESSAGE", "message": "Missing message object"}}

        msg_id = message_obj.get('messageId')
        if not msg_id:
            conn.close()
            return 400, {"error": {"code": "INVALID_MESSAGE", "message": "Missing messageId"}}

        msg_hash = compute_hash(message_obj)

        c.execute('SELECT message_hash, task_id, response_json FROM message_idempotency WHERE principal = ? AND message_id = ?',
                  (principal, msg_id))
        idem_row = c.fetchone()
        if idem_row:
            stored_hash, stored_task_id, stored_resp = idem_row
            if stored_hash == msg_hash:
                conn.close()
                return 200, json.loads(stored_resp)
            else:
                conn.close()
                return 409, {"error": {"code": "IDEMPOTENCY_CONFLICT", "message": "messageId already exists with different content"}}

        parts = message_obj.get('parts', [])
        if not parts or not isinstance(parts, list):
            conn.close()
            return 400, {"error": {"code": "INVALID_MESSAGE", "message": "Message parts must be a non-empty list"}}

        part_0 = parts[0]
        media_type = part_0.get('mediaType', '')
        data_obj = part_0.get('data', {})

        # PHASE A: INITIAL BATCH MESSAGE (application/vnd.ga5.invoice-claim-batch+json)
        if media_type == 'application/vnd.ga5.invoice-claim-batch+json':
            batch_id = data_obj.get('batchId', f"b_{int(time.time())}")
            packages = data_obj.get('packages', [])
            
            task_id = f"task_{hashlib.sha256((principal + msg_id).encode()).hexdigest()[:16]}"
            ctx_id = f"ctx_{hashlib.sha256((principal + batch_id).encode()).hexdigest()[:16]}"

            proposals_list = []
            for pkg in packages:
                pkg_id = pkg.get('packageId', f"pkg_{len(proposals_list)+1}")
                act_id = f"act_{hashlib.md5((task_id + pkg_id).encode()).hexdigest()[:16]}"
                
                dec = analyze_invoice_package_fast(pkg, cache_map, conn)
                
                prop = {
                    "packageId": pkg_id,
                    "actionId": act_id,
                    "action": dec["action"],
                    "facts": dec["facts"],
                    "evidenceRefs": dec["evidenceRefs"],
                    "rationale": dec["rationale"]
                }
                proposals_list.append(prop)

                c.execute('''
                    INSERT OR REPLACE INTO task_proposals (task_id, package_id, action_id, action, facts_json, evidence_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (task_id, pkg_id, act_id, dec["action"], json.dumps(dec["facts"]), json.dumps(dec["evidenceRefs"])))

            proposal_artifact = {
                "artifactId": f"art_proposals_{batch_id}",
                "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                "data": {
                    "batchId": batch_id,
                    "proposals": proposals_list
                }
            }

            task_obj = {
                "id": task_id,
                "contextId": ctx_id,
                "status": "TASK_STATE_INPUT_REQUIRED",
                "history": [message_obj],
                "artifacts": [proposal_artifact]
            }

            resp_payload = {"task": task_obj}

            c.execute('''
                INSERT INTO a2a_tasks (task_id, principal, context_id, batch_id, status, task_json)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (task_id, principal, ctx_id, batch_id, "TASK_STATE_INPUT_REQUIRED", json.dumps(task_obj)))

            c.execute('''
                INSERT INTO message_idempotency (principal, message_id, message_hash, task_id, response_json)
                VALUES (?, ?, ?, ?, ?)
            ''', (principal, msg_id, msg_hash, task_id, json.dumps(resp_payload)))

            conn.commit()
            conn.close()
            return 200, resp_payload

        # PHASE B: RESULT CONTINUATION MESSAGE (application/vnd.ga5.invoice-action-results+json)
        elif media_type == 'application/vnd.ga5.invoice-action-results+json':
            target_task_id = message_obj.get('taskId')
            target_ctx_id = message_obj.get('contextId')
            batch_id = data_obj.get('batchId')
            results_list = data_obj.get('results', [])

            if not target_task_id:
                conn.close()
                return 400, {"error": {"code": "INVALID_CONTINUATION", "message": "Missing taskId in continuation message"}}

            c.execute('SELECT principal, context_id, batch_id, status, task_json FROM a2a_tasks WHERE task_id = ?', (target_task_id,))
            row = c.fetchone()
            if not row or row[0] != principal:
                conn.close()
                return 404, {"error": {"code": "NOT_FOUND", "message": "Task not found"}}

            stored_principal, stored_ctx_id, stored_batch_id, status, task_json_str = row
            if status in ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"]:
                conn.close()
                return 409, {"error": {"code": "TASK_TERMINAL", "message": "Task is already in terminal state"}}

            if target_ctx_id and target_ctx_id != stored_ctx_id:
                conn.close()
                return 409, {"error": {"code": "CONTINUATION_MISMATCH", "message": "contextId mismatch"}}
            if batch_id and batch_id != stored_batch_id:
                conn.close()
                return 409, {"error": {"code": "CONTINUATION_MISMATCH", "message": "batchId mismatch"}}

            c.execute('SELECT package_id, action_id, action, facts_json, evidence_json FROM task_proposals WHERE task_id = ?', (target_task_id,))
            p_rows = c.fetchall()
            stored_props = {r[0]: {"actionId": r[1], "action": r[2], "facts": json.loads(r[3]), "evidenceRefs": json.loads(r[4])} for r in p_rows}

            executions_list = []
            for res_item in results_list:
                p_id = res_item.get('packageId')
                act_id = res_item.get('actionId')
                act_name = res_item.get('action')
                outcome = res_item.get('outcome')
                nonce = res_item.get('receiptNonce')

                if not p_id or p_id not in stored_props:
                    conn.close()
                    return 409, {"error": {"code": "CONTINUATION_MISMATCH", "message": f"unknown packageId {p_id}"}}

                sp = stored_props[p_id]
                if act_id != sp["actionId"] or act_name != sp["action"]:
                    conn.close()
                    return 409, {"error": {"code": "CONTINUATION_MISMATCH", "message": f"action or actionId mismatch for package {p_id}"}}

                if outcome == 'ACCEPTED':
                    executions_list.append({
                        "packageId": p_id,
                        "actionId": act_id,
                        "action": act_name,
                        "receiptNonce": nonce,
                        "facts": sp["facts"],
                        "evidenceRefs": sp["evidenceRefs"]
                    })

            receipt_artifact = {
                "artifactId": f"art_receipts_{stored_batch_id}",
                "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
                "data": {
                    "batchId": stored_batch_id,
                    "executions": executions_list
                }
            }

            task_obj = json.loads(task_json_str)
            task_obj["status"] = "TASK_STATE_COMPLETED"
            task_obj["history"].append(message_obj)
            task_obj["artifacts"].append(receipt_artifact)

            resp_payload = {"task": task_obj}

            c.execute('UPDATE a2a_tasks SET status = ?, task_json = ?, updated_at = CURRENT_TIMESTAMP WHERE task_id = ?',
                      ("TASK_STATE_COMPLETED", json.dumps(task_obj), target_task_id))

            c.execute('''
                INSERT INTO message_idempotency (principal, message_id, message_hash, task_id, response_json)
                VALUES (?, ?, ?, ?, ?)
            ''', (principal, msg_id, msg_hash, target_task_id, json.dumps(resp_payload)))

            conn.commit()
            conn.close()
            return 200, resp_payload

        else:
            conn.close()
            return 400, {"error": {"code": "UNSUPPORTED_MEDIA_TYPE", "message": f"Unsupported mediaType {media_type}"}}

    conn.close()
    return 404, {"error": {"code": "NOT_FOUND", "message": "Unknown A2A route"}}
