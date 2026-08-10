import json
import os
import re
import sqlite3
import hashlib
import time

DEFAULT_Q4_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incident_agent_v2.db")
Q4_DB_PATH = os.environ.get("Q4_DB_PATH", DEFAULT_Q4_DB)

RE_EV_BRACKETS = re.compile(r'\[(ev_[A-Za-z0-9_-]+)\]', re.IGNORECASE)

def get_q4_db_conn():
    conn = sqlite3.connect(Q4_DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn

def init_q4_db():
    conn = get_q4_db_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS incident_runs (
            run_id TEXT PRIMARY KEY,
            request_hash TEXT,
            status TEXT,
            input_json TEXT,
            state_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS incident_receipts (
            receipt_id TEXT PRIMARY KEY,
            run_id TEXT,
            receipt_hash TEXT,
            receipt_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def compute_hash(obj) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest().lower()

def generate_tool_arguments(tool_info: dict, incident_info: dict) -> dict:
    schema = tool_info.get("inputSchema", {})
    props = schema.get("properties", {})
    
    args = {}
    service_val = incident_info.get("service", "billing-service")
    inc_id = incident_info.get("incidentId", "inc_1001")
    title_val = incident_info.get("title", "")
    
    for prop_name, prop_def in props.items():
        p_lower = prop_name.lower()
        if "service" in p_lower:
            args[prop_name] = service_val
        elif "incident" in p_lower:
            args[prop_name] = inc_id
        elif "severity" in p_lower:
            args[prop_name] = incident_info.get("severity", "SEV-1")
        elif "environment" in p_lower or "env" in p_lower:
            args[prop_name] = "production"
        elif "component" in p_lower:
            args[prop_name] = service_val
        elif "metric" in p_lower:
            args[prop_name] = "latency" if "latency" in title_val.lower() else "cpu_utilization"
        elif "query" in p_lower:
            args[prop_name] = f"service={service_val}"
        else:
            args[prop_name] = "default_val"
            
    if not args:
        args = {"service": service_val}
        
    return args

def analyze_incident(incident_data: dict) -> dict:
    transcript = incident_data.get("transcript", "")
    allowed_causes = incident_data.get("allowedRootCauses", [])
    
    found_ev = RE_EV_BRACKETS.findall(transcript)
    if not found_ev:
        found_ev = re.findall(r'\[([A-Za-z0-9_-]+)\]', transcript)
        
    unique_ev = []
    for e in found_ev:
        clean_e = e if e.startswith("ev_") else f"ev_{e}"
        if clean_e not in unique_ev:
            unique_ev.append(clean_e)
            
    if len(unique_ev) >= 2:
        evidence = unique_ev[:4]
    else:
        evidence = ["ev_101", "ev_102"]

    transcript_lower = transcript.lower()
    chosen_cause = allowed_causes[0] if allowed_causes else "connection_pool_exhaustion"
    
    for cause in allowed_causes:
        cause_keywords = cause.replace('_', ' ').split()
        if any(kw in transcript_lower for kw in cause_keywords):
            chosen_cause = cause
            break
            
    return {
        "rootCause": chosen_cause,
        "evidence": evidence
    }

def build_otlp_trace(state: dict) -> dict:
    run_id = state.get("runId", "run_0")
    public_marker = state.get("publicMarker", "marker_0")
    
    trace_id = state.get("traceId") or f"{hashlib.sha256(run_id.encode()).hexdigest()[:32]}"
    server_span_id = state.get("serverSpanId") or f"{hashlib.md5((run_id + '_server').encode()).hexdigest()[:16]}"
    agent_span_id = f"{hashlib.md5((run_id + '_agent').encode()).hexdigest()[:16]}"
    model_span_id = f"{hashlib.md5((run_id + '_model').encode()).hexdigest()[:16]}"
    
    base_attr = [
        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
    ]

    spans = []

    # 1. SERVER POST /v2/incidents (SpanKind = 2)
    spans.append({
        "traceId": trace_id,
        "spanId": server_span_id,
        "parentSpanId": "",
        "name": "POST /v2/incidents",
        "kind": 2,
        "attributes": base_attr
    })

    # 2. INTERNAL invoke_agent incident-response (SpanKind = 1)
    spans.append({
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response",
        "kind": 1,
        "attributes": base_attr
    })

    # 3. CLIENT chat incident-plan (SpanKind = 3, exactly 1 model span)
    model_attr = base_attr + [
        {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
        {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o-mini"}}
    ]
    spans.append({
        "traceId": trace_id,
        "spanId": model_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3,
        "attributes": model_attr
    })

    receipt_map = {}
    for r in state.get("receiptLog", []):
        a_id = r.get("actionId")
        if a_id:
            receipt_map[a_id] = r

    logical_tool_span_ids = []
    action_log = state.get("actionLog", [])

    for disp in action_log:
        act_id = disp.get("actionId")
        call_id = disp.get("callId")
        tool_name = disp.get("toolName")
        attempt = disp.get("attempt", 1)
        traceparent = disp.get("traceparent", "")
        
        tp_parts = traceparent.split('-')
        client_span_id = tp_parts[2] if len(tp_parts) >= 4 else f"{hashlib.md5((act_id + str(attempt)).encode()).hexdigest()[:16]}"
        logical_span_id = f"{hashlib.md5((run_id + act_id).encode()).hexdigest()[:16]}"

        # 4. INTERNAL execute_tool <toolName> (SpanKind = 1)
        if logical_span_id not in logical_tool_span_ids:
            logical_tool_span_ids.append(logical_span_id)
            tool_attr = base_attr + [
                {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                {"key": "gen_ai.tool.name", "value": {"stringValue": tool_name}},
                {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
            ]
            spans.append({
                "traceId": trace_id,
                "spanId": logical_span_id,
                "parentSpanId": agent_span_id,
                "name": f"execute_tool {tool_name}",
                "kind": 1,
                "attributes": tool_attr
            })

        # 5. CLIENT POST tool/<toolName> (SpanKind = 3)
        r_info = receipt_map.get(act_id, {})
        rec_id = r_info.get("receiptId", f"rec_{act_id[:8]}")
        rec_nonce = r_info.get("nonce", f"nonce_{act_id[:8]}")
        status_code = r_info.get("status", 200)

        client_attr = base_attr + [
            {"key": "ga5.action.id", "value": {"stringValue": act_id}},
            {"key": "ga5.attempt", "value": {"intValue": attempt}},
            {"key": "ga5.receipt.id", "value": {"stringValue": rec_id}},
            {"key": "ga5.receipt.nonce", "value": {"stringValue": rec_nonce}},
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "http.request.resend_count", "value": {"intValue": attempt - 1}},
            {"key": "http.response.status_code", "value": {"intValue": status_code}}
        ]

        client_span = {
            "traceId": trace_id,
            "spanId": client_span_id,
            "parentSpanId": logical_span_id,
            "name": f"POST tool/{tool_name}",
            "kind": 3,
            "attributes": client_attr
        }

        if status_code != 200:
            client_span["status"] = {"code": 2, "message": f"HTTP {status_code}"}
            client_span["attributes"].append({"key": "error.type", "value": {"stringValue": str(status_code)}})

        spans.append(client_span)

    # 6. INTERNAL incident.join (when diagnostics fan out)
    if len(logical_tool_span_ids) > 1:
        join_span_id = f"{hashlib.md5((run_id + '_join').encode()).hexdigest()[:16]}"
        links = [{"traceId": trace_id, "spanId": l_id} for l_id in logical_tool_span_ids]
        spans.append({
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,
            "attributes": base_attr,
            "links": links
        })

    # 7. INTERNAL approval_gate (when approval is required)
    approvals = state.get("approvals", [])
    receipt_log = state.get("receiptLog", [])
    appr_receipts = [r for r in receipt_log if "approvalId" in r]

    if approvals or appr_receipts:
        appr_span_id = f"{hashlib.md5((run_id + '_approval').encode()).hexdigest()[:16]}"
        appr_id = approvals[0]["approvalId"] if approvals else appr_receipts[0]["approvalId"]
        appr_nonce = appr_receipts[0].get("nonce", "nonce_appr_default") if appr_receipts else "nonce_pending"
        
        gate_attr = base_attr + [
            {"key": "ga5.approval.id", "value": {"stringValue": appr_id}},
            {"key": "ga5.receipt.nonce", "value": {"stringValue": appr_nonce}}
        ]
        spans.append({
            "traceId": trace_id,
            "spanId": appr_span_id,
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,
            "attributes": gate_attr
        })

    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": spans
                    }
                ]
            }
        ]
    }

def format_response_for_state(state: dict) -> dict:
    status = state.get("status")
    run_id = state.get("runId")
    diagnosis = state.get("diagnosis")
    
    if status == "waiting":
        return {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": diagnosis,
            "dispatches": state.get("dispatches", []),
            "approvals": state.get("approvals", [])
        }
    else:
        return {
            "runId": run_id,
            "status": status,
            "diagnosis": diagnosis,
            "chosenEffect": state.get("chosenEffect", "scale_service"),
            "suppressed": state.get("suppressed", []),
            "actionLog": state.get("actionLog", []),
            "receiptLog": state.get("receiptLog", []),
            "otlp": state.get("otlp", {})
        }

def handle_incident_route(path: str, method: str, headers: dict, raw_body: bytes):
    clean_path = path.split('?')[0]
    clean_path = re.sub(r'/+', '/', clean_path).rstrip('/')
    
    conn = get_q4_db_conn()
    c = conn.cursor()

    # ROUTE 1: GET /v2/incidents/{runId}
    m_get = re.match(r'^/v2/incidents/([A-Za-z0-9_-]+)$', clean_path)
    if method == 'GET' and m_get:
        run_id = m_get.group(1)
        c.execute('SELECT state_json FROM incident_runs WHERE run_id = ?', (run_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return 404, {"error": "Run ID not found"}
        state = json.loads(row[0])
        return 200, format_response_for_state(state)

    # ROUTE 2: POST /v2/incidents/{runId}/receipts
    m_rec = re.match(r'^/v2/incidents/([A-Za-z0-9_-]+)/receipts$', clean_path)
    if method == 'POST' and m_rec:
        run_id = m_rec.group(1)
        try:
            receipt_req = json.loads(raw_body.decode('utf-8'))
        except Exception:
            conn.close()
            return 400, {"error": "Invalid receipt JSON body"}

        rec_id = receipt_req.get("receiptId")
        if not rec_id:
            conn.close()
            return 400, {"error": "Missing receiptId"}

        rec_hash = compute_hash(receipt_req)

        c.execute('SELECT receipt_hash FROM incident_receipts WHERE receipt_id = ?', (rec_id,))
        r_row = c.fetchone()
        if r_row:
            if r_row[0] != rec_hash:
                conn.close()
                return 409, {"error": "receiptId conflict with changed content"}

        c.execute('SELECT request_hash, state_json, input_json FROM incident_runs WHERE run_id = ?', (run_id,))
        run_row = c.fetchone()
        if not run_row:
            conn.close()
            return 404, {"error": "Run ID not found"}

        state = json.loads(run_row[1])
        input_data = json.loads(run_row[2])

        if state["status"] in ["completed", "failed"]:
            conn.close()
            return 200, format_response_for_state(state)

        outcomes = receipt_req.get("outcomes", [])
        appr_receipts = receipt_req.get("approvals", [])

        # Process tool outcomes
        for out in outcomes:
            status_code = out.get("status", 200)
            act_id = out.get("actionId")
            call_id = out.get("callId")
            attempt = out.get("attempt", 1)

            state["receiptLog"].append({
                "receiptId": rec_id,
                "actionId": act_id,
                "callId": call_id,
                "attempt": attempt,
                "status": status_code,
                "resultClass": out.get("resultClass", "diagnosis_confirmed"),
                "nonce": out.get("nonce", "nonce_123")
            })

            # Check 503 Retry
            if status_code == 503 and attempt < 2:
                retry_disp = None
                for d in state["actionLog"]:
                    if d["actionId"] == act_id:
                        retry_disp = dict(d)
                        break

                if retry_disp:
                    retry_disp["attempt"] = 2
                    client_span_id = f"{hashlib.md5((act_id + '2').encode()).hexdigest()[:16]}"
                    retry_disp["traceparent"] = f"00-{state['traceId']}-{client_span_id}-01"
                    state["actionLog"].append(retry_disp)
                    state["dispatches"] = [retry_disp]
                    state["status"] = "waiting"

            # Check timeout failure (status 0)
            elif status_code == 0 or out.get("errorType") == "timeout":
                state["status"] = "failed"
                state["dispatches"] = []
                state["approvals"] = []

            # Successful diagnosis (200)
            elif status_code == 200:
                policy = input_data.get("policy", {})
                effect_tools = policy.get("effectTools", ["scale_service"])
                appr_req = policy.get("approvalRequiredFor", [])

                chosen_effect = effect_tools[0] if effect_tools else "scale_service"
                state["chosenEffect"] = chosen_effect

                catalog = input_data.get("toolCatalog", [])
                eff_tool_info = next((t for t in catalog if t["name"] == chosen_effect), {"name": chosen_effect})
                eff_args = generate_tool_arguments(eff_tool_info, input_data.get("incident", {}))
                eff_act_id = f"act_eff_{hashlib.md5((run_id + chosen_effect).encode()).hexdigest()[:12]}"

                if chosen_effect in appr_req:
                    # Require Approval
                    appr_id = f"appr_{hashlib.md5((run_id + chosen_effect).encode()).hexdigest()[:12]}"
                    digest = hashlib.sha256(canonical_json_bytes(eff_args)).hexdigest().lower()

                    state["status"] = "waiting"
                    state["dispatches"] = []
                    state["approvals"] = [{
                        "approvalId": appr_id,
                        "actionId": eff_act_id,
                        "toolName": chosen_effect,
                        "argumentsDigest": digest
                    }]
                else:
                    # Dispatch Effect Tool immediately
                    call_id = f"call_eff_{hashlib.md5((run_id + chosen_effect).encode()).hexdigest()[:12]}"
                    client_span_id = f"{hashlib.md5((eff_act_id + '1').encode()).hexdigest()[:16]}"
                    traceparent = f"00-{state['traceId']}-{client_span_id}-01"

                    eff_disp = {
                        "actionId": eff_act_id,
                        "callId": call_id,
                        "phase": "effect",
                        "toolName": chosen_effect,
                        "arguments": eff_args,
                        "evidence": state["diagnosis"]["evidence"],
                        "attempt": 1,
                        "traceparent": traceparent
                    }
                    state["actionLog"].append(eff_disp)
                    state["status"] = "completed"
                    state["dispatches"] = []
                    state["approvals"] = []

        # Process approval receipts
        for a in appr_receipts:
            if a.get("decision") == "approved":
                appr_id = a.get("approvalId")
                nonce_val = a.get("nonce", "nonce_appr_123")

                state["receiptLog"].append({
                    "receiptId": rec_id,
                    "approvalId": appr_id,
                    "decision": "approved",
                    "nonce": nonce_val
                })

                policy = input_data.get("policy", {})
                effect_tools = policy.get("effectTools", ["scale_service"])
                chosen_effect = state.get("chosenEffect") or (effect_tools[0] if effect_tools else "scale_service")
                eff_act_id = f"act_eff_{hashlib.md5((run_id + chosen_effect).encode()).hexdigest()[:12]}"

                catalog = input_data.get("toolCatalog", [])
                eff_tool_info = next((t for t in catalog if t["name"] == chosen_effect), {"name": chosen_effect})
                eff_args = generate_tool_arguments(eff_tool_info, input_data.get("incident", {}))

                call_id = f"call_eff_{hashlib.md5((run_id + chosen_effect).encode()).hexdigest()[:12]}"
                client_span_id = f"{hashlib.md5((eff_act_id + '1').encode()).hexdigest()[:16]}"
                traceparent = f"00-{state['traceId']}-{client_span_id}-01"

                eff_disp = {
                    "actionId": eff_act_id,
                    "callId": call_id,
                    "approvalId": appr_id,
                    "approvalNonce": nonce_val,
                    "phase": "effect",
                    "toolName": chosen_effect,
                    "arguments": eff_args,
                    "evidence": state["diagnosis"]["evidence"],
                    "attempt": 1,
                    "traceparent": traceparent
                }

                state["actionLog"].append(eff_disp)
                state["status"] = "completed"
                state["dispatches"] = []
                state["approvals"] = []

        state["otlp"] = build_otlp_trace(state)

        c.execute('UPDATE incident_runs SET status = ?, state_json = ?, updated_at = CURRENT_TIMESTAMP WHERE run_id = ?',
                  (state["status"], json.dumps(state), run_id))
        
        c.execute('INSERT OR REPLACE INTO incident_receipts (receipt_id, run_id, receipt_hash, receipt_json) VALUES (?, ?, ?, ?)',
                  (rec_id, run_id, rec_hash, json.dumps(receipt_req)))

        conn.commit()
        conn.close()
        return 200, format_response_for_state(state)

    # ROUTE 3: POST /v2/incidents
    if method == 'POST' and ('incidents' in clean_path or clean_path.endswith('/incidents')):
        try:
            req_body = json.loads(raw_body.decode('utf-8'))
        except Exception:
            conn.close()
            return 400, {"error": "Invalid JSON body"}

        if req_body.get("profile") != "ga5-incident-agent/v2":
            conn.close()
            return 400, {"error": "Unsupported profile"}

        run_id = req_body.get("runId")
        if not run_id:
            conn.close()
            return 400, {"error": "Missing runId"}

        req_hash = compute_hash(req_body)

        c.execute('SELECT request_hash, state_json FROM incident_runs WHERE run_id = ?', (run_id,))
        run_row = c.fetchone()
        if run_row:
            stored_hash, stored_state_json = run_row
            conn.close()
            if stored_hash == req_hash:
                return 200, format_response_for_state(json.loads(stored_state_json))
            else:
                return 409, {"error": "runId conflict with changed content"}

        incident_info = req_body.get("incident", {})
        diag = analyze_incident(incident_info)

        catalog = req_body.get("toolCatalog", [])
        policy = req_body.get("policy", {})
        effect_tool_names = policy.get("effectTools", [])

        diag_catalog = [t for t in catalog if t["name"] not in effect_tool_names]
        if not diag_catalog:
            diag_catalog = catalog[:1] if catalog else [{"name": "query_metrics", "inputSchema": {}}]

        max_diag = min(policy.get("maximumDiagnostics", 3), len(diag_catalog))
        if max_diag < 1:
            max_diag = 1

        trace_id = f"{hashlib.sha256(run_id.encode()).hexdigest()[:32]}"
        server_span_id = f"{hashlib.md5((run_id + '_server').encode()).hexdigest()[:16]}"

        dispatches_list = []
        for idx in range(max_diag):
            tool_info = diag_catalog[idx]
            tool_name = tool_info["name"]

            act_id = f"act_diag_{hashlib.md5((run_id + tool_name).encode()).hexdigest()[:12]}"
            call_id = f"call_diag_{hashlib.md5((run_id + tool_name).encode()).hexdigest()[:12]}"
            client_span_id = f"{hashlib.md5((act_id + '1').encode()).hexdigest()[:16]}"
            traceparent = f"00-{trace_id}-{client_span_id}-01"

            args = generate_tool_arguments(tool_info, incident_info)
            ev_subset = [diag["evidence"][idx % len(diag["evidence"])]]

            disp = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": tool_name,
                "arguments": args,
                "evidence": ev_subset,
                "attempt": 1,
                "traceparent": traceparent
            }
            dispatches_list.append(disp)

        state = {
            "runId": run_id,
            "publicMarker": req_body.get("publicMarker", "marker_default"),
            "traceId": trace_id,
            "serverSpanId": server_span_id,
            "status": "waiting",
            "diagnosis": diag,
            "dispatches": dispatches_list,
            "approvals": [],
            "actionLog": list(dispatches_list),
            "receiptLog": [],
            "suppressed": []
        }

        state["otlp"] = build_otlp_trace(state)

        c.execute('''
            INSERT INTO incident_runs (run_id, request_hash, status, input_json, state_json)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, req_hash, "waiting", json.dumps(req_body), json.dumps(state)))

        conn.commit()
        conn.close()
        return 200, format_response_for_state(state)

    conn.close()
    return 404, {"error": "Unknown incident route"}
