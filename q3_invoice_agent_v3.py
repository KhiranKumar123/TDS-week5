"""Q3 V3 overlay: bind every continuation to the persisted proposal before terminalizing."""
import json
import re
import q3_invoice_agent_v2 as v2

base = v2.base


def handle_a2a_route(path, method, headers, raw_body, base_url):
    clean = path.split("?")[0].rstrip("/")
    if method != "POST" or not clean.endswith("message:send"):
        return v2.handle_a2a_route(path, method, headers, raw_body, base_url)

    # Preserve exact message replay: the underlying implementation has already
    # persisted the complete response keyed by (principal,messageId).
    try:
        req = json.loads(raw_body.decode("utf-8"))
        msg = req.get("message") or {}
        parts = msg.get("parts") or []
        if not parts or parts[0].get("mediaType") != "application/vnd.ga5.invoice-action-results+json":
            return v2.handle_a2a_route(path, method, headers, raw_body, base_url)
        principal = base.extract_principal(headers)
        msg_id = msg.get("messageId")
        if principal and isinstance(msg_id, str):
            conn = base.get_db_conn(); c = conn.cursor()
            c.execute("SELECT message_hash FROM message_idempotency WHERE principal=? AND message_id=?", (principal, msg_id))
            old = c.fetchone()
            if old and old[0] == base.compute_hash(msg):
                conn.close()
                return v2.handle_a2a_route(path, method, headers, raw_body, base_url)
            conn.close()
    except Exception:
        pass

    # For a new continuation, validate the entire receipt set against the
    # persisted task/proposals. Do this before the wrapped implementation can
    # transition the task to COMPLETED.
    try:
        req = json.loads(raw_body.decode("utf-8")); msg = req["message"]
        task_id = msg["taskId"]; ctx_id = msg["contextId"]
        data = msg["parts"][0]["data"]
        results = data["results"]
        principal = base.extract_principal(headers)
        conn = base.get_db_conn(); c = conn.cursor()
        c.execute("SELECT principal, context_id, batch_id, status FROM a2a_tasks WHERE task_id=?", (task_id,))
        row = c.fetchone()
        if not row or row[0] != principal:
            conn.close(); return 404, {"error":{"code":"NOT_FOUND","message":"Task not found"}}
        if row[3] in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"):
            conn.close(); return 409, {"error":{"code":"TASK_TERMINAL","message":"Task is already terminal"}}
        if row[1] != ctx_id or row[2] != data.get("batchId"):
            conn.close(); return 409, {"error":{"code":"CONTINUATION_MISMATCH","message":"Task context does not match"}}
        c.execute("SELECT package_id, action_id, action FROM task_proposals WHERE task_id=?", (task_id,))
        stored = {r[0]:(r[1],r[2]) for r in c.fetchall()}
        if len(results) != len(stored) or {r.get("packageId") for r in results} != set(stored):
            conn.close(); return 409, {"error":{"code":"CONTINUATION_MISMATCH","message":"Receipt set does not match proposals"}}
        seen_nonces=set()
        for r in results:
            pid=r.get("packageId"); aid=r.get("actionId"); act=r.get("action"); nonce=r.get("receiptNonce")
            if pid not in stored or (aid,act) != stored[pid] or not isinstance(nonce,str) or not nonce or nonce in seen_nonces:
                conn.close(); return 409, {"error":{"code":"RECEIPT_BINDING","message":"Receipt does not match the stored proposal"}}
            if r.get("outcome") not in ("ACCEPTED","REJECTED"):
                conn.close(); return 400, {"error":{"code":"INVALID_CONTINUATION","message":"Invalid receipt outcome"}}
            seen_nonces.add(nonce)
        conn.close()
    except Exception:
        return 400, {"error":{"code":"INVALID_CONTINUATION","message":"Invalid result continuation"}}

    # v2 owns the single-process serialization for cancel-vs-result.
    return v2.handle_a2a_route(path, method, headers, raw_body, base_url)

init_q3_db = base.init_q3_db
