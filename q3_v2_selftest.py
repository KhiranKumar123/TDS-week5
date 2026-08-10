# Lightweight offline smoke test for the Q3 V2 decision layer.
from q3_invoice_agent_v2 import improved_decision

pkg = {
  "packageId": "p1",
  "invoice": {"vendorName":"Acme", "invoiceNumber":"INV-1", "amountMinor":12500, "currency":"INR"},
  "sources": [{"title":"case", "lines":[
    {"lineId":"L1", "text":"Invoice INV-1 is fully reconciled and within delegated authority. [A1] [A2] [A3]"},
    {"lineId":"L2", "text":"Archive example: request approval for high value invoices. [X1] [X2] [X3]"}
  ]}]
}
r = improved_decision(pkg)
assert r["action"] == "settle_invoice", r
assert r["facts"]["vendorName"] == "Acme", r
assert r["facts"]["invoiceNumber"] == "INV-1", r
assert r["facts"]["amountMinor"] == 12500, r
assert r["facts"]["currency"] == "INR", r
assert r["evidenceRefs"] == ["[A1]", "[A2]", "[A3]"], r
print("Q3 V2 decision smoke test passed")
