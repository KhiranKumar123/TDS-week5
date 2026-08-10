# Q3-only activation layer. Python imports sitecustomize before server.py.
# Q1 and Q2 code in server.py are untouched. Q3 is routed through V3,
# which wraps the durable baseline implementation with strict protocol,
# evidence-first decisions, receipt binding, and race serialization.
import sys
try:
    import q3_invoice_agent_v3
    sys.modules["q3_invoice_agent"] = q3_invoice_agent_v3
except Exception as exc:
    print("Q3 overlay disabled:", exc)
