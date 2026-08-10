# Q3-only activation layer. Python imports sitecustomize before server.py.
# Q1 and Q2 code in server.py are untouched; only the q3_invoice_agent module
# imported by the router is replaced by the V2 wrapper.
import sys
try:
    import q3_invoice_agent_v2
    sys.modules["q3_invoice_agent"] = q3_invoice_agent_v2
except Exception as exc:
    # Do not prevent the service from starting if the optional Q3 overlay fails.
    print("Q3 overlay disabled:", exc)
