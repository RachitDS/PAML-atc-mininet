"""Compatibility entry point for the corrected observation controller.

Use run_campaign.sh with an experiment manifest for scored lab evaluation.
The previous implementation is retained in ryu_paml_controller.py.legacy.
"""
from controller.auditable_controller import AuditableController


class PAMLATCRyuController(AuditableController):
    pass
