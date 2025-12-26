"""
Base runtime for MAAIS-Runtime.

Provides a lightweight `Runtime` wrapper around the existing
`MultiTenantRuntime` implementation in `core.multitenant.tenant_manager`.

This file existed as an empty placeholder; provide a minimal, well-behaved
implementation so imports and demos have a reliable runtime to use.
"""
from typing import Dict, Any, Optional

from core.multitenant.tenant_manager import MultiTenantRuntime, TenantManager
from core.models import ActionRequest, Decision


class Runtime:
    """Simple runtime facade.

    This class wraps the fuller multi-tenant runtime and exposes the
    common, well-documented methods used across demos and tests.
    """

    def __init__(self, tenant_manager: Optional[TenantManager] = None, config: Dict[str, Any] = None):
        self.tenant_manager = tenant_manager or TenantManager()
        # Use the existing multi-tenant runtime implementation
        self._mt_runtime = MultiTenantRuntime(self.tenant_manager)
        self.config = config or {}

    def intercept(self, action: ActionRequest) -> Decision:
        """Evaluate an `ActionRequest` and return a `Decision`."""
        return self._mt_runtime.intercept(action)

    def set_anomaly_detector(self, detector):
        """Set a global anomaly detector."""
        self._mt_runtime.set_anomaly_detector(detector)

    def set_webhook_manager(self, webhook_manager):
        """Set a global webhook manager."""
        self._mt_runtime.set_webhook_manager(webhook_manager)

    def health_check(self) -> Dict[str, Any]:
        """Return a health summary for the runtime."""
        return self._mt_runtime.health_check()

    def shutdown(self):
        """Perform graceful shutdown tasks."""
        # If the multi-tenant runtime exposes shutdown in the future, call it.
        if hasattr(self._mt_runtime, 'shutdown'):
            try:
                self._mt_runtime.shutdown()
            except Exception:
                # Best-effort shutdown; do not raise during cleanup
                pass


# Convenience singleton factory used by demos/tests
_runtime_instance: Optional[Runtime] = None


def get_runtime(config: Dict[str, Any] = None) -> Runtime:
    global _runtime_instance
    if _runtime_instance is None:
        _runtime_instance = Runtime(config=config)
    return _runtime_instance
