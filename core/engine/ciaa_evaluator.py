"""
CIAA (Confidentiality, Integrity, Availability, Accountability) Evaluator
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from core.models import ActionRequest, ActionType


class CIAAEvaluator:
    """
    Evaluates actions against CIAA constraints.
    Returns dict of violations (empty = pass).
    """
    
    def __init__(self):
        # Rate limiting state
        self.action_counts = defaultdict(list)
        self.rate_windows = {
            "minute": timedelta(minutes=1),
            "hour": timedelta(hours=1),
            "day": timedelta(days=1)
        }
        
        # Sensitive patterns (in real implementation, load from config)
        self.sensitive_patterns = [
            r"(?i)(password|secret|token|key|credential)",
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone numbers
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Emails
        ]
    
    def evaluate(self, action: ActionRequest) -> Dict[str, str]:
        """
        Evaluate action against CIAA constraints.
        Returns dict of violations: {"C": "reason", "I": "reason", ...}
        """
        violations = {}
        
        # Confidentiality checks
        if self._violates_confidentiality(action):
            violations["C"] = self._violates_confidentiality(action)
        
        # Integrity checks
        if self._violates_integrity(action):
            violations["I"] = self._violates_integrity(action)
        
        # Availability checks (rate limiting)
        if self._violates_availability(action):
            violations["A"] = self._violates_availability(action)
        
        # Accountability is checked separately by AccountabilityResolver
        
        return violations
    
    def _violates_confidentiality(self, action: ActionRequest) -> Optional[str]:
        """Check for sensitive data exfiltration"""
        
        # Check parameters for sensitive data
        params_str = str(action.parameters).lower()
        
        for pattern in self.sensitive_patterns:
            import re
            if re.search(pattern, params_str):
                return f"Sensitive data pattern detected in parameters: {pattern}"
        
        # Check for external data transfer
        if action.action_type == ActionType.TOOL_CALL:
            if action.target in ["http_request", "send_email", "upload_file"]:
                # Check if destination is external
                url = action.parameters.get("url", "")
                if "http" in url and not any(domain in url for domain in ["localhost", "127.0.0.1", "internal"]):
                    return "Attempting to send data to external destination"
        
        return None
    
    def _violates_integrity(self, action: ActionRequest) -> Optional[str]:
        """Check for unauthorized state mutation"""
        
        # Prevent writes to critical system locations
        if action.action_type in [ActionType.FILE_WRITE, ActionType.MEMORY_WRITE]:
            target = action.target.lower()
            critical_paths = ["/etc/", "/bin/", "/usr/bin/", "/system/", "config.yaml"]
            
            for path in critical_paths:
                if path in target:
                    return f"Attempting to write to critical location: {target}"
        
        # Prevent system modifications
        if action.action_type == ActionType.TOOL_CALL:
            dangerous_tools = ["execute_command", "install_package", "modify_system"]
            if action.target in dangerous_tools:
                return f"Dangerous system modification attempt: {action.target}"
        
        return None
    
    def _violates_availability(self, action: ActionRequest) -> Optional[str]:
        """Check for resource abuse"""
        
        # Simple rate limiting
        now = datetime.utcnow()
        key = f"{action.agent_id}:{action.action_type.value}:{action.target}"
        
        # Clean old entries
        self.action_counts[key] = [
            ts for ts in self.action_counts[key]
            if now - ts < self.rate_windows["minute"]
        ]
        
        # Check rate limit
        if len(self.action_counts[key]) >= self._get_rate_limit(action):
            return f"Rate limit exceeded: {len(self.action_counts[key])} calls in last minute"
        
        # Add current call
        self.action_counts[key].append(now)
        
        return None
    
    def _get_rate_limit(self, action: ActionRequest) -> int:
        """Get rate limit for action type"""
        limits = {
            ActionType.DATABASE_QUERY: 50,
            ActionType.MEMORY_READ: 100,
            ActionType.API_CALL: 30,
            ActionType.NETWORK_REQUEST: 10,
        }
        
        return limits.get(action.action_type, 100)  # Default 100/min
    
    def reset_counters(self) -> None:
        """Reset rate limiting counters (for testing)"""
        self.action_counts.clear()