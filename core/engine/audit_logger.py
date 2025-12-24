"""
Immutable Audit Logger with Hash Chaining
"""
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import ActionRequest, Decision, AuditEvent


class AuditLogger:
    """Append-only, hash-chained audit logger"""
    
    def __init__(self, log_dir: str = "audit/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create daily log file
        self.log_file = self.log_dir / f"audit_{datetime.utcnow().date()}.log"
        self.last_hash = self._load_last_hash()
    
    def _load_last_hash(self) -> str:
        """Load last hash from previous log entry"""
        if not self.log_file.exists():
            return "0" * 64  # Genesis hash
        
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            if lines:
                last_line = json.loads(lines[-1].strip())
                return last_line.get("hash", "0" * 64)
        
        return "0" * 64
    
    def _calculate_hash(self, data: dict, previous_hash: str) -> str:
        """Calculate SHA-256 hash for data with previous hash"""
        data_str = json.dumps(data, sort_keys=True) + previous_hash
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def append(self, action: ActionRequest, decision: Decision, ciaa_evaluation: dict) -> None:
        """Append immutable audit event"""
        # Create audit event
        event_data = {
            "action_request": {
                "action_id": action.action_id,
                "agent_id": action.agent_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "parameters": action.parameters,
                "declared_goal": action.declared_goal,
                "timestamp": action.timestamp.isoformat()
            },
            "decision": decision.to_dict(),
            "ciaa_evaluation": ciaa_evaluation,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Calculate hash with chain
        event_hash = self._calculate_hash(event_data, self.last_hash)
        
        # Create final event
        audit_event = {
            "hash": event_hash,
            "previous_hash": self.last_hash,
            **event_data
        }
        
        # Append to log file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(audit_event) + '\n')
        
        # Update last hash
        self.last_hash = event_hash
        
        print(f"[AUDIT] Event logged: {action.action_id} -> {'ALLOW' if decision.allow else 'DENY'}")
    
    def verify_chain(self) -> bool:
        """Verify hash chain integrity"""
        if not self.log_file.exists():
            return True
        
        previous_hash = "0" * 64
        
        with open(self.log_file, 'r') as f:
            for line in f:
                event = json.loads(line.strip())
                
                # Verify previous hash matches
                if event["previous_hash"] != previous_hash:
                    return False
                
                # Recalculate hash
                event_data = {k: v for k, v in event.items() if k not in ["hash", "previous_hash"]}
                calculated_hash = self._calculate_hash(event_data, previous_hash)
                
                if event["hash"] != calculated_hash:
                    return False
                
                previous_hash = event["hash"]
        
        return True
    
    def get_recent_events(self, limit: int = 100) -> list:
        """Get recent audit events"""
        events = []
        
        if not self.log_file.exists():
            return events
        
        with open(self.log_file, 'r') as f:
            lines = f.readlines()[-limit:]
            for line in lines:
                events.append(json.loads(line.strip()))
        
        return list(reversed(events))  # Newest first