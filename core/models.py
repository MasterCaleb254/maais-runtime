"""
MAAIS-Runtime Core Data Models
Authoritative definitions - any deviation is a security bug
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """All possible action types an agent can perform"""
    TOOL_CALL = "tool_call"
    API_CALL = "api_call"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    DATABASE_QUERY = "database_query"
    NETWORK_REQUEST = "network_request"


@dataclass
class ActionRequest:
    """
    Normalized action request schema.
    All agent actions must be converted to this format before evaluation.
    """
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    action_type: ActionType
    target: str  # Tool/API/Resource name
    parameters: Dict[str, Any]
    declared_goal: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    context: Dict[str, Any] = field(default_factory=dict)  # Additional context
    
    def __post_init__(self):
        """Validate the action request"""
        if not self.agent_id:
            raise ValueError("agent_id is required")
        if not self.target:
            raise ValueError("target is required")


@dataclass
class Decision:
    """
    Security decision for an action request.
    """
    allow: bool
    policy_id: Optional[str] = None
    explanation: str = ""
    ciaa_violations: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    accountability_owner: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        return {
            "allow": self.allow,
            "policy_id": self.policy_id,
            "explanation": self.explanation,
            "ciaa_violations": self.ciaa_violations,
            "timestamp": self.timestamp.isoformat(),
            "accountability_owner": self.accountability_owner
        }


@dataclass
class Policy:
    """Security policy definition"""
    id: str
    applies_to: List[ActionType]
    condition: Dict[str, Any]
    decision: str  # "ALLOW" or "DENY"
    reason: str
    priority: int = 100  # Lower = higher priority
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountabilityRecord:
    """Accountability tracking record"""
    action_id: str
    agent_id: str
    policy_id: Optional[str]
    responsibility_owner: str
    decision: bool
    explanation: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass 
class AuditEvent:
    """Immutable audit event with hash chaining"""
    hash: str
    previous_hash: str
    action_request: ActionRequest
    decision: Decision
    ciaa_evaluation: Dict[str, str]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage"""
        return {
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "action_request": {
                "action_id": self.action_request.action_id,
                "agent_id": self.action_request.agent_id,
                "action_type": self.action_request.action_type.value,
                "target": self.action_request.target,
                "parameters": self.action_request.parameters,
                "declared_goal": self.action_request.declared_goal,
                "timestamp": self.action_request.timestamp.isoformat()
            },
            "decision": self.decision.to_dict(),
            "ciaa_evaluation": self.ciaa_evaluation,
            "timestamp": self.timestamp.isoformat()
        }


# Pydantic models for YAML parsing
class PolicyRule(BaseModel):
    """YAML policy rule schema"""
    id: str
    applies_to: List[str] | str
    condition: Dict[str, Any]
    decision: str
    reason: str
    priority: Optional[int] = 100
    
    class Config:
        extra = "forbid"  # No extra fields allowed


class PolicyConfig(BaseModel):
    """YAML policy configuration"""
    policies: List[PolicyRule]
    
    class Config:
        extra = "forbid"