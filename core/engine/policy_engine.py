"""
Policy Engine for MAAIS-Runtime
Evaluates actions against security policies (first-match wins)
"""
import yaml
import re
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from core.models import ActionRequest, ActionType, PolicyRule, PolicyConfig


class PolicyEngine:
    """YAML-based policy engine with deterministic evaluation"""
    
    def __init__(self, policy_file: str = "policies/static/security_policies.yaml"):
        self.policy_file = Path(policy_file)
        self.policies: List[PolicyRule] = []
        self._load_policies()
    
    def _load_policies(self) -> None:
        """Load and validate policies from YAML file"""
        if not self.policy_file.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_file}")
        
        with open(self.policy_file, 'r') as f:
            data = yaml.safe_load(f)
        
        config = PolicyConfig(**data)
        # Sort by priority (lower = higher priority)
        self.policies = sorted(config.policies, key=lambda p: p.priority)
        
        print(f"Loaded {len(self.policies)} policies from {self.policy_file}")
    
    def evaluate(self, action: ActionRequest) -> Optional[str]:
        """
        Evaluate action against policies.
        Returns policy_id if denied, None if allowed.
        """
        for policy in self.policies:
            if self._policy_applies(policy, action) and self._conditions_match(policy, action):
                if policy.decision == "DENY":
                    return policy.id
                # If ALLOW policy matches, continue to next policy
                # (first DENY wins)
        
        return None  # No denying policy matched
    
    def _policy_applies(self, policy: PolicyRule, action: ActionRequest) -> bool:
        """Check if policy applies to this action type"""
        applies_to = policy.applies_to
        
        if isinstance(applies_to, str):
            applies_to = [applies_to]
        
        # Wildcard applies to all actions
        if "*" in applies_to:
            return True
        
        # Check if action type matches
        return action.action_type.value in applies_to
    
    def _conditions_match(self, policy: PolicyRule, action: ActionRequest) -> bool:
        """Evaluate if action matches policy conditions"""
        conditions = policy.condition
        
        # Empty conditions match everything
        if not conditions:
            return True
        
        # Check each condition
        for key, value in conditions.items():
            if key == "target":
                if not self._match_target(value, action.target):
                    return False
            elif key == "parameters":
                if not self._match_parameters(value, action.parameters):
                    return False
            elif key == "rate_limit":
                # Simplified rate limiting (will be enhanced later)
                pass  # TODO: Implement rate limiting
            elif key == "or":
                # OR condition
                if not self._match_or_condition(value, action):
                    return False
            elif key == "and":
                # AND condition
                if not self._match_and_condition(value, action):
                    return False
            elif key == "pattern":
                # Regex pattern matching
                if not re.match(value, str(action.target)):
                    return False
        
        return True
    
    def _match_target(self, condition: Any, target: str) -> bool:
        """Match target condition"""
        if isinstance(condition, str):
            return condition == target
        elif isinstance(condition, dict):
            if "in" in condition:
                return target in condition["in"]
            elif "pattern" in condition:
                return bool(re.match(condition["pattern"], target))
        elif isinstance(condition, list):
            return target in condition
        
        return False
    
    def _match_parameters(self, condition: Dict[str, Any], parameters: Dict[str, Any]) -> bool:
        """Match parameters condition"""
        for param_key, param_condition in condition.items():
            if param_key not in parameters:
                return False
            
            param_value = parameters[param_key]
            
            if isinstance(param_condition, dict):
                if "pattern" in param_condition:
                    if not re.match(param_condition["pattern"], str(param_value)):
                        return False
                elif "in" in param_condition:
                    if param_value not in param_condition["in"]:
                        return False
            else:
                if param_value != param_condition:
                    return False
        
        return True
    
    def _match_or_condition(self, conditions: List[Dict], action: ActionRequest) -> bool:
        """Match OR condition (any must be true)"""
        for condition in conditions:
            if self._conditions_match(PolicyRule(**{"condition": condition}), action):
                return True
        return False
    
    def _match_and_condition(self, conditions: List[Dict], action: ActionRequest) -> bool:
        """Match AND condition (all must be true)"""
        for condition in conditions:
            if not self._conditions_match(PolicyRule(**{"condition": condition}), action):
                return False
        return True
    
    def reload_policies(self) -> None:
        """Reload policies from file (for hot reloading)"""
        self._load_policies()