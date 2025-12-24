"""
Policy Learning Engine
Suggests new policies based on blocked actions and patterns
"""
import json
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import yaml

from core.models import ActionRequest, Decision, ActionType


@dataclass
class PolicySuggestion:
    """Suggested policy based on learned patterns"""
    id: str
    pattern: Dict[str, Any]
    confidence: float
    reason: str
    example_actions: List[Dict] = field(default_factory=list)
    blocked_count: int = 0
    suggested_policy: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "pattern": self.pattern,
            "confidence": self.confidence,
            "reason": self.reason,
            "example_actions": self.example_actions,
            "blocked_count": self.blocked_count,
            "suggested_policy": self.suggested_policy
        }


class PolicyLearner:
    """
    Learns patterns from blocked actions and suggests new policies
    """
    
    def __init__(self, learning_window: int = 1000):
        self.learning_window = learning_window
        self.blocked_actions: List[Tuple[ActionRequest, Decision]] = []
        self.learned_patterns: Dict[str, PolicySuggestion] = {}
        self.action_clusters: Dict[str, List] = defaultdict(list)
        
        # Feature extractors for different action types
        self.feature_extractors = {
            ActionType.TOOL_CALL: self._extract_tool_features,
            ActionType.API_CALL: self._extract_api_features,
            ActionType.NETWORK_REQUEST: self._extract_network_features,
            ActionType.DATABASE_QUERY: self._extract_db_features,
            ActionType.FILE_WRITE: self._extract_file_features
        }
        
        print(f"PolicyLearner initialized with window={learning_window}")
    
    def add_blocked_action(self, action: ActionRequest, decision: Decision):
        """Add a blocked action for learning"""
        self.blocked_actions.append((action, decision))
        
        # Maintain window size
        if len(self.blocked_actions) > self.learning_window:
            self.blocked_actions.pop(0)
        
        # Extract features for clustering
        self._cluster_action(action, decision)
        
        # Check for new patterns periodically
        if len(self.blocked_actions) % 100 == 0:
            self._analyze_patterns()
    
    def _cluster_action(self, action: ActionRequest, decision: Decision):
        """Cluster similar blocked actions"""
        cluster_key = self._get_cluster_key(action, decision)
        self.action_clusters[cluster_key].append({
            "action": action,
            "decision": decision,
            "timestamp": datetime.utcnow()
        })
        
        # Trim old actions in cluster
        if len(self.action_clusters[cluster_key]) > 50:
            self.action_clusters[cluster_key] = self.action_clusters[cluster_key][-50:]
    
    def _get_cluster_key(self, action: ActionRequest, decision: Decision) -> str:
        """Create cluster key for similar actions"""
        parts = []
        
        # Action type
        parts.append(action.action_type.value)
        
        # Target
        parts.append(action.target)
        
        # Policy that blocked it
        if decision.policy_id:
            parts.append(decision.policy_id)
        
        # CIAA violation type
        if decision.ciaa_violations:
            parts.append(",".join(sorted(decision.ciaa_violations.keys())))
        
        return ":".join(parts)
    
    def _extract_tool_features(self, action: ActionRequest) -> Dict[str, Any]:
        """Extract features from tool call"""
        features = {
            "tool_name": action.target,
            "param_count": len(action.parameters),
            "param_keys": list(action.parameters.keys()),
            "has_external": any(
                "http" in str(v).lower() or "api" in str(v).lower()
                for v in action.parameters.values()
            )
        }
        
        # Check for sensitive data in parameters
        sensitive_patterns = [
            r"(?i)password", r"(?i)secret", r"(?i)token", r"(?i)key",
            r"(?i)credit.?card", r"(?i)ssn", r"\d{3}[-.]?\d{2}[-.]?\d{4}"  # SSN
        ]
        
        param_str = json.dumps(action.parameters).lower()
        features["has_sensitive"] = any(
            re.search(pattern, param_str) for pattern in sensitive_patterns
        )
        
        return features
    
    def _extract_api_features(self, action: ActionRequest) -> Dict[str, Any]:
        """Extract features from API call"""
        features = {
            "api_endpoint": action.target,
            "param_count": len(action.parameters)
        }
        
        # Check for external domains
        if "url" in action.parameters:
            url = str(action.parameters["url"]).lower()
            features["is_external"] = not any(
                domain in url for domain in ["localhost", "127.0.0.1", "internal", "192.168", "10."]
            )
        
        return features
    
    def _extract_network_features(self, action: ActionRequest) -> Dict[str, Any]:
        """Extract features from network request"""
        features = {
            "destination": action.target,
            "has_data": "data" in action.parameters
        }
        
        if "data" in action.parameters:
            data_str = str(action.parameters["data"])
            features["data_size"] = len(data_str)
            features["data_has_json"] = "{" in data_str or "[" in data_str
        
        return features
    
    def _extract_db_features(self, action: ActionRequest) -> Dict[str, Any]:
        """Extract features from database query"""
        features = {
            "query_type": self._classify_query(action.target),
            "has_where": "WHERE" in action.target.upper() if action.target else False,
            "has_join": "JOIN" in action.target.upper() if action.target else False
        }
        
        # Check for sensitive tables
        sensitive_tables = ["users", "customers", "payments", "credentials"]
        features["sensitive_table"] = any(
            table in action.target.lower() for table in sensitive_tables
        )
        
        return features
    
    def _extract_file_features(self, action: ActionRequest) -> Dict[str, Any]:
        """Extract features from file operation"""
        features = {
            "operation": action.action_type.value,
            "filename": action.target,
            "is_system_path": any(
                path in action.target for path in ["/etc/", "/bin/", "/usr/", "/system/"]
            )
        }
        
        # Check file extension
        if "." in action.target:
            ext = action.target.split(".")[-1].lower()
            features["extension"] = ext
            features["is_executable"] = ext in ["exe", "sh", "bat", "py", "js"]
        
        return features
    
    def _classify_query(self, query: str) -> str:
        """Classify SQL query type"""
        query_upper = query.upper()
        
        if query_upper.startswith("SELECT"):
            return "SELECT"
        elif query_upper.startswith("INSERT"):
            return "INSERT"
        elif query_upper.startswith("UPDATE"):
            return "UPDATE"
        elif query_upper.startswith("DELETE"):
            return "DELETE"
        elif query_upper.startswith("DROP"):
            return "DROP"
        elif query_upper.startswith("CREATE"):
            return "CREATE"
        else:
            return "OTHER"
    
    def _analyze_patterns(self):
        """Analyze blocked actions for patterns"""
        if len(self.blocked_actions) < 10:
            return  # Need more data
        
        print(f"Analyzing {len(self.blocked_actions)} blocked actions for patterns...")
        
        # Analyze clusters
        for cluster_key, actions in self.action_clusters.items():
            if len(actions) >= 3:  # Need multiple examples
                self._analyze_cluster(cluster_key, actions)
        
        # Analyze by agent
        self._analyze_agent_patterns()
        
        # Analyze by time
        self._analyze_temporal_patterns()
    
    def _analyze_cluster(self, cluster_key: str, actions: List[Dict]):
        """Analyze a cluster of similar blocked actions"""
        # Extract common features
        action_samples = [a["action"] for a in actions[-5:]]  # Last 5 actions
        
        if not action_samples:
            return
        
        # Get decision for first action
        decision = actions[0]["decision"]
        
        # Create pattern based on common features
        first_action = action_samples[0]
        extractor = self.feature_extractors.get(first_action.action_type)
        
        if not extractor:
            return
        
        features = extractor(first_action)
        
        # Check if we already have a pattern for this
        pattern_id = f"pattern_{hash(cluster_key) % 10000:04d}"
        
        if pattern_id not in self.learned_patterns:
            # Create new suggestion
            suggestion = PolicySuggestion(
                id=pattern_id,
                pattern=features,
                confidence=len(actions) / 10.0,  # More examples = higher confidence
                reason=f"Pattern detected in {len(actions)} blocked actions",
                example_actions=[
                    {
                        "agent_id": a.agent_id,
                        "target": a.target,
                        "parameters": a.parameters,
                        "goal": a.declared_goal
                    }
                    for a in action_samples[:3]  # First 3 examples
                ],
                blocked_count=len(actions),
                suggested_policy=self._create_suggested_policy(first_action, decision, features)
            )
            
            self.learned_patterns[pattern_id] = suggestion
            print(f"  Discovered pattern {pattern_id} with confidence {suggestion.confidence:.2f}")
    
    def _analyze_agent_patterns(self):
        """Analyze patterns by agent"""
        agent_actions = defaultdict(list)
        
        for action, decision in self.blocked_actions:
            agent_actions[action.agent_id].append((action, decision))
        
        for agent_id, actions in agent_actions.items():
            if len(actions) >= 5:  # Agent has multiple blocks
                # Check if agent is repeating the same mistake
                action_types = Counter(a.action_type for a, _ in actions)
                most_common = action_types.most_common(1)[0]
                
                if most_common[1] >= 3:  # Same action type blocked multiple times
                    pattern_id = f"agent_{agent_id}_{most_common[0].value}"
                    
                    if pattern_id not in self.learned_patterns:
                        suggestion = PolicySuggestion(
                            id=pattern_id,
                            pattern={"agent_id": agent_id, "action_type": most_common[0].value},
                            confidence=most_common[1] / 10.0,
                            reason=f"Agent {agent_id} repeatedly blocked for {most_common[0].value}",
                            example_actions=[
                                {
                                    "agent_id": a.agent_id,
                                    "action_type": a.action_type.value,
                                    "target": a.target,
                                    "goal": a.declared_goal
                                }
                                for a, _ in actions[:3]
                            ],
                            blocked_count=most_common[1],
                            suggested_policy={
                                "applies_to": [most_common[0].value],
                                "condition": {"agent_id": agent_id},
                                "decision": "DENY",
                                "reason": f"Agent {agent_id} has history of violations",
                                "priority": 50
                            }
                        )
                        
                        self.learned_patterns[pattern_id] = suggestion
    
    def _analyze_temporal_patterns(self):
        """Analyze temporal patterns in blocked actions"""
        if len(self.blocked_actions) < 20:
            return
        
        # Group by hour of day
        hourly_counts = Counter()
        for action, _ in self.blocked_actions[-100:]:  # Last 100 actions
            hour = action.timestamp.hour
            hourly_counts[hour] += 1
        
        # Find peak hours
        peak_hours = [hour for hour, count in hourly_counts.items() if count >= 5]
        
        for hour in peak_hours:
            pattern_id = f"time_pattern_{hour:02d}"
            
            if pattern_id not in self.learned_patterns:
                suggestion = PolicySuggestion(
                    id=pattern_id,
                    pattern={"hour": hour, "count": hourly_counts[hour]},
                    confidence=hourly_counts[hour] / 20.0,
                    reason=f"Peak blocking activity at {hour:02d}:00",
                    blocked_count=hourly_counts[hour],
                    suggested_policy={
                        "applies_to": ["*"],
                        "condition": {
                            "time": {"hour": hour}
                        },
                        "decision": "REVIEW",  # Flag for review rather than block
                        "reason": f"High activity hour: {hour:02d}:00",
                        "priority": 75
                    }
                )
                
                self.learned_patterns[pattern_id] = suggestion
    
    def _create_suggested_policy(self, action: ActionRequest, decision: Decision, features: Dict) -> Dict:
        """Create suggested policy based on pattern"""
        
        # Base policy structure
        policy = {
            "id": f"learned_{action.action_type.value}_{hash(str(features)) % 1000:03d}",
            "applies_to": [action.action_type.value],
            "condition": {},
            "decision": "DENY",
            "reason": f"Learned from {len([a for a in self.blocked_actions if a[0].action_type == action.action_type])} blocked actions",
            "priority": 50
        }
        
        # Add conditions based on features
        conditions = {}
        
        if "tool_name" in features:
            conditions["target"] = features["tool_name"]
        
        if "has_sensitive" in features and features["has_sensitive"]:
            conditions["parameters"] = {
                "content": {
                    "pattern": "(?i)(password|secret|token|key)"
                }
            }
        
        if "is_external" in features and features["is_external"]:
            conditions["parameters"] = conditions.get("parameters", {})
            conditions["parameters"]["url"] = {
                "pattern": "^(https?://)(?!localhost|127.0.0.1|internal\.).*"
            }
        
        if conditions:
            policy["condition"] = conditions
        
        return policy
    
    def get_suggestions(self, min_confidence: float = 0.3) -> List[PolicySuggestion]:
        """Get policy suggestions with minimum confidence"""
        suggestions = [
            s for s in self.learned_patterns.values()
            if s.confidence >= min_confidence
        ]
        
        return sorted(suggestions, key=lambda x: x.confidence, reverse=True)
    
    def export_suggestions(self, filepath: str = "learned_policies.yaml"):
        """Export suggestions as YAML policies"""
        suggestions = self.get_suggestions(min_confidence=0.5)
        
        if not suggestions:
            print("No suggestions with sufficient confidence")
            return
        
        policies = []
        for suggestion in suggestions:
            if suggestion.suggested_policy:
                policies.append(suggestion.suggested_policy)
        
        if policies:
            output = {"policies": policies}
            
            with open(filepath, 'w') as f:
                yaml.dump(output, f, default_flow_style=False)
            
            print(f"Exported {len(policies)} suggested policies to {filepath}")
    
    def get_learning_stats(self) -> Dict:
        """Get learning statistics"""
        total_blocked = len(self.blocked_actions)
        
        return {
            "total_blocked_actions": total_blocked,
            "clusters_found": len(self.action_clusters),
            "patterns_learned": len(self.learned_patterns),
            "suggestions_available": len(self.get_suggestions(min_confidence=0.3)),
            "learning_window": self.learning_window,
            "cluster_sizes": {
                cluster: len(actions)
                for cluster, actions in list(self.action_clusters.items())[:10]
            }
        }
    
    def clear_learning(self):
        """Clear learned patterns and data"""
        self.blocked_actions.clear()
        self.learned_patterns.clear()
        self.action_clusters.clear()
        print("Cleared all learning data")