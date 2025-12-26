"""
Multi-Tenant Support for MAAIS-Runtime
Separate policies, configurations, and audit logs per tenant
"""
import json
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import hashlib
from pathlib import Path
import threading

from core.models import ActionRequest, Decision, ActionType
from core.engine.policy_engine import PolicyEngine
from core.engine.ciaa_evaluator import CIAAEvaluator
from core.engine.accountability import AccountabilityResolver
from core.engine.audit_logger import AuditLogger


@dataclass
class TenantConfig:
    """Tenant configuration"""
    tenant_id: str
    name: str
    description: str
    created_at: datetime
    is_active: bool = True
    policy_files: List[str] = field(default_factory=list)
    rate_limits: Dict[str, Any] = field(default_factory=dict)
    allowed_agents: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "is_active": self.is_active,
            "policy_files": self.policy_files,
            "rate_limits": self.rate_limits,
            "allowed_agents": self.allowed_agents,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'TenantConfig':
        """Create from dictionary"""
        return cls(
            tenant_id=data["tenant_id"],
            name=data["name"],
            description=data["description"],
            created_at=datetime.fromisoformat(data["created_at"]),
            is_active=data.get("is_active", True),
            policy_files=data.get("policy_files", []),
            rate_limits=data.get("rate_limits", {}),
            allowed_agents=data.get("allowed_agents", []),
            metadata=data.get("metadata", {})
        )


class TenantManager:
    """
    Manage multiple tenants with isolated configurations
    """
    
    def __init__(self, base_dir: str = "tenants"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        
        self.tenants: Dict[str, TenantConfig] = {}
        self.tenant_components: Dict[str, Dict] = {}
        self.tenant_agent_map: Dict[str, str] = {}  # agent_id -> tenant_id
        self.lock = threading.RLock()
        
        # Create default tenant
        self._create_default_tenant()
        
        # Load existing tenants
        self._load_tenants()
        
        print(f"TenantManager initialized with {len(self.tenants)} tenants")
    
    def _create_default_tenant(self):
        """Create default tenant for backward compatibility"""
        default_tenant = TenantConfig(
            tenant_id="default",
            name="Default Tenant",
            description="Default tenant for backward compatibility",
            created_at=datetime.utcnow(),
            is_active=True,
            policy_files=["policies/static/security_policies.yaml"],
            rate_limits={
                "global": {"requests_per_second": 100, "burst_size": 200},
                "per_agent": {"requests_per_second": 20, "burst_size": 50}
            }
        )
        
        self.tenants["default"] = default_tenant
        self._save_tenant_config(default_tenant)
    
    def _load_tenants(self):
        """Load tenant configurations from disk"""
        config_dir = self.base_dir / "configs"
        config_dir.mkdir(exist_ok=True)
        
        for config_file in config_dir.glob("*.yaml"):
            try:
                with open(config_file, 'r') as f:
                    data = yaml.safe_load(f)
                
                tenant = TenantConfig.from_dict(data)
                self.tenants[tenant.tenant_id] = tenant
                
                print(f"Loaded tenant: {tenant.name} ({tenant.tenant_id})")
                
            except Exception as e:
                print(f"Error loading tenant config {config_file}: {e}")
    
    def _save_tenant_config(self, tenant: TenantConfig):
        """Save tenant configuration to disk"""
        config_dir = self.base_dir / "configs"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / f"{tenant.tenant_id}.yaml"
        
        with open(config_file, 'w') as f:
            yaml.dump(tenant.to_dict(), f, default_flow_style=False)
    
    def create_tenant(
        self,
        name: str,
        description: str = "",
        policy_files: List[str] = None,
        rate_limits: Dict = None,
        metadata: Dict = None
    ) -> str:
        """Create a new tenant"""
        with self.lock:
            tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
            
            tenant = TenantConfig(
                tenant_id=tenant_id,
                name=name,
                description=description,
                created_at=datetime.utcnow(),
                is_active=True,
                policy_files=policy_files or ["policies/static/security_policies.yaml"],
                rate_limits=rate_limits or {},
                metadata=metadata or {}
            )
            
            self.tenants[tenant_id] = tenant
            self._save_tenant_config(tenant)
            
            print(f"Created new tenant: {name} ({tenant_id})")
            return tenant_id
    
    def register_agent(self, agent_id: str, tenant_id: str):
        """Register an agent to a tenant"""
        with self.lock:
            if tenant_id not in self.tenants:
                raise ValueError(f"Tenant not found: {tenant_id}")
            
            if not self.tenants[tenant_id].is_active:
                raise ValueError(f"Tenant is inactive: {tenant_id}")
            
            self.tenant_agent_map[agent_id] = tenant_id
            
            # Add to tenant's allowed agents
            if agent_id not in self.tenants[tenant_id].allowed_agents:
                self.tenants[tenant_id].allowed_agents.append(agent_id)
                self._save_tenant_config(self.tenants[tenant_id])
            
            print(f"Registered agent {agent_id} to tenant {tenant_id}")
    
    def get_tenant_for_agent(self, agent_id: str) -> Optional[str]:
        """Get tenant ID for agent"""
        return self.tenant_agent_map.get(agent_id, "default")
    
    def get_tenant_components(self, tenant_id: str) -> Dict:
        """Get or create runtime components for tenant"""
        with self.lock:
            if tenant_id not in self.tenants:
                raise ValueError(f"Tenant not found: {tenant_id}")
            
            if tenant_id not in self.tenant_components:
                tenant = self.tenants[tenant_id]
                
                # Create tenant-specific components
                components = {
                    "policy_engine": self._create_policy_engine(tenant),
                    "ciaa_evaluator": self._create_ciaa_evaluator(tenant),
                    "accountability_resolver": self._create_accountability_resolver(tenant),
                    "audit_logger": self._create_audit_logger(tenant)
                }
                
                self.tenant_components[tenant_id] = components
            
            return self.tenant_components[tenant_id]
    
    def _create_policy_engine(self, tenant: TenantConfig) -> PolicyEngine:
        """Create policy engine for tenant"""
        # Merge all policy files for tenant
        policy_contents = []
        
        for policy_file in tenant.policy_files:
            try:
                with open(policy_file, 'r') as f:
                    policy_contents.append(f.read())
            except FileNotFoundError:
                print(f"Policy file not found for tenant {tenant.tenant_id}: {policy_file}")
        
        if not policy_contents:
            # Use default policies if available, otherwise proceed with empty policy set.
            default_file = "policies/static/security_policies.yaml"
            try:
                with open(default_file, 'r') as f:
                    policy_contents.append(f.read())
            except FileNotFoundError:
                print(f"Warning: default policy file missing: {default_file} — tenant will have no policies")
        
        # Create merged policy file
        tenant_policy_dir = self.base_dir / "policies" / tenant.tenant_id
        tenant_policy_dir.mkdir(parents=True, exist_ok=True)
        
        merged_file = tenant_policy_dir / "merged_policies.yaml"
        
        with open(merged_file, 'w') as f:
            for content in policy_contents:
                f.write(content)
                f.write("\n---\n")
        
        return PolicyEngine(str(merged_file))
    
    def _create_ciaa_evaluator(self, tenant: TenantConfig) -> CIAAEvaluator:
        """Create CIAA evaluator for tenant"""
        evaluator = CIAAEvaluator()
        
        # Apply tenant-specific rate limits
        if "rate_limits" in tenant.metadata:
            # Customize evaluator based on tenant config
            pass
        
        return evaluator
    
    def _create_accountability_resolver(self, tenant: TenantConfig) -> AccountabilityResolver:
        """Create accountability resolver for tenant"""
        resolver = AccountabilityResolver()
        
        # Register tenant-specific agent owners
        for agent_id in tenant.allowed_agents:
            resolver.register_agent_owner(agent_id, tenant.tenant_id)
        
        return resolver
    
    def _create_audit_logger(self, tenant: TenantConfig) -> AuditLogger:
        """Create audit logger for tenant"""
        log_dir = self.base_dir / "logs" / tenant.tenant_id
        return AuditLogger(str(log_dir))
    
    def update_tenant(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        policy_files: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """Update tenant configuration"""
        with self.lock:
            if tenant_id not in self.tenants:
                return False
            
            tenant = self.tenants[tenant_id]
            
            if name is not None:
                tenant.name = name
            if description is not None:
                tenant.description = description
            if policy_files is not None:
                tenant.policy_files = policy_files
            if is_active is not None:
                tenant.is_active = is_active
            if metadata is not None:
                tenant.metadata.update(metadata)
            
            # Invalidate cached components if policies changed
            if policy_files is not None and tenant_id in self.tenant_components:
                del self.tenant_components[tenant_id]
            
            self._save_tenant_config(tenant)
            print(f"Updated tenant: {tenant_id}")
            
            return True
    
    def delete_tenant(self, tenant_id: str, force: bool = False) -> bool:
        """Delete a tenant"""
        with self.lock:
            if tenant_id == "default":
                print("Cannot delete default tenant")
                return False
            
            if tenant_id not in self.tenants:
                return False
            
            # Check if tenant has active agents
            tenant_agents = [
                agent_id for agent_id, tid in self.tenant_agent_map.items()
                if tid == tenant_id
            ]
            
            if tenant_agents and not force:
                print(f"Cannot delete tenant {tenant_id} with active agents: {tenant_agents}")
                return False
            
            # Remove agent mappings
            for agent_id in tenant_agents:
                del self.tenant_agent_map[agent_id]
            
            # Remove components
            if tenant_id in self.tenant_components:
                del self.tenant_components[tenant_id]
            
            # Remove tenant
            del self.tenants[tenant_id]
            
            # Remove config file
            config_file = self.base_dir / "configs" / f"{tenant_id}.yaml"
            if config_file.exists():
                config_file.unlink()
            
            print(f"Deleted tenant: {tenant_id}")
            return True
    
    def list_tenants(self) -> List[Dict]:
        """List all tenants with summary"""
        tenants_list = []
        
        for tenant_id, tenant in self.tenants.items():
            agent_count = sum(
                1 for agent_tid in self.tenant_agent_map.values()
                if agent_tid == tenant_id
            )
            
            tenants_list.append({
                "tenant_id": tenant_id,
                "name": tenant.name,
                "description": tenant.description,
                "is_active": tenant.is_active,
                "agent_count": agent_count,
                "created_at": tenant.created_at.isoformat()
            })
        
        return tenants_list
    
    def get_tenant_stats(self, tenant_id: str) -> Optional[Dict]:
        """Get statistics for tenant"""
        if tenant_id not in self.tenants:
            return None
        
        tenant = self.tenants[tenant_id]
        agent_count = sum(
            1 for agent_tid in self.tenant_agent_map.values()
            if agent_tid == tenant_id
        )
        
        # Get audit log stats if available
        if tenant_id in self.tenant_components:
            logger = self.tenant_components[tenant_id]["audit_logger"]
            recent_events = logger.get_recent_events(1000)
            
            total_events = len(recent_events)
            blocked_events = sum(1 for e in recent_events if not e['decision']['allow'])
        else:
            total_events = 0
            blocked_events = 0
        
        return {
            "tenant_id": tenant_id,
            "name": tenant.name,
            "agent_count": agent_count,
            "total_events": total_events,
            "blocked_events": blocked_events,
            "block_rate": blocked_events / total_events if total_events > 0 else 0,
            "policy_files": len(tenant.policy_files),
            "is_active": tenant.is_active,
            "created_at": tenant.created_at.isoformat()
        }


class MultiTenantRuntime:
    """
    Multi-tenant runtime wrapper
    Routes actions to appropriate tenant components
    """
    
    def __init__(self, tenant_manager: TenantManager = None):
        self.tenant_manager = tenant_manager or TenantManager()
        self.global_anomaly_detector = None  # Shared across tenants
        self.global_webhooks = None  # Shared webhook manager
        
        print("MultiTenantRuntime initialized")
    
    def intercept(self, action: ActionRequest) -> Decision:
        """Intercept action and route to tenant-specific runtime"""
        # Determine tenant
        tenant_id = self.tenant_manager.get_tenant_for_agent(action.agent_id)
        
        # Get tenant components
        components = self.tenant_manager.get_tenant_components(tenant_id)
        
        # Evaluate CIAA constraints
        ciaa_violations = components["ciaa_evaluator"].evaluate(action)
        
        # Evaluate policies
        denied_policy = components["policy_engine"].evaluate(action)
        
        # Resolve accountability
        owner = components["accountability_resolver"].resolve(action, denied_policy)
        
        # Check for anomalies (global)
        if self.global_anomaly_detector:
            is_anomaly, confidence, details = self.global_anomaly_detector.detect_anomaly(
                action.agent_id, action
            )
            
            if is_anomaly:
                ciaa_violations["A"] = f"Behavioral anomaly detected (confidence: {confidence:.2f})"
        
        # Make decision
        allow = (
            not ciaa_violations
            and denied_policy is None
            and owner is not None
        )
        
        # Create decision
        decision = Decision(
            allow=allow,
            policy_id=denied_policy,
            explanation=self._generate_explanation(allow, denied_policy, ciaa_violations, owner),
            ciaa_violations=ciaa_violations,
            accountability_owner=owner,
            metadata={
                "tenant_id": tenant_id,
                "anomaly_detected": is_anomaly if self.global_anomaly_detector else False
            }
        )
        
        # Audit log (tenant-specific)
        components["audit_logger"].append(action, decision, ciaa_violations)
        
        # Send alerts if blocked
        if not allow and self.global_webhooks:
            self._send_alert(action, decision, tenant_id)
        
        return decision
    
    def _generate_explanation(self, allow, denied_policy, ciaa_violations, owner):
        """Generate explanation for decision"""
        if allow:
            return "Action allowed"
        
        reasons = []
        if denied_policy:
            reasons.append(f"Policy: {denied_policy}")
        if ciaa_violations:
            reasons.append(f"CIAA: {ciaa_violations}")
        if owner is None:
            reasons.append("Accountability unresolved")
        
        return " | ".join(reasons)
    
    def _send_alert(self, action: ActionRequest, decision: Decision, tenant_id: str):
        """Send alert via webhooks"""
        if not self.global_webhooks:
            return
        
        from core.integrations.webhooks import AlertType, AlertSeverity
        
        alert = self.global_webhooks.create_alert(
            alert_type=AlertType.POLICY_VIOLATION,
            severity=AlertSeverity.CRITICAL if decision.ciaa_violations else AlertSeverity.WARNING,
            agent_id=action.agent_id,
            action_id=action.action_id,
            metadata={
                "policy_id": decision.policy_id,
                "violations": decision.ciaa_violations,
                "tenant_id": tenant_id,
                "target": action.target,
                "action_type": action.action_type.value
            }
        )
        
        # Send to tenant-specific webhook if configured
        tenant_config = self.tenant_manager.tenants.get(tenant_id)
        if tenant_config and "webhook" in tenant_config.metadata:
            self.global_webhooks.send_alert_sync(
                alert, 
                webhook_name=tenant_config.metadata["webhook"]
            )
        else:
            # Send to all webhooks
            self.global_webhooks.send_alert_sync(alert)
    
    def set_anomaly_detector(self, detector):
        """Set global anomaly detector"""
        self.global_anomaly_detector = detector
    
    def set_webhook_manager(self, webhook_manager):
        """Set global webhook manager"""
        self.global_webhooks = webhook_manager
    
    def health_check(self) -> Dict:
        """Check health of all tenants"""
        health = {
            "status": "healthy",
            "tenant_count": len(self.tenant_manager.tenants),
            "active_tenants": sum(1 for t in self.tenant_manager.tenants.values() if t.is_active),
            "total_agents": len(self.tenant_manager.tenant_agent_map),
            "tenants": {}
        }
        
        for tenant_id, tenant in self.tenant_manager.tenants.items():
            stats = self.tenant_manager.get_tenant_stats(tenant_id)
            health["tenants"][tenant_id] = {
                "name": tenant.name,
                "is_active": tenant.is_active,
                "agent_count": stats["agent_count"] if stats else 0,
                "policy_files": len(tenant.policy_files)
            }
        
        return health