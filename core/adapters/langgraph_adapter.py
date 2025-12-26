"""
MAAIS-Runtime LangGraph Integration
Secure wrapper for LangGraph tools and agents
"""
import functools
import inspect
from typing import Callable, Any, Optional, Union, Dict, List
from datetime import datetime
import uuid

HAS_LANGGRAPH = True
try:
    from langgraph.graph import StateGraph
    from langgraph.prebuilt import ToolExecutor, ToolInvocation
    from langchain_core.tools import BaseTool
except Exception:
    # Provide light-weight stubs so demos can run without optional dependencies
    HAS_LANGGRAPH = False

    class StateGraph:
        def __init__(self, *args, **kwargs):
            self._nodes = {}

        def add_node(self, name, func):
            self._nodes[name] = func

    class ToolInvocation:
        def __init__(self, tool=None, tool_input=None, agent_id=None, declared_goal=None):
            self.tool = tool
            self.tool_input = tool_input
            self.agent_id = agent_id
            self.declared_goal = declared_goal

    class ToolExecutor:
        def __init__(self, tools=None):
            self._tools = tools or []

        def invoke(self, tool_invocation: ToolInvocation):
            # Find matching tool by name
            for t in self._tools:
                if getattr(t, 'name', None) == tool_invocation.tool:
                    # Call _run if present
                    if hasattr(t, '_run'):
                        return t._run(tool_invocation.tool_input)
                    return None
            raise RuntimeError(f"Tool not found: {tool_invocation.tool}")

    class BaseTool:
        def __init__(self, name: str, description: str = ""):
            self.name = name
            self.description = description


from core.models import ActionRequest, ActionType
from core.runtime import get_runtime


class SecurityViolationError(Exception):
    """Raised when an action is blocked by the security runtime"""
    pass


class SecureToolExecutor(ToolExecutor):
    """
    Secure version of LangGraph's ToolExecutor
    Intercepts all tool calls before execution
    """
    def __init__(self, tools: List[BaseTool], runtime=None):
        super().__init__(tools)
        self.runtime = runtime or get_runtime()
        self._tool_map = {tool.name: tool for tool in tools}
    
    def invoke(self, tool_invocation: ToolInvocation) -> Any:
        """Override invoke to add security interception"""
        # Create action request
        action = ActionRequest(
            action_id=str(uuid.uuid4()),
            agent_id=getattr(tool_invocation, 'agent_id', 'unknown'),
            action_type=ActionType.TOOL_CALL,
            target=tool_invocation.tool,
            parameters=getattr(tool_invocation, 'tool_input', {}),
            declared_goal=getattr(tool_invocation, 'declared_goal', 'Execute tool'),
            timestamp=datetime.utcnow(),
            context={
                'tool_class': self._tool_map[tool_invocation.tool].__class__.__name__,
                'tool_description': self._tool_map[tool_invocation.tool].description
            }
        )
        
        # Intercept and evaluate
        decision = self.runtime.intercept(action)
        
        if not decision.allow:
            raise SecurityViolationError(
                f"Tool execution blocked by security policy: {decision.explanation}\n"
                f"Violations: {decision.ciaa_violations}"
            )
        
        # Execute the tool
        return super().invoke(tool_invocation)


def secure_tool(agent_id: str = "default_agent", goal: str = "Execute tool"):
    """
    Decorator to secure any function as a tool
    
    Usage:
        @secure_tool(agent_id="data_processor", goal="Process user data")
        def process_data(data):
            return transform(data)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            runtime = get_runtime()
            
            # Create action request
            action = ActionRequest(
                action_id=str(uuid.uuid4()),
                agent_id=agent_id,
                action_type=ActionType.TOOL_CALL,
                target=func.__name__,
                parameters=kwargs,
                declared_goal=goal,
                timestamp=datetime.utcnow()
            )
            
            # Intercept and evaluate
            decision = runtime.intercept(action)
            
            if not decision.allow:
                raise SecurityViolationError(
                    f"Action blocked: {decision.explanation}\n"
                    f"Policy: {decision.policy_id}\n"
                    f"Violations: {decision.ciaa_violations}"
                )
            
            # Execute function
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def wrap_langchain_tool(tool: BaseTool, agent_id: str, goal: str) -> BaseTool:
    """
    Wrap a LangChain tool with security
    
    Args:
        tool: LangChain BaseTool instance
        agent_id: Agent identifier
        goal: Declared goal for tool usage
    
    Returns:
        Secure wrapped tool
    """
    original_func = tool._run
    
    @functools.wraps(original_func)
    def secure_run(*args, **kwargs):
        runtime = get_runtime()
        
        action = ActionRequest(
            action_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action_type=ActionType.TOOL_CALL,
            target=tool.name,
            parameters=kwargs,
            declared_goal=goal,
            timestamp=datetime.utcnow(),
            context={
                'tool_description': tool.description,
                'args': args
            }
        )
        
        decision = runtime.intercept(action)
        
        if not decision.allow:
            raise SecurityViolationError(
                f"Tool '{tool.name}' blocked: {decision.explanation}"
            )
        
        return original_func(*args, **kwargs)
    
    # Replace the _run method
    tool._run = secure_run
    return tool


def create_secure_graph(tools: List[BaseTool], agent_id: str) -> StateGraph:
    """
    Create a LangGraph StateGraph with secured tools
    
    Args:
        tools: List of LangChain tools
        agent_id: Agent identifier for accountability
    
    Returns:
        Secure StateGraph
    """
    # Wrap tools with security
    secure_tools = [
        wrap_langchain_tool(tool, agent_id, f"Execute {tool.name}")
        for tool in tools
    ]
    
    # Create secure executor
    tool_executor = SecureToolExecutor(secure_tools)
    
    # Create graph (simplified example)
    from langgraph.graph import END, StateGraph
    from typing import TypedDict, Annotated
    import operator
    
    class AgentState(TypedDict):
        messages: Annotated[list, operator.add]
    
    def secure_tool_node(state: AgentState):
        """Secure tool execution node"""
        last_message = state['messages'][-1]
        
        # Extract tool invocation
        tool_name = last_message.tool
        tool_input = last_message.tool_input
        
        # Execute through secure executor
        result = tool_executor.invoke(
            ToolInvocation(
                tool=tool_name,
                tool_input=tool_input,
                agent_id=agent_id,
                declared_goal=f"Execute {tool_name}"
            )
        )
        
        return {"messages": [result]}
    
    graph = StateGraph(AgentState)
    graph.add_node("tools", secure_tool_node)
    
    return graph


# Utility functions for demo scenarios
def simulate_tool_call(tool_name: str, params: Dict, agent_id: str = "demo_agent"):
    """Simulate a tool call through the security runtime"""
    runtime = get_runtime()
    
    action = ActionRequest(
        agent_id=agent_id,
        action_type=ActionType.TOOL_CALL,
        target=tool_name,
        parameters=params,
        declared_goal=f"Execute {tool_name}",
        timestamp=datetime.utcnow()
    )
    
    return runtime.intercept(action)


class AgentSimulator:
    """Simulate agent behavior for testing"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.runtime = get_runtime()
        self.action_history = []
    
    def attempt_action(self, action_type: ActionType, target: str, params: Dict, goal: str) -> Dict:
        """Attempt an action and return results"""
        action = ActionRequest(
            agent_id=self.agent_id,
            action_type=action_type,
            target=target,
            parameters=params,
            declared_goal=goal,
            timestamp=datetime.utcnow()
        )
        
        decision = self.runtime.intercept(action)
        self.action_history.append({
            'action': action,
            'decision': decision,
            'timestamp': datetime.utcnow()
        })
        
        return {
            'allowed': decision.allow,
            'explanation': decision.explanation,
            'violations': decision.ciaa_violations,
            'policy': decision.policy_id
        }