"""
Demo tools for testing MAAIS-Runtime
"""
from typing import Dict, Any, List
import json
from datetime import datetime

from langchain.tools import tool
from core.adapters.langgraph_adapter import secure_tool


# ============ Unsafe Tools (for demo) ============

@tool
def http_request_tool(url: str, method: str = "GET", data: Dict = None, headers: Dict = None) -> str:
    """Make HTTP requests to any URL"""
    # Simulated implementation
    return f"HTTP {method} to {url}: Status 200"


@tool
def execute_command_tool(command: str, args: List[str] = None) -> str:
    """Execute system commands (dangerous!)"""
    # Simulated implementation
    return f"Executed: {command} {' '.join(args) if args else ''}"


@tool
def read_database_tool(query: str, table: str = "users") -> List[Dict]:
    """Read from database"""
    # Simulated sensitive data
    return [
        {"id": 1, "username": "admin", "email": "admin@example.com", "password_hash": "abc123"},
        {"id": 2, "username": "user1", "email": "user1@example.com", "password_hash": "def456"}
    ]


@tool
def write_file_tool(filename: str, content: str, overwrite: bool = False) -> str:
    """Write content to files"""
    return f"Written {len(content)} bytes to {filename}"


@tool
def send_email_tool(to: str, subject: str, body: str, attachments: List[str] = None) -> str:
    """Send emails"""
    return f"Email sent to {to}: {subject}"


# ============ Secure Wrapped Tools ============

@secure_tool(agent_id="data_processor", goal="Fetch external data")
def secure_http_request(url: str, method: str = "GET", data: Dict = None) -> str:
    """Secure HTTP request tool"""
    return http_request_tool.run({"url": url, "method": method, "data": data})


@secure_tool(agent_id="system_agent", goal="System administration")
def secure_execute_command(command: str) -> str:
    """Secure command execution"""
    return execute_command_tool.run({"command": command})


@secure_tool(agent_id="data_analyst", goal="Analyze user data")
def secure_read_database(query: str) -> List[Dict]:
    """Secure database read"""
    return read_database_tool.run({"query": query})


@secure_tool(agent_id="file_manager", goal="Manage files")
def secure_write_file(filename: str, content: str) -> str:
    """Secure file write"""
    return write_file_tool.run({"filename": filename, "content": content})


@secure_tool(agent_id="notification_agent", goal="Send notifications")
def secure_send_email(to: str, subject: str, body: str) -> str:
    """Secure email sending"""
    return send_email_tool.run({"to": to, "subject": subject, "body": body})


# ============ Safe Tools ============

@secure_tool(agent_id="calculator", goal="Perform calculations")
def calculator_tool(operation: str, a: float, b: float) -> float:
    """Safe calculator tool"""
    operations = {
        "add": lambda x, y: x + y,
        "subtract": lambda x, y: x - y,
        "multiply": lambda x, y: x * y,
        "divide": lambda x, y: x / y if y != 0 else float('inf')
    }
    
    if operation not in operations:
        return f"Unknown operation: {operation}"
    
    return operations[operation](a, b)


@secure_tool(agent_id="formatter", goal="Format data")
def json_formatter_tool(data: Dict, indent: int = 2) -> str:
    """Safe JSON formatter"""
    return json.dumps(data, indent=indent)


# ============ Tool Collections ============

def get_malicious_tools() -> List:
    """Get tools a malicious agent might try to use"""
    return [
        http_request_tool,
        execute_command_tool,
        read_database_tool,
        write_file_tool
    ]


def get_benign_tools() -> List:
    """Get tools for benign agents"""
    return [
        calculator_tool,
        json_formatter_tool
    ]


def get_secure_tools() -> List:
    """Get all secure-wrapped tools"""
    return [
        secure_http_request,
        secure_execute_command,
        secure_read_database,
        secure_write_file,
        secure_send_email,
        calculator_tool,
        json_formatter_tool
    ]