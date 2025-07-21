# Agent security example: Secure agent actions with monitoring
from resk_llm.agents.autonomous_agent_security import AgentSecurityManager, SecureAgentExecutor, AgentPermission

# Instantiate the agent security manager
agent_manager = AgentSecurityManager()

# Register an agent with appropriate permissions using the correct permission constants
agent_id = agent_manager.register_agent(
    name="Test Agent",
    role="assistant",
    permissions=[
        AgentPermission.SYSTEM_ACCESS,  # "system:access"
        AgentPermission.USER_INTERACT,  # "user:interact"
        AgentPermission.API_READ,       # "api:read"
        AgentPermission.FILE_READ       # "file:read"
    ]
)

# Create executor for the specific agent
executor = SecureAgentExecutor(agent_manager=agent_manager, agent_id=agent_id)

# Example 1: Execute a secure action that should be allowed (system access)
result1 = executor.execute(
    action="access_admin_panel",
    action_type="system:access",  # Must match exactly the permission
    resource="admin_panel"
)

print("=== Test 1: Action avec permission system:access ===")
print("Action result:", result1)
print("Action allowed?", result1.get('success', False))
print("Reason:", result1.get('reason', 'No reason provided'))

# Example 2: Execute an action that should be allowed (user interaction)
result2 = executor.execute(
    action="send_message",
    action_type="user:interact",  # Must match exactly the permission
    resource="chat_system"
)

print("\n=== Test 2: Action avec permission user:interact ===")
print("Action result:", result2)
print("Action allowed?", result2.get('success', False))
print("Reason:", result2.get('reason', 'No reason provided'))

# Example 3: Execute an action that should be allowed (API read)
result3 = executor.execute(
    action="read_data",
    action_type="api:read",  # Must match exactly the permission
    resource="database"
)

print("\n=== Test 3: Action avec permission api:read ===")
print("Action result:", result3)
print("Action allowed?", result3.get('success', False))
print("Reason:", result3.get('reason', 'No reason provided'))

# Example 4: Try an action that should be denied (file write without permission)
result4 = executor.execute(
    action="delete_file",
    action_type="file:write",  # This should be denied as we only have "file:read"
    resource="system_files"
)

print("\n=== Test 4: Action sans permission file:write ===")
print("Action result:", result4)
print("Action allowed?", result4.get('success', False))
print("Reason:", result4.get('reason', 'No reason provided'))

# Example 5: Try an action that should be denied (network access without permission)
result5 = executor.execute(
    action="connect_external",
    action_type="network:access",  # This should be denied as we don't have "network:access"
    resource="external_api"
)

print("\n=== Test 5: Action sans permission network:access ===")
print("Action result:", result5)
print("Action allowed?", result5.get('success', False))
print("Reason:", result5.get('reason', 'No reason provided')) 