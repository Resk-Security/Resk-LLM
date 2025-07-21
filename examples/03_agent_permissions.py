# Simple agent security test
from resk_llm.agents.autonomous_agent_security import AgentSecurityManager, SecureAgentExecutor, AgentPermission

print("TEST SIMPLE DES PERMISSIONS D'AGENT")
print("=" * 50)

# Create agent manager
agent_manager = AgentSecurityManager()

# Register agent with permissions
agent_id = agent_manager.register_agent(
    name="Test Agent",
    role="assistant",
    permissions=[AgentPermission.SYSTEM_ACCESS, AgentPermission.USER_INTERACT]
)

print(f"Agent enregistre avec ID: {agent_id}")

# Create executor
executor = SecureAgentExecutor(agent_manager=agent_manager, agent_id=agent_id)

# Test 1: Allowed action
print("\nTest 1: Action autorisee (system:access)")
result1 = executor.execute(
    action="access_panel",
    action_type="system:access",
    resource="admin"
)
print(f"Status: {result1.get('status')}")
print(f"Succes: {result1.get('status') == 'success'}")

# Test 2: Allowed action
print("\nTest 2: Action autorisee (user:interact)")
result2 = executor.execute(
    action="send_message",
    action_type="user:interact",
    resource="chat"
)
print(f"Status: {result2.get('status')}")
print(f"Succes: {result2.get('status') == 'success'}")

# Test 3: Denied action
print("\nTest 3: Action refusee (file:write)")
result3 = executor.execute(
    action="delete_file",
    action_type="file:write",
    resource="system"
)
print(f"Status: {result3.get('status')}")
print(f"Refuse: {result3.get('status') == 'error'}")

print("\nTests termines !") 