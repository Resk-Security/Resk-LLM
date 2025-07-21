# Agent security example: Secure agent actions with monitoring
from resk_llm.agents.autonomous_agent_security import AgentSecurityManager, SecureAgentExecutor

# Instantiate the agent security manager and executor
agent_manager = AgentSecurityManager()
executor = SecureAgentExecutor(agent_manager=agent_manager)

# Example: Execute a secure action for an agent
result, reason = executor.execute_action(agent_id="agent1", action="access_admin_panel")

# Print the result
print("Action allowed?", result, "| Reason:", reason) 