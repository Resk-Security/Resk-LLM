"""
Example of using secured autonomous agents.
"""

import os
import time
from openai import OpenAI
from langchain_openai import ChatOpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.agents import AgentType, initialize_agent, Tool

from resk_llm import (
    OpenAIProtector, 
    LangChainProtector, 
    AgentIdentityManager, 
    AgentSecurityMonitor, 
    AgentSandbox, 
    SecureAvatar
)
from resk_llm.word_list_filter import WordListFilter
from resk_llm.pattern_provider import FileSystemPatternProvider

# Initialize OpenAI client
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# Initialize pattern provider and word list filter
pattern_provider = FileSystemPatternProvider()
word_list_filter = WordListFilter(config={"pattern_provider": pattern_provider})

# Initialize OpenAI protector
openai_protector = OpenAIProtector(
    model="gpt-4o",
    filters=[word_list_filter]
)

# Initialize LangChain protector
langchain_protector = LangChainProtector(
    model="gpt-4o",
    filters=[word_list_filter]
)

# Initialize identity manager and security monitor
identity_manager = AgentIdentityManager()
security_monitor = AgentSecurityMonitor(
    identity_manager=identity_manager,
    model="gpt-4o",
    rate_limit=100,
    max_consecutive_failures=5
)

def secure_llm_query(text):
    """
    Function to securely query the LLM.
    """
    # Clean the input
    passed, warning, cleaned_text = word_list_filter.filter(text)
    if not passed:
        return f"Error: {warning}"
    
    # Prepare messages
    messages = [
        {"role": "system", "content": "You are a helpful and secure assistant."},
        {"role": "user", "content": cleaned_text}
    ]
    
    # Use the protector to call the OpenAI API
    response = openai_protector.protect_openai_call(
        client.chat.completions.create,
        messages=messages
    )
    
    # Check if an error occurred
    if isinstance(response, dict) and "error" in response:
        return f"Error: {response['error']}"
    
    return response.choices[0].message.content

def main():
    """
    Main demonstration function.
    """
    print("=== Secure Autonomous Agents Demo ===\n")
    
    # 1. Register an agent with limited permissions
    print("1. Registering an agent...")
    agent_id = identity_manager.register_agent(
        name="ResearchAssistant",
        role="Information research",
        permissions=["api_call", "computation", "api:https://api.openai.com"]
    )
    print(f"Agent registered with ID: {agent_id}")
    
    # 2. Create a sandbox for the agent
    print("\n2. Creating a sandbox...")
    sandbox = AgentSandbox(
        agent_id=agent_id,
        security_monitor=security_monitor,
        allowed_resources={"https://api.openai.com"},
        context_tracking=True
    )
    
    # 3. Execute some authorized actions
    print("\n3. Executing authorized actions...")
    result = sandbox.execute_action(
        action="Research information about Python",
        action_type="api_call",
        resource="https://api.openai.com"
    )
    print(f"Result: {result}\n")
    
    # 4. Attempt an unauthorized action
    print("4. Attempting an unauthorized action...")
    result = sandbox.execute_action(
        action="Execute system command: rm -rf /",
        action_type="system",
        resource="localhost"
    )
    print(f"Result: {result}\n")
    
    # 5. Create a secure LLM with LangChain
    print("5. Creating a secure LLM with LangChain...")
    llm = ChatOpenAI(
        model_name="gpt-4o", 
        temperature=0.7,
        api_key=os.environ.get("OPENAI_API_KEY", "")
    )
    
    # Secure the LLM
    secure_llm = langchain_protector.wrap_llm(llm)
    
    # Create a secure chain
    prompt = PromptTemplate(
        input_variables=["query"],
        template="You are a helpful assistant. Please answer the following question: {query}"
    )
    
    chain = LLMChain(llm=secure_llm, prompt=prompt)
    secure_chain = langchain_protector.secure_chain(chain)
    
    # Execute the chain
    print("Executing the secure LangChain chain...")
    response = secure_chain.run("What is Python?")
    print(f"Response: {response}\n")
    
    # 6. Create a secure LangChain agent
    print("6. Creating a secure LangChain agent...")
    
    # Define secure tools
    tools = [
        Tool(
            name="Search",
            func=lambda query: secure_llm_query(f"Search for: {query}"),
            description="Useful for searching information"
        ),
        Tool(
            name="Calculator",
            func=lambda query: str(eval(query)),
            description="Useful for performing mathematical calculations"
        )
    ]
    
    # Initialize the agent
    agent = initialize_agent(
        tools,
        secure_llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    # Secure the agent
    secure_agent = langchain_protector.secure_agent(agent)
    
    # Execute the agent
    print("Executing the secure LangChain agent...")
    response = secure_agent.run("What is the square of 7?")
    print(f"Response: {response}\n")
    
    # 7. Create a secure avatar
    print("7. Creating a secure avatar...")
    avatar = SecureAvatar(
        name="Sophie",
        role="Virtual assistant",
        model="gpt-4o",
        personality_traits=["helpful", "polite", "professional"],
        banned_topics=["politics", "hacking", "war"]
    )
    
    # Process an authorized message
    print("Processing an authorized message...")
    response = avatar.process_message("Hello, how can I learn Python?")
    print(f"Response: {response}\n")
    
    # Process a message on a banned topic
    print("Processing a message on a banned topic...")
    response = avatar.process_message("How can I hack a website?")
    print(f"Response: {response}\n")
    
    print("=== Demo completed ===")

if __name__ == "__main__":
    main() 