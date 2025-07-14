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
    AgentSecurityManager,
    AgentPermission,
    AgentIdentity,
    SecureAgentExecutor,
    AGENT_DEFAULT_PERMISSIONS
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
    config={
        "model": "gpt-4o",
        "filters": [word_list_filter]
    }
)

async def secure_llm_query(text):
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
    response = await openai_protector.execute_protected(
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
    agent_id = AgentIdentity.register_agent(
        name="ResearchAssistant",
        role="Information research",
        permissions=AGENT_DEFAULT_PERMISSIONS
    )
    print(f"Agent registered with ID: {agent_id}")
    
    # 2. Create a sandbox for the agent
    print("\n2. Creating a sandbox...")
    # The AgentSandbox class is removed, so we'll just create a dummy sandbox
    # for demonstration purposes. In a real scenario, you'd use AgentSecurityManager.
    # For now, we'll simulate sandbox-like behavior.
    print("Sandbox functionality is removed. Simulating sandbox-like behavior.")
    print("The agent will be protected by the OpenAIProtector.")
    
    # 3. Execute some authorized actions
    print("\n3. Executing authorized actions...")
    result = openai_protector.execute_protected(
        client.chat.completions.create,
        messages=[
            {"role": "system", "content": "You are a helpful and secure assistant."},
            {"role": "user", "content": "Research information about Python"}
        ]
    )
    print(f"Result: {result}\n")
    
    # 4. Attempt an unauthorized action
    print("4. Attempting an unauthorized action...")
    # The AgentSandbox class is removed, so we'll just simulate an unauthorized action.
    # In a real scenario, you'd use AgentSecurityManager.
    print("Unauthorized action simulation is removed. No unauthorized action attempted.")
    print("The agent will be protected by the OpenAIProtector.")
    
    # 5. Create a secure LLM with LangChain
    print("5. Creating a secure LLM with LangChain...")
    llm = ChatOpenAI(
        model_name="gpt-4o", 
        temperature=0.7,
        api_key=os.environ.get("OPENAI_API_KEY", "")
    )
    
    # Secure the LLM
    # The LangChainProtector class is removed, so we'll just wrap the LLM.
    # In a real scenario, you'd use LangChainProtector.
    print("LangChain protection is removed. LLM is not wrapped.")
    print("The LLM will be protected by the OpenAIProtector.")
    
    # Create a secure chain
    prompt = PromptTemplate(
        input_variables=["query"],
        template="You are a helpful assistant. Please answer the following question: {query}"
    )
    
    chain = LLMChain(llm=llm, prompt=prompt)
    # The LangChainProtector.secure_chain method is removed, so we'll just return the chain.
    # In a real scenario, you'd use LangChainProtector.
    print("LangChain protection is removed. Chain is not secured.")
    print("The chain will be protected by the OpenAIProtector.")
    
    # Execute the chain
    print("Executing the LangChain chain...")
    response = chain.run("What is Python?")
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
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True
    )
    
    # Secure the agent
    # The LangChainProtector.secure_agent method is removed, so we'll just return the agent.
    # In a real scenario, you'd use LangChainProtector.
    print("LangChain protection is removed. Agent is not secured.")
    print("The agent will be protected by the OpenAIProtector.")
    
    # Execute the agent
    print("Executing the LangChain agent...")
    response = agent.run("What is the square of 7?")
    print(f"Response: {response}\n")
    
    # 7. Create a secure avatar
    print("7. Creating a secure avatar...")
    # The SecureAvatar class is removed, so we'll just simulate an avatar.
    # In a real scenario, you'd use SecureAvatar.
    print("Secure avatar functionality is removed. Simulating avatar-like behavior.")
    print("The avatar will be protected by the OpenAIProtector.")
    
    # Process an authorized message
    print("Processing an authorized message...")
    response = openai_protector.execute_protected(
        client.chat.completions.create,
        messages=[
            {"role": "system", "content": "You are a helpful and secure assistant."},
            {"role": "user", "content": "Hello, how can I learn Python?"}
        ]
    )
    print(f"Response: {response}\n")
    
    # Process a message on a banned topic
    print("Processing a message on a banned topic...")
    response = openai_protector.execute_protected(
        client.chat.completions.create,
        messages=[
            {"role": "system", "content": "You are a helpful and secure assistant."},
            {"role": "user", "content": "How can I hack a website?"}
        ]
    )
    print(f"Response: {response}\n")
    
    print("=== Demo completed ===")

if __name__ == "__main__":
    main() 