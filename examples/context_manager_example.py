"""
Example of using RESK-LLM's Context Manager to handle conversation history.

This example demonstrates how to:
1. Use TokenBasedContextManager to manage conversation history based on token count
2. Use MessageBasedContextManager to manage conversation history based on message count
3. Use ContextWindowManager to manage multiple conversation windows
"""

import os
from typing import List, Dict, Any
import openai
from openai import OpenAI

from resk_llm.resk_context_manager import (
    TokenBasedContextManager,
    MessageBasedContextManager,
    ContextWindowManager
)

# Initialize OpenAI client (for demonstration purposes)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", "your-api-key"))

def simulate_llm_response(messages: List[Dict[str, str]]) -> str:
    """Simulate a response from an LLM API."""
    # In a real application, you would call your LLM API here
    # For this example, we'll just return a simple response
    user_message = messages[-1]["content"] if messages[-1]["role"] == "user" else ""
    
    if "hello" in user_message.lower():
        return "Hello! How can I help you today?"
    elif "weather" in user_message.lower():
        return "I don't have access to real-time weather data, but I can help with other questions!"
    elif "name" in user_message.lower():
        return "I'm an AI assistant. You can call me Assistant."
    else:
        return "I understand your message. Is there anything specific you'd like to know?"

def main():
    """Run the context manager example."""
    print("🔄 RESK-LLM Context Manager Example 🔄")
    print("-------------------------------------")
    
    # Example 1: Using TokenBasedContextManager
    print("\n1. TokenBasedContextManager Example")
    print("   This manager maintains conversation context based on token count")
    
    # Create a token-based context manager with a 4000 token limit
    token_manager = TokenBasedContextManager(
        config={
            "max_tokens": 4000,
            "reserved_tokens": 1000,  # Reserve tokens for the response
            "system_prompt": "You are a helpful AI assistant."
        }
    )
    
    # Simulate a conversation
    conversation_history = []
    
    # Add system message
    system_message = {"role": "system", "content": "You are a helpful AI assistant."}
    conversation_history.append(system_message)
    token_manager.add_message(system_message)
    
    # First user message
    user_message1 = {"role": "user", "content": "Hello there!"}
    conversation_history.append(user_message1)
    token_manager.add_message(user_message1)
    
    # Get response and add it to history
    context = token_manager.get_current_context()
    response1 = simulate_llm_response(context)
    assistant_message1 = {"role": "assistant", "content": response1}
    conversation_history.append(assistant_message1)
    token_manager.add_message(assistant_message1)
    
    # Second user message
    user_message2 = {"role": "user", "content": "What's your name?"}
    conversation_history.append(user_message2)
    token_manager.add_message(user_message2)
    
    # Get response and add it to history
    context = token_manager.get_current_context()
    response2 = simulate_llm_response(context)
    assistant_message2 = {"role": "assistant", "content": response2}
    conversation_history.append(assistant_message2)
    token_manager.add_message(assistant_message2)
    
    # Print the final context
    print("\n   Final context from TokenBasedContextManager:")
    for message in token_manager.get_current_context():
        print(f"   - {message['role']}: {message['content']}")
    
    # Example 2: Using MessageBasedContextManager
    print("\n2. MessageBasedContextManager Example")
    print("   This manager maintains conversation context based on message count")
    
    # Create a message-based context manager with a limit of 5 messages
    message_manager = MessageBasedContextManager(
        config={
            "max_messages": 5,
            "system_prompt": "You are a helpful AI assistant."
        }
    )
    
    # Add the same conversation history
    for message in conversation_history:
        message_manager.add_message(message)
    
    # Add a few more messages to demonstrate pruning
    for i in range(3):
        user_message = {"role": "user", "content": f"This is test message {i+1}"}
        message_manager.add_message(user_message)
        
        context = message_manager.get_current_context()
        response = simulate_llm_response(context)
        assistant_message = {"role": "assistant", "content": response}
        message_manager.add_message(assistant_message)
    
    # Print the final context
    print("\n   Final context from MessageBasedContextManager:")
    for message in message_manager.get_current_context():
        print(f"   - {message['role']}: {message['content']}")
    
    # Example 3: Using ContextWindowManager
    print("\n3. ContextWindowManager Example")
    print("   This manager maintains multiple context windows for different conversations")
    
    # Create a context window manager
    window_manager = ContextWindowManager(
        config={
            "context_type": "token",  # Use token-based context
            "max_tokens": 4000,
            "reserved_tokens": 1000,
            "system_prompt": "You are a helpful AI assistant."
        }
    )
    
    # Create two conversation windows
    window_id1 = "user123"
    window_id2 = "user456"
    
    # Add messages to the first window
    window_manager.add_message(window_id1, system_message)
    window_manager.add_message(window_id1, user_message1)
    window_manager.add_message(window_id1, assistant_message1)
    
    # Add messages to the second window
    window_manager.add_message(window_id2, system_message)
    window_manager.add_message(window_id2, {"role": "user", "content": "How's the weather today?"})
    
    # Get current context for each window
    context1 = window_manager.get_current_context(window_id1)
    context2 = window_manager.get_current_context(window_id2)
    
    # Print contexts for both windows
    print("\n   Context for window 1:")
    for message in context1:
        print(f"   - {message['role']}: {message['content']}")
    
    print("\n   Context for window 2:")
    for message in context2:
        print(f"   - {message['role']}: {message['content']}")
    
    # Example 4: Advanced features
    print("\n4. Advanced Features")
    
    # Update configuration for token manager
    token_manager.update_config({
        "max_tokens": 6000,
        "reserved_tokens": 2000
    })
    print(f"   ✓ Updated token manager configuration")
    
    # Estimate tokens in a message
    message = {"role": "user", "content": "This is a test message to estimate tokens."}
    estimated_tokens = token_manager.estimate_tokens(message)
    print(f"   ✓ Estimated tokens for message: {estimated_tokens}")
    
    # Clean HTML from a message
    html_message = "<p>This is a <b>message</b> with <i>HTML</i> tags.</p>"
    cleaned_message = token_manager.clean_html(html_message)
    print(f"   ✓ Cleaned HTML message: '{cleaned_message}'")

if __name__ == "__main__":
    main() 