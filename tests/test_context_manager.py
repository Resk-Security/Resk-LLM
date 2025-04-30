import sys
from resk_llm.resk_context_manager import TokenBasedContextManager

def test_token_based_context_manager():
    try:
        print("Starting TokenBasedContextManager tests...")
        
        # Test 1: Basic message management
        model_info = {"context_window": 8192}
        context_manager = TokenBasedContextManager(
            model_info=model_info,
            preserved_prompts=2,
            reserved_tokens=1000,
            compression_enabled=False
        )
        
        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello, how are you?"},
            {"role": "assistant", "content": "I'm doing well, thank you for asking!"},
            {"role": "user", "content": "Can you help me with a question?"}
        ]
        
        managed_messages = context_manager.manage_sliding_context(test_messages)
        print(f"Number of managed messages: {len(managed_messages)}")
        assert len(managed_messages) == 4, "Should maintain all messages when under context limit"
        
        # Test 2: Large message handling
        large_content = "This is a very large message. " * 1000  # Simulate a large message
        large_message = {"role": "user", "content": large_content}
        test_with_large = test_messages + [large_message]
        
        managed_with_large = context_manager.manage_sliding_context(test_with_large)
        print(f"Number of managed messages with large message: {len(managed_with_large)}")
        assert len(managed_with_large) >= 2, "Should preserve at least system and one user message"
        
        print("All tests completed successfully!")
        
    except Exception as e:
        print(f"Error during testing: {str(e)}")




if __name__ == "__main__":
    success = test_token_based_context_manager()
    sys.exit(0 if success else 1) 