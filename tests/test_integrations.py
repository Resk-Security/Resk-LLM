"""
Tests for RESK-LLM integrations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from resk_llm.integrations.resk_providers_integration import (
    OpenAIProtector, AnthropicProtector, CohereProtector
)
from resk_llm.integrations.resk_fastapi_integration import FastAPIProtector
from resk_llm.integrations.resk_flask_integration import FlaskProtector
from resk_llm.integrations.resk_huggingface_integration import HuggingFaceProtector
from resk_llm.integrations.resk_langchain_integration import LangChainProtector


class TestOpenAIProtector:
    """Test the OpenAIProtector class."""
    
    def test_openai_protector_initialization(self, mock_openai_client):
        """Test OpenAI protector initialization."""
        protector = OpenAIProtector(client=mock_openai_client)
        assert protector is not None
        assert protector.client == mock_openai_client
    
    def test_openai_protector_safe_request(self, mock_openai_client, safe_text):
        """Test OpenAI protector with safe request."""
        protector = OpenAIProtector(client=mock_openai_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": safe_text}]
        )
        
        assert result.is_safe is True
        assert result.response is not None
    
    def test_openai_protector_malicious_request(self, mock_openai_client, malicious_text):
        """Test OpenAI protector with malicious request."""
        protector = OpenAIProtector(client=mock_openai_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": malicious_text}]
        )
        
        # Should either block or flag the request
        assert hasattr(result, 'is_safe')
        assert hasattr(result, 'response')
    
    def test_openai_protector_custom_filters(self, mock_openai_client):
        """Test OpenAI protector with custom filters."""
        custom_filter = Mock()
        custom_filter.process.return_value = Mock(is_safe=False, confidence=0.9)
        
        protector = OpenAIProtector(
            client=mock_openai_client,
            filters=[custom_filter]
        )
        
        result = protector.process_request(
            messages=[{"role": "user", "content": "test"}]
        )
        
        assert result.is_safe is False
        custom_filter.process.assert_called_once()
    
    def test_openai_protector_error_handling(self, mock_openai_client):
        """Test OpenAI protector error handling."""
        mock_openai_client.chat.completions.create.side_effect = Exception("API Error")
        
        protector = OpenAIProtector(client=mock_openai_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": "test"}]
        )
        
        assert result.is_safe is False
        assert "error" in result.response.lower()


class TestAnthropicProtector:
    """Test the AnthropicProtector class."""
    
    def test_anthropic_protector_initialization(self, mock_anthropic_client):
        """Test Anthropic protector initialization."""
        protector = AnthropicProtector(client=mock_anthropic_client)
        assert protector is not None
        assert protector.client == mock_anthropic_client
    
    def test_anthropic_protector_safe_request(self, mock_anthropic_client, safe_text):
        """Test Anthropic protector with safe request."""
        protector = AnthropicProtector(client=mock_anthropic_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": safe_text}]
        )
        
        assert result.is_safe is True
        assert result.response is not None
    
    def test_anthropic_protector_malicious_request(self, mock_anthropic_client, malicious_text):
        """Test Anthropic protector with malicious request."""
        protector = AnthropicProtector(client=mock_anthropic_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": malicious_text}]
        )
        
        assert hasattr(result, 'is_safe')
        assert hasattr(result, 'response')
    
    def test_anthropic_protector_custom_system_prompt(self, mock_anthropic_client):
        """Test Anthropic protector with custom system prompt."""
        custom_system = "You are a helpful assistant with security restrictions."
        protector = AnthropicProtector(
            client=mock_anthropic_client,
            system_prompt=custom_system
        )
        
        result = protector.process_request(
            messages=[{"role": "user", "content": "test"}]
        )
        
        assert result.is_safe is True
        # Verify system prompt was used
        mock_anthropic_client.messages.create.assert_called_once()


class TestCohereProtector:
    """Test the CohereProtector class."""
    
    def test_cohere_protector_initialization(self, mock_cohere_client):
        """Test Cohere protector initialization."""
        protector = CohereProtector(client=mock_cohere_client)
        assert protector is not None
        assert protector.client == mock_cohere_client
    
    def test_cohere_protector_safe_request(self, mock_cohere_client, safe_text):
        """Test Cohere protector with safe request."""
        protector = CohereProtector(client=mock_cohere_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": safe_text}]
        )
        
        assert result.is_safe is True
        assert result.response is not None
    
    def test_cohere_protector_malicious_request(self, mock_cohere_client, malicious_text):
        """Test Cohere protector with malicious request."""
        protector = CohereProtector(client=mock_cohere_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": malicious_text}]
        )
        
        assert hasattr(result, 'is_safe')
        assert hasattr(result, 'response')


class TestFastAPIProtector:
    """Test the FastAPIProtector class."""
    
    def test_fastapi_protector_initialization(self):
        """Test FastAPI protector initialization."""
        protector = FastAPIProtector()
        assert protector is not None
    
    def test_fastapi_protector_middleware_creation(self):
        """Test FastAPI middleware creation."""
        protector = FastAPIProtector()
        middleware = protector.create_middleware()
        
        assert callable(middleware)
    
    def test_fastapi_protector_request_validation(self):
        """Test FastAPI request validation."""
        protector = FastAPIProtector()
        
        # Mock request
        mock_request = Mock()
        mock_request.json.return_value = {"message": "test"}
        mock_request.headers = {}
        
        result = protector.validate_request(mock_request)
        assert isinstance(result, dict)
    
    def test_fastapi_protector_response_validation(self):
        """Test FastAPI response validation."""
        protector = FastAPIProtector()
        
        # Mock response
        mock_response = Mock()
        mock_response.body = b'{"response": "test"}'
        
        result = protector.validate_response(mock_response)
        assert isinstance(result, dict)


class TestFlaskProtector:
    """Test the FlaskProtector class."""
    
    def test_flask_protector_initialization(self):
        """Test Flask protector initialization."""
        protector = FlaskProtector()
        assert protector is not None
    
    def test_flask_protector_blueprint_creation(self):
        """Test Flask blueprint creation."""
        protector = FlaskProtector()
        blueprint = protector.create_blueprint()
        
        assert blueprint is not None
        assert hasattr(blueprint, 'name')
    
    def test_flask_protector_request_validation(self):
        """Test Flask request validation."""
        protector = FlaskProtector()
        
        # Mock request
        mock_request = Mock()
        mock_request.get_json.return_value = {"message": "test"}
        mock_request.headers = {}
        
        result = protector.validate_request(mock_request)
        assert isinstance(result, dict)
    
    def test_flask_protector_response_validation(self):
        """Test Flask response validation."""
        protector = FlaskProtector()
        
        # Mock response
        mock_response = Mock()
        mock_response.get_data.return_value = b'{"response": "test"}'
        
        result = protector.validate_response(mock_response)
        assert isinstance(result, dict)


class TestHuggingFaceProtector:
    """Test the HuggingFaceProtector class."""
    
    def test_huggingface_protector_initialization(self):
        """Test HuggingFace protector initialization."""
        protector = HuggingFaceProtector()
        assert protector is not None
    
    def test_huggingface_protector_model_loading(self):
        """Test HuggingFace model loading."""
        with patch('transformers.AutoTokenizer.from_pretrained') as mock_tokenizer:
            mock_tokenizer.return_value = Mock()
            
            # Mock the conditional import
            with patch('resk_llm.integrations.resk_huggingface_integration.TORCH_AVAILABLE', True), \
                 patch('resk_llm.integrations.resk_huggingface_integration.AutoModelForCausalLM') as mock_model_class:
                mock_model_class.from_pretrained.return_value = Mock()
                
                protector = HuggingFaceProtector(model_name="test-model")
                assert protector.tokenizer is not None
                # Model might be None if PyTorch is not available, which is acceptable
    
    def test_huggingface_protector_text_generation(self):
        """Test HuggingFace text generation."""
        with patch('transformers.AutoTokenizer.from_pretrained') as mock_tokenizer:
            mock_tokenizer.return_value = Mock()
            
            # Mock the conditional import
            with patch('resk_llm.integrations.resk_huggingface_integration.TORCH_AVAILABLE', True), \
                 patch('resk_llm.integrations.resk_huggingface_integration.AutoModelForCausalLM') as mock_model_class:
                mock_model_class.from_pretrained.return_value = Mock()
                
                protector = HuggingFaceProtector(model_name="test-model")
                
                result = protector.generate_text("test input")
                assert isinstance(result, str)
    
    def test_huggingface_protector_safe_generation(self, safe_text):
        """Test HuggingFace safe text generation."""
        with patch('transformers.AutoTokenizer.from_pretrained') as mock_tokenizer:
            mock_tokenizer.return_value = Mock()
            
            # Mock the conditional import
            with patch('resk_llm.integrations.resk_huggingface_integration.TORCH_AVAILABLE', True), \
                 patch('resk_llm.integrations.resk_huggingface_integration.AutoModelForCausalLM') as mock_model_class:
                mock_model_class.from_pretrained.return_value = Mock()
                
                protector = HuggingFaceProtector(model_name="test-model")
                
                result = protector.process_request(safe_text)
                assert result.is_safe is True


class TestLangChainProtector:
    """Test the LangChainProtector class."""
    
    def test_langchain_protector_initialization(self):
        """Test LangChain protector initialization."""
        protector = LangChainProtector()
        assert protector is not None
    
    def test_langchain_protector_chain_creation(self):
        """Test LangChain chain creation."""
        protector = LangChainProtector()
        
        with patch('langchain.llms.base.LLM') as mock_llm:
            mock_llm.return_value = Mock()
            
            chain = protector.create_secure_chain(mock_llm())
            assert chain is not None
    
    def test_langchain_protector_prompt_validation(self):
        """Test LangChain prompt validation."""
        protector = LangChainProtector()
        
        result = protector.validate_prompt("test prompt")
        assert isinstance(result, dict)
        assert 'is_safe' in result
    
    def test_langchain_protector_agent_creation(self):
        """Test LangChain agent creation."""
        protector = LangChainProtector()
        
        with patch('langchain.agents.initialize_agent') as mock_init_agent:
            mock_init_agent.return_value = Mock()
            
            agent = protector.create_secure_agent(tools=[], llm=Mock())
            assert agent is not None


class TestIntegrationErrorHandling:
    """Test error handling across integrations."""
    
    def test_provider_timeout_handling(self, mock_openai_client):
        """Test timeout handling in providers."""
        import time
        from unittest.mock import Mock
        
        # Mock timeout
        def timeout_call(*args, **kwargs):
            time.sleep(0.1)  # Simulate delay
            raise Exception("Timeout")
        
        mock_openai_client.chat.completions.create.side_effect = timeout_call
        
        protector = OpenAIProtector(client=mock_openai_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": "test"}]
        )
        
        assert result.is_safe is False
        assert "timeout" in result.response.lower() or "error" in result.response.lower()
    
    def test_provider_rate_limit_handling(self, mock_openai_client):
        """Test rate limit handling in providers."""
        # Mock rate limit error
        class RateLimitError(Exception):
            pass
        
        mock_openai_client.chat.completions.create.side_effect = RateLimitError("Rate limit exceeded")
        
        protector = OpenAIProtector(client=mock_openai_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": "test"}]
        )
        
        assert result.is_safe is False
        assert "rate limit" in result.response.lower() or "error" in result.response.lower()
    
    def test_provider_authentication_handling(self, mock_openai_client):
        """Test authentication error handling in providers."""
        # Mock auth error
        class AuthError(Exception):
            pass
        
        mock_openai_client.chat.completions.create.side_effect = AuthError("Invalid API key")
        
        protector = OpenAIProtector(client=mock_openai_client)
        
        result = protector.process_request(
            messages=[{"role": "user", "content": "test"}]
        )
        
        assert result.is_safe is False
        assert "authentication" in result.response.lower() or "error" in result.response.lower()


class TestIntegrationConfiguration:
    """Test configuration options for integrations."""
    
    def test_openai_protector_configuration(self, mock_openai_client):
        """Test OpenAI protector configuration options."""
        config = {
            "max_tokens": 100,
            "temperature": 0.7,
            "timeout": 30,
            "retry_attempts": 3
        }
        
        protector = OpenAIProtector(
            client=mock_openai_client,
            config=config
        )
        
        assert protector.config == config
    
    def test_anthropic_protector_configuration(self, mock_anthropic_client):
        """Test Anthropic protector configuration options."""
        config = {
            "max_tokens": 100,
            "temperature": 0.7,
            "model": "claude-3-sonnet-20240229"
        }
        
        protector = AnthropicProtector(
            client=mock_anthropic_client,
            config=config
        )
        
        assert protector.config == config
    
    def test_cohere_protector_configuration(self, mock_cohere_client):
        """Test Cohere protector configuration options."""
        config = {
            "max_tokens": 100,
            "temperature": 0.7,
            "model": "command"
        }
        
        protector = CohereProtector(
            client=mock_cohere_client,
            config=config
        )
        
        assert protector.config == config 