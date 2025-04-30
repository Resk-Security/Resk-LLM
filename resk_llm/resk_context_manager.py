from typing import Dict, List, Union, Optional, Any, Tuple, TypedDict
import re
import json
import time
import logging
from collections import deque

from resk_llm.core.abc import SecurityComponent

# Logger configuration
logger = logging.getLogger(__name__)

class TextCleaner:
    """
    Class for cleaning and formatting text.
    """
    @staticmethod
    def clean_text(text: str) -> str:
        """
        Clean text by normalizing whitespace.
        
        Args:
            text: Text to clean
            
        Returns:
            Cleaned text
        """
        return ' '.join(text.split())

    @staticmethod
    def truncate_text(text: str, max_length: int) -> str:
        """
        Truncate text to a maximum length.
        
        Args:
            text: Text to truncate
            max_length: Maximum length
            
        Returns:
            Truncated text
        """
        if len(text) <= max_length:
            return text
        
        # Try to truncate at the last space to avoid cutting a word
        last_space = text[:max_length].rfind(' ')
        if last_space > max_length * 0.8:  # If we lose less than 20% of the text
            return text[:last_space] + "..."
        
        return text[:max_length] + "..."
    
    @staticmethod
    def remove_duplicate_lines(text: str) -> str:
        """
        Remove consecutive duplicate lines.
        
        Args:
            text: Text to clean
            
        Returns:
            Cleaned text
        """
        lines = text.split('\n')
        result = []
        prev_line = None
        
        for line in lines:
            if line != prev_line:
                result.append(line)
                prev_line = line
                
        return '\n'.join(result)
    
    @staticmethod
    def format_code_blocks(text: str) -> str:
        """
        Properly format code blocks.
        
        Args:
            text: Text to format
            
        Returns:
            Formatted text
        """
        # Ensure code blocks have correct delimiters
        code_block_pattern = r'```(?:\w+)?\n(.*?)\n```'
        
        def fix_code_block(match):
            content = match.group(1)
            if not content.endswith('\n'):
                content += '\n'
            return f'```\n{content}```'
        
        return re.sub(code_block_pattern, fix_code_block, text, flags=re.DOTALL)

# Define the structure for context manager configuration
class ContextManagerConfig(TypedDict, total=False):
    model_info: Dict[str, Union[int, str]]
    preserved_prompts: int
    # Add other optional keys used by subclasses
    reserved_tokens: int 
    compression_enabled: bool
    max_messages: int
    smart_pruning: bool

# Ignore type-var error for TypedDict compatibility
class ContextManagerBase(SecurityComponent[ContextManagerConfig]): # type: ignore[type-var]
    """
    Base class for context managers.
    """
    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2):
        """
        Initialize the base context manager.
        
        Args:
            model_info: Model information dictionary
            preserved_prompts: Number of prompts to preserve
        """
        config: ContextManagerConfig = {
            "model_info": model_info,
            "preserved_prompts": preserved_prompts
        }
        super().__init__(config)
        self.max_context_length = int(model_info.get("context_window", 8192))
        self.preserved_prompts = preserved_prompts
        self.text_cleaner = TextCleaner()
        
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if "model_info" not in self.config:
            raise ValueError("model_info is required")
        
        model_info = self.config["model_info"]
        if not isinstance(model_info, dict):
            raise ValueError("model_info must be a dictionary")
        
        if "context_window" not in model_info:
            raise ValueError("context_window is required in model_info")

    def update_config(self, config: ContextManagerConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if "model_info" in config:
            model_info = config["model_info"]
            self.max_context_length = int(model_info.get("context_window", 8192))
        
        if "preserved_prompts" in config:
            self.preserved_prompts = config["preserved_prompts"]
        
    def clean_message(self, message: str) -> str:
        """
        Clean a message.
        
        Args:
            message: Message to clean
            
        Returns:
            Cleaned message
        """
        message = self.text_cleaner.clean_text(message)
        message = self.text_cleaner.remove_duplicate_lines(message)
        message = self.text_cleaner.format_code_blocks(message)
        message = self._close_html_tags(message)
        return message

    def _close_html_tags(self, text: str) -> str:
        """
        Close open HTML tags in text.
        
        Args:
            text: Text with potentially unclosed tags
            
        Returns:
            Text with closed tags
        """
        opened_tags: List[str] = []
        # Find all open and closed tags
        for match in re.finditer(r'<(/)?(\w+)[^>]*>', text):
            is_closing = match.group(1) is not None
            tag = match.group(2).lower()
            
            # Ignore self-closing tags
            if tag.lower() in ['br', 'hr', 'img', 'input', 'meta', 'link']:
                continue
                
            if is_closing:
                # If it's a closing tag, check if it matches the last opened tag
                if opened_tags and opened_tags[-1] == tag:
                    opened_tags.pop()
                # Otherwise it's a closing tag without a matching opening tag
            else:
                # Add the tag to the list of opened tags
                opened_tags.append(tag)
                
        # Close remaining tags in reverse order
        for tag in reversed(opened_tags):
            text += f'</{tag}>'
            
        return text
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate the number of tokens in text.
        This is an approximation based on word count.
        
        Args:
            text: Text to analyze
            
        Returns:
            Estimated token count
        """
        words = text.split()
        return int(len(words) * 1.3)  # A token is typically ~0.75 words
    
    def _get_message_tokens(self, message: Dict[str, Any]) -> int:
        """
        Estimate the number of tokens in a message.
        
        Args:
            message: Message to analyze
            
        Returns:
            Estimated token count
        """
        content = message.get('content', '')
        role = message.get('role', '')
        
        if isinstance(content, list):  # Multimodal format
            text_content = ""
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text_content += item.get('text', '')
            content = text_content
            
        return self.estimate_tokens(content) + self.estimate_tokens(role) + 4  # +4 for structure tokens
    
    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Manage the sliding context, preserving important messages and truncating if necessary.
        
        Args:
            messages: List of messages
            
        Returns:
            Adjusted list of messages
        """
        # This is an abstract method that should be implemented by subclasses
        raise NotImplementedError("Subclasses must implement manage_sliding_context")


class TokenBasedContextManager(ContextManagerBase):
    """
    Token-based context manager.
    """
    def __init__(self, 
                 model_info: Dict[str, Union[int, str]], 
                 preserved_prompts: int = 2, 
                 reserved_tokens: int = 1000,
                 compression_enabled: bool = False):
        """
        Initialize the token-based context manager.
        
        Args:
            model_info: Model information dictionary
            preserved_prompts: Number of prompts to preserve
            reserved_tokens: Number of tokens reserved for the response
            compression_enabled: Enable context compression
        """
        super().__init__(model_info, preserved_prompts)
        self.config.update({
            "reserved_tokens": reserved_tokens,
            "compression_enabled": compression_enabled
        })
        self.reserved_tokens = reserved_tokens
        self.compression_enabled = compression_enabled
        self.token_estimator = self.estimate_tokens

    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        super()._validate_config()
        
        if "reserved_tokens" in self.config and not isinstance(self.config["reserved_tokens"], int):
            raise ValueError("reserved_tokens must be an integer")
        
        if "compression_enabled" in self.config and not isinstance(self.config["compression_enabled"], bool):
            raise ValueError("compression_enabled must be a boolean")

    def update_config(self, config: ContextManagerConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        super().update_config(config)
        
        if "reserved_tokens" in config:
            self.reserved_tokens = config["reserved_tokens"]
        
        if "compression_enabled" in config:
            self.compression_enabled = config["compression_enabled"]

    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Manage the sliding context, preserving important messages and truncating if necessary.
        
        Args:
            messages: List of messages
            
        Returns:
            Adjusted list of messages
        """
        # Clean messages and estimate their token size
        cleaned_messages = []
        total_tokens = 0
        
        for msg in messages:
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            if isinstance(content, str):
                cleaned_content = self.clean_message(content)
                message_tokens = self.token_estimator(cleaned_content) + self.token_estimator(role) + 4
                cleaned_messages.append({
                    'role': role, 
                    'content': cleaned_content, 
                    'tokens': message_tokens
                })
                total_tokens += message_tokens
            else:  # Multimodal messages
                # Rename inner variable
                inner_cleaned_content: List[Any] = []
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text = item.get('text', '')
                        cleaned_text = self.clean_message(text)
                        inner_cleaned_content.append({**item, 'text': cleaned_text})
                    else:
                        inner_cleaned_content.append(item)
                        
                cleaned_messages.append({
                    'role': role, 
                    'content': inner_cleaned_content, # Use renamed variable
                    'tokens': self.token_estimator(role) + 4
                })
                total_tokens += self.token_estimator(role) + 4
        
        # If the total tokens are within the limit, return all messages
        if total_tokens <= int(self.max_context_length) - int(self.reserved_tokens):
            # Remove 'tokens' field before returning
            return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in cleaned_messages]
        
        # Preserve system messages and first user prompts
        preserved_messages = cleaned_messages[:self.preserved_prompts]
        preserved_tokens_int: int = int(sum(int(msg['tokens']) for msg in preserved_messages))
        
        # Compress context if enabled
        if self.compression_enabled and len(cleaned_messages) > self.preserved_prompts + 5:
            return self._compress_context(cleaned_messages, preserved_tokens_int)
        
        # Calculate tokens for recent messages
        recent_messages = cleaned_messages[-3:]  # 3 most recent messages
        recent_tokens_int: int = int(sum(int(msg['tokens']) for msg in recent_messages))
        
        # Calculate tokens available for summary
        max_context_length_int: int = int(self.max_context_length)
        reserved_tokens_int: int = int(self.reserved_tokens)
        available_tokens_int: int = max_context_length_int - reserved_tokens_int - preserved_tokens_int - recent_tokens_int
        
        # Keep as many recent messages as possible
        remaining_messages = cleaned_messages[self.preserved_prompts:]
        included_messages: List[Dict[str, Any]] = []
        
        # Process messages from most recent to oldest
        for msg in reversed(remaining_messages):
            token_count: int = int(msg['tokens'])
            if token_count <= available_tokens_int:
                included_messages.insert(0, msg)
                available_tokens_int -= token_count
            else:
                # If a message is too long, try to truncate it
                if available_tokens_int > 200:  # Only if we still have enough space
                    content = msg['content']
                    role = msg['role']
                    
                    if isinstance(content, str):
                        # Truncate text content
                        truncated_content = self.text_cleaner.truncate_text(
                            content, 
                            int(available_tokens_int / 1.3)  # Approximate conversion tokens -> characters
                        )
                        
                        # Check that truncation reduced size enough
                        truncated_tokens = self.token_estimator(truncated_content) + self.token_estimator(role) + 4
                        
                        if truncated_tokens <= available_tokens_int:
                            truncated_msg: Dict[str, Any] = {
                                'role': role,
                                'content': truncated_content + "\n[Message truncated to respect context limit]",
                                'tokens': truncated_tokens
                            }
                            included_messages.insert(0, truncated_msg)
                            available_tokens_int -= truncated_tokens
                    
                break  # Exit loop after processing the first message that's too long
        
        # Combine preserved and included messages
        final_messages = preserved_messages + included_messages
        
        # Remove 'tokens' field before returning
        return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in final_messages]
    
    def _compress_context(self, messages: List[Dict[str, Any]], preserved_tokens: int) -> List[Dict[str, Any]]:
        """
        Compress the context by summarizing older messages.
        
        Args:
            messages: List of messages with their tokens
            preserved_tokens: Number of tokens already used by preserved messages
            
        Returns:
            Compressed list of messages
        """
        # Preserve protected messages (system, instructions, etc.)
        preserved_messages = messages[:self.preserved_prompts]
        remaining_messages = messages[self.preserved_prompts:]
        
        # Do nothing if we have few messages
        if len(remaining_messages) <= 5:
            return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in messages]
        
        # Divide remaining messages into groups
        recent_messages = remaining_messages[-3:]  # 3 most recent messages
        older_messages = remaining_messages[:-3]  # Older messages to compress
        
        # Calculate tokens for recent messages
        recent_tokens_int: int = int(sum(int(msg['tokens']) for msg in recent_messages))
        
        # Calculate tokens available for summary
        max_context_length_int: int = int(self.max_context_length)
        reserved_tokens_int: int = int(self.reserved_tokens)
        preserved_tokens_int: int = int(preserved_tokens)
        available_tokens_int: int = max_context_length_int - reserved_tokens_int - preserved_tokens_int - recent_tokens_int
        
        # Create a summary of older conversations
        summary = {
            'role': 'system',
            'content': f"[Summary of {len(older_messages)} previous messages: "
        }
        
        # Extract key points from each message
        points = []
        for msg in older_messages:
            if isinstance(msg['content'], str):
                # Take the first sentence or X first characters as key point
                content = msg['content'].strip()
                first_sentence_match = re.match(r'^(.*?[.!?])\s', content)
                
                if first_sentence_match:
                    summary_point = first_sentence_match.group(1)
                else:
                    summary_point = content[:100] + ("..." if len(content) > 100 else "")
                
                points.append(f"{msg['role']}: {summary_point}")
        
        # Add as many points as possible within the token limit
        summary_content = summary['content']
        for point in points:
            point_tokens = self.token_estimator(point + "\n")
            if self.token_estimator(summary_content) + point_tokens <= available_tokens_int:
                summary_content += "\n- " + point
            else:
                summary_content += "\n- [and other messages...]"
                break
        
        summary_content += "]"
        summary['content'] = summary_content
        # Convert token estimation to the expected type (string)
        summary['tokens'] = str(int(self.token_estimator(summary_content)))
        
        # Combine preserved messages, summary, and recent messages
        final_messages = preserved_messages + [summary] + recent_messages
        
        # Remove 'tokens' field before returning
        return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in final_messages]


class MessageBasedContextManager(ContextManagerBase):
    """
    Message-based context manager.
    """
    def __init__(self, 
                 model_info: Dict[str, Union[int, str]], 
                 preserved_prompts: int = 2, 
                 max_messages: int = 50,
                 smart_pruning: bool = False):
        """
        Initialize the message-based context manager.
        
        Args:
            model_info: Model information dictionary
            preserved_prompts: Number of prompts to preserve
            max_messages: Maximum number of messages to keep
            smart_pruning: Use intelligent message pruning
        """
        super().__init__(model_info, preserved_prompts)
        self.config.update({
            "max_messages": max_messages,
            "smart_pruning": smart_pruning
        })
        self.max_messages = max_messages
        self.smart_pruning = smart_pruning
        self.message_importance: Dict[int, float] = {}  # Store calculated message importance
        
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        super()._validate_config()
        
        if "max_messages" in self.config and not isinstance(self.config["max_messages"], int):
            raise ValueError("max_messages must be an integer")
        
        if "smart_pruning" in self.config and not isinstance(self.config["smart_pruning"], bool):
            raise ValueError("smart_pruning must be a boolean")

    def update_config(self, config: ContextManagerConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        super().update_config(config)
        
        if "max_messages" in config:
            self.max_messages = config["max_messages"]
        
        if "smart_pruning" in config:
            self.smart_pruning = config["smart_pruning"]
        
    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Manage the sliding context, preserving important messages and respecting the maximum count.
        
        Args:
            messages: List of messages
            
        Returns:
            Adjusted list of messages
        """
        # Clean messages
        cleaned_messages = []
        for msg in messages:
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            if isinstance(content, str):
                cleaned_content = self.clean_message(content)
                cleaned_messages.append({'role': role, 'content': cleaned_content})
            else:  # Multimodal messages
                # Rename inner variable
                inner_cleaned_content: List[Any] = []
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text = item.get('text', '')
                        cleaned_text = self.clean_message(text)
                        inner_cleaned_content.append({**item, 'text': cleaned_text})
                    else:
                        inner_cleaned_content.append(item)
                        
                cleaned_messages.append({'role': role, 'content': inner_cleaned_content}) # Use renamed variable
        
        # If the number of messages is within the limit, return all messages
        if len(cleaned_messages) <= self.max_messages:
            return cleaned_messages
        
        # Preserve system messages and first user prompts
        preserved_messages = cleaned_messages[:self.preserved_prompts]
        remaining_messages = cleaned_messages[self.preserved_prompts:]
        
        # If smart pruning is enabled, select the most important messages
        if self.smart_pruning:
            return self._smart_prune_messages(preserved_messages, remaining_messages)
        
        # Otherwise, simply keep the most recent messages
        retained_messages = remaining_messages[-(self.max_messages - len(preserved_messages)):]
        
        return preserved_messages + retained_messages
    
    def _smart_prune_messages(self, preserved_messages: List[Dict[str, Any]], remaining_messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Intelligently prune messages, keeping the most important ones.
        
        Args:
            preserved_messages: Messages to preserve
            remaining_messages: Messages to prune
            
        Returns:
            Pruned list of messages
        """
        # Calculate how many messages we need to retain
        num_to_retain = self.max_messages - len(preserved_messages)
        
        if num_to_retain >= len(remaining_messages):
            return preserved_messages + remaining_messages
        
        # Always keep the 3 most recent messages
        num_recent = min(3, len(remaining_messages))
        recent_messages = remaining_messages[-num_recent:]
        older_messages = remaining_messages[:-num_recent]
        
        # Number of older messages to keep
        num_older_to_retain = num_to_retain - num_recent
        
        if num_older_to_retain <= 0:
            return preserved_messages + recent_messages
        
        # Evaluate importance of each message
        scored_messages = []
        for idx, msg in enumerate(older_messages):
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            # Extract text for evaluation
            if isinstance(content, list):
                text_content = ""
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text_content += item.get('text', '')
                content = text_content
            
            # Calculate importance score
            importance = self._calculate_message_importance(content, role, idx, len(older_messages))
            scored_messages.append((importance, msg))
        
        # Sort by decreasing importance and take top N
        scored_messages.sort(key=lambda x: x[0], reverse=True)
        selected_older_messages = [msg for _, msg in scored_messages[:num_older_to_retain]]
        
        # Preserve chronological order
        selected_message_indices = [older_messages.index(msg) for msg in selected_older_messages]
        selected_message_indices.sort()
        ordered_selected_messages = [older_messages[i] for i in selected_message_indices]
        
        return preserved_messages + ordered_selected_messages + recent_messages
    
    def _calculate_message_importance(self, content: str, role: str, index: int, total_messages: int) -> float:
        """
        Calculate the importance of a message.
        
        Args:
            content: Message content
            role: Sender role
            index: Message position
            total_messages: Total number of messages
            
        Returns:
            Importance score
        """
        # Assign base scores by role
        role_scores = {
            'system': 10.0,
            'assistant': 7.0,
            'user': 5.0,
            'function': 3.0,
            'tool': 3.0
        }
        
        base_score = role_scores.get(role.lower(), 1.0)
        
        # Bonus for more recent messages (relative position)
        recency_score = index / total_messages * 3.0
        
        # Bonus for messages containing key information
        content_score = 0.0
        
        if isinstance(content, str):
            # Code detection
            if '```' in content or re.search(r'<code>\s*[\s\S]*?\s*</code>', content):
                content_score += 5.0
                
            # URL or file path detection
            if re.search(r'https?://\S+|file:/\S+|/\w+/\S+', content):
                content_score += 2.0
                
            # Question detection
            if '?' in content:
                content_score += 1.5
                
            # Bonus for longer messages (but not too long)
            length = len(content)
            if 100 <= length <= 1000:
                content_score += 1.0
            elif length > 1000:
                content_score += 0.5
        
        # Combine scores
        total_score = base_score + recency_score + content_score
        
        return total_score

    def calculate_message_importance(self, messages: List[Dict[str, Any]]) -> Dict[int, float]:
        """
        Calculate the importance of each message in a conversation.
        
        Args:
            messages: List of messages
            
        Returns:
            Dictionary mapping message index to importance score
        """
        message_importance: Dict[int, float] = {}
        
        for idx, msg in enumerate(messages):
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            # Extract text for multimodal messages
            if isinstance(content, list):
                text_content = ""
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text_content += item.get('text', '')
                content = text_content
            
            importance = self._calculate_message_importance(
                content, role, idx, len(messages)
            )
            message_importance[idx] = importance
        
        return message_importance

    def combine_sliding_windows(self, windows: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Combine sliding windows into a single context.
        
        Args:
            windows: List of message windows
            
        Returns:
            Combined list of messages
        """
        if not windows:
            return []
            
        combined_context: List[Dict[str, Any]] = []
        seen_messages = set()  # To avoid duplicates
        
        # Process windows from newest to oldest
        for window in reversed(windows):
            for msg in reversed(window):
                # Create a unique fingerprint for the message
                msg_content = msg.get('content', '')
                if isinstance(msg_content, list):
                    # For multimodal messages, extract text
                    text_content_inner = "" # Initialize as empty string
                    for item in msg_content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            # Fix: Use += for string concatenation
                            text_content_inner += item.get('text', '') + " " # Add space between parts
                    # Fix: Assign the built string, remove incorrect append call
                    # Assign to outer msg_content which is used below
                    msg_content = text_content_inner.strip() # Assign the concatenated string
                
                # Create a unique fingerprint for the message
                msg_fingerprint = f"{msg.get('role', '')}:{msg_content[:50]}"
                
                if msg_fingerprint not in seen_messages:
                    combined_context.insert(0, msg)
                    seen_messages.add(msg_fingerprint)
        
        return combined_context


class ContextWindowManager:
    """
    Advanced context window manager with support for multiple windows.
    """
    def __init__(self, 
                 model_info: Dict[str, Union[int, str]], 
                 window_size: int = 10, 
                 max_windows: int = 5,
                 overlap: int = 2):
        """
        Initialize the context window manager.
        
        Args:
            model_info: Model information dictionary (context_window, etc.)
            window_size: Size of each window
            max_windows: Maximum number of windows to keep
            overlap: Number of overlapping messages between windows
        """
        self.model_info = model_info
        self.window_size = window_size
        self.max_windows = max_windows
        self.overlap = overlap
        
        self.windows: List[List[Dict[str, Any]]] = []
        self.history_buffer: List[Dict[str, Any]] = []
        self.message_index: Dict[int, Dict[str, Any]] = {}
        self.next_id = 0
        self.text_cleaner = TextCleaner()
        
    def add_message(self, message: Dict[str, Any]) -> None:
        """
        Add a message to the context manager.
        
        Args:
            message: Message to add
        """
        # Clean the message
        content = message.get('content', '')
        role = message.get('role', '')
        
        if isinstance(content, str):
            cleaned_content = self.text_cleaner.clean_text(content)
            cleaned_message = {'role': role, 'content': cleaned_content}
        else:  # Multimodal messages
            # Rename variable to avoid redefinition
            cleaned_content_list: List[Any] = [] 
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text = item.get('text', '')
                    cleaned_text = self.text_cleaner.clean_text(text)
                    # Append the cleaned item to the list
                    cleaned_content_list.append({**item, 'text': cleaned_text}) 
                else:
                    # Append non-text items directly
                    cleaned_content_list.append(item) 
                    
            # Assign the list to the message content
            cleaned_message = {'role': role, 'content': cleaned_content_list} 
            
        # Add to history buffer
        self.history_buffer.append(cleaned_message)
        
        # Update windows
        self._update_windows()
        
    def get_current_context(self, max_messages: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Return the current context.
        
        Args:
            max_messages: Maximum number of messages to include
            
        Returns:
            List of context messages
        """
        # If no windows exist, return history buffer
        if not self.windows:
            context = list(self.history_buffer)
            if max_messages:
                return context[-max_messages:]
            return context
        
        # Combine all windows
        combined_context: List[Dict[str, Any]] = []
        seen_messages = set()  # To avoid duplicates
        
        # Process windows from newest to oldest
        for window in reversed(self.windows):
            for msg in reversed(window):
                # Create a unique fingerprint for the message
                msg_content = msg.get('content', '')
                if isinstance(msg_content, list):
                    # For multimodal messages, extract text
                    text_content_inner = "" # Initialize as empty string
                    for item in msg_content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            # Fix: Use += for string concatenation
                            text_content_inner += item.get('text', '') + " " # Add space between parts
                    # Fix: Assign the built string, remove incorrect append call
                    # Assign to outer msg_content which is used below
                    msg_content = text_content_inner.strip() # Assign the concatenated string
                
                # Create a unique fingerprint for the message
                msg_fingerprint = f"{msg.get('role', '')}:{msg_content[:50]}"
                
                if msg_fingerprint not in seen_messages:
                    combined_context.insert(0, msg)
                    seen_messages.add(msg_fingerprint)
        
        # Apply message limit
        if max_messages and len(combined_context) > max_messages:
            return combined_context[-max_messages:]
            
        return combined_context
    
    def _update_windows(self) -> None:
        """
        Update context windows.
        """
        # If not enough messages to form a complete window
        if len(self.history_buffer) < self.window_size:
            self.windows = [list(self.history_buffer)]
            return
        
        # Create a new window with the most recent messages
        new_window = list(self.history_buffer)[-self.window_size:]
        
        # If it's the first window
        if not self.windows:
            self.windows.append(new_window)
            return
        
        # Check overlap with the most recent window
        last_window = self.windows[-1]
        overlap_detected = False
        
        # Check if the new window sufficiently overlaps with the last window
        for i in range(1, min(self.overlap + 1, len(last_window), len(new_window))):
            if last_window[-i:] == new_window[:i]:
                overlap_detected = True
                break
        
        # If no overlap, add a new window
        if not overlap_detected:
            self.windows.append(new_window)
            
            # Limit the number of windows
            if len(self.windows) > self.max_windows:
                self.windows.pop(0)
        else:
            # Update the last window
            self.windows[-1] = new_window

    def calculate_message_importance(self, messages: List[Dict[str, Any]]) -> Dict[int, float]:
        """
        Calculate the importance of each message in a conversation.
        
        Args:
            messages: List of messages
            
        Returns:
            Dictionary mapping message index to importance score
        """
        # Create a MessageBasedContextManager temporarily to use its implementation
        temp_manager = MessageBasedContextManager(self.model_info)
        return temp_manager.calculate_message_importance(messages)

    def combine_sliding_windows(self, windows: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Combine sliding windows into a single context.
        
        Args:
            windows: List of message windows
            
        Returns:
            Combined list of messages
        """
        # Create a MessageBasedContextManager temporarily to use its implementation
        temp_manager = MessageBasedContextManager(self.model_info)
        return temp_manager.combine_sliding_windows(windows)
