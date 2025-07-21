from typing import Dict, List, Union, Optional, Any, Tuple, TypedDict
import re
import json
import time
import logging
from collections import deque
from dataclasses import dataclass, field

from resk_llm.core.abc import SecurityComponent

# Logger configuration
logger = logging.getLogger(__name__)

@dataclass
class RESK_TextCleaner:
    """
    Utility class for cleaning and formatting text.
    """
    @staticmethod
    def clean_text(text: str) -> str:
        return ' '.join(text.split())

    @staticmethod
    def truncate_text(text: str, max_length: int) -> str:
        if len(text) <= max_length:
            return text
        last_space = text[:max_length].rfind(' ')
        if last_space > max_length * 0.8:
            return text[:last_space] + "..."
        return text[:max_length] + "..."

    @staticmethod
    def remove_duplicate_lines(text: str) -> str:
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
        code_block_pattern = r'```(?:\w+)?\n(.*?)\n```'
        def fix_code_block(match):
            content = match.group(1)
            if not content.endswith('\n'):
                content += '\n'
            return f'```\n{content}```'
        return re.sub(code_block_pattern, fix_code_block, text, flags=re.DOTALL)

class RESK_ContextManager(SecurityComponent[Dict[str, Any]]):
    """
    Base class for context managers (RESK).
    """
    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2):
        config: Dict[str, Any] = {
            "model_info": model_info,
            "preserved_prompts": preserved_prompts
        }
        super().__init__(config)
        self.max_context_length = int(model_info.get("context_window", 8192))
        self.preserved_prompts = preserved_prompts
        self.text_cleaner = RESK_TextCleaner()

    def _validate_config(self) -> None:
        if "model_info" not in self.config:
            raise ValueError("model_info is required")
        model_info = self.config["model_info"]
        if not isinstance(model_info, dict):
            raise ValueError("model_info must be a dictionary")
        if "context_window" not in model_info:
            raise ValueError("context_window is required in model_info")

    def update_config(self, config: Dict[str, Any]) -> None:
        self.config.update(config)
        self._validate_config()
        if "model_info" in config:
            model_info = config["model_info"]
            self.max_context_length = int(model_info.get("context_window", 8192))
        if "preserved_prompts" in config:
            self.preserved_prompts = config["preserved_prompts"]

    def clean_message(self, message: str) -> str:
        message = self.text_cleaner.clean_text(message)
        message = self.text_cleaner.remove_duplicate_lines(message)
        message = self.text_cleaner.format_code_blocks(message)
        message = self._close_html_tags(message)
        return message

    def _close_html_tags(self, text: str) -> str:
        opened_tags: List[str] = []
        for match in re.finditer(r'<(/)?(\w+)[^>]*>', text):
            is_closing = match.group(1) is not None
            tag = match.group(2).lower()
            if tag.lower() in ['br', 'hr', 'img', 'input', 'meta', 'link']:
                continue
            if is_closing:
                if opened_tags and opened_tags[-1] == tag:
                    opened_tags.pop()
            else:
                opened_tags.append(tag)
        for tag in reversed(opened_tags):
            text += f'</{tag}>'
        return text

    def estimate_tokens(self, text: str) -> int:
        words = text.split()
        return int(len(words) * 1.3)

    def _get_message_tokens(self, message: Dict[str, Any]) -> int:
        content = message.get('content', '')
        role = message.get('role', '')
        if isinstance(content, list):
            text_content = ""
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text_content += item.get('text', '')
            content = text_content
        return self.estimate_tokens(content) + self.estimate_tokens(role) + 4

    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement manage_sliding_context")

@dataclass
class RESK_TokenBasedContextManager(RESK_ContextManager):
    reserved_tokens: int = 1000
    compression_enabled: bool = False
    token_estimator: Any = field(init=False, default=None)

    def __post_init__(self):
        self.token_estimator = self.estimate_tokens

    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2, reserved_tokens: int = 1000, compression_enabled: bool = False):
        super().__init__(model_info, preserved_prompts)
        self.config.update({
            "reserved_tokens": reserved_tokens,
            "compression_enabled": compression_enabled
        })
        self.reserved_tokens = reserved_tokens
        self.compression_enabled = compression_enabled
        self.token_estimator = self.estimate_tokens

    def _validate_config(self) -> None:
        super()._validate_config()
        if "reserved_tokens" in self.config and not isinstance(self.config["reserved_tokens"], int):
            raise ValueError("reserved_tokens must be an integer")
        if "compression_enabled" in self.config and not isinstance(self.config["compression_enabled"], bool):
            raise ValueError("compression_enabled must be a boolean")

    def update_config(self, config: Dict[str, Any]) -> None:
        super().update_config(config)
        if "reserved_tokens" in config:
            self.reserved_tokens = config["reserved_tokens"]
        if "compression_enabled" in config:
            self.compression_enabled = config["compression_enabled"]

    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # TODO: Refactor en sous-méthodes pour respecter 11 lignes max/méthode
        cleaned_messages = []
        total_tokens = 0
        for msg in messages:
            content = msg.get('content', '')
            role = msg.get('role', '')
            if isinstance(content, str):
                cleaned_content = self.clean_message(content)
                message_tokens = self.token_estimator(cleaned_content) + self.token_estimator(role) + 4
                cleaned_messages.append({'role': role, 'content': cleaned_content, 'tokens': message_tokens})
                total_tokens += message_tokens
            else:
                inner_cleaned_content: List[Any] = []
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text = item.get('text', '')
                        cleaned_text = self.clean_message(text)
                        inner_cleaned_content.append({**item, 'text': cleaned_text})
                    else:
                        inner_cleaned_content.append(item)
                cleaned_messages.append({'role': role, 'content': inner_cleaned_content, 'tokens': self.token_estimator(role) + 4})
                total_tokens += self.token_estimator(role) + 4
        if total_tokens <= int(self.max_context_length) - int(self.reserved_tokens):
            return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in cleaned_messages]
        preserved_messages = cleaned_messages[:self.preserved_prompts]
        preserved_tokens_int: int = int(sum(int(msg['tokens']) for msg in preserved_messages))
        if self.compression_enabled and len(cleaned_messages) > self.preserved_prompts + 5:
            return self._compress_context(cleaned_messages, preserved_tokens_int)
        recent_messages = cleaned_messages[-3:]
        recent_tokens_int: int = int(sum(int(msg['tokens']) for msg in recent_messages))
        max_context_length_int: int = int(self.max_context_length)
        reserved_tokens_int: int = int(self.reserved_tokens)
        available_tokens_int: int = max_context_length_int - reserved_tokens_int - preserved_tokens_int - recent_tokens_int
        remaining_messages = cleaned_messages[self.preserved_prompts:]
        included_messages: List[Dict[str, Any]] = []
        for msg in reversed(remaining_messages):
            token_count: int = int(msg['tokens'])
            if token_count <= available_tokens_int:
                included_messages.insert(0, msg)
                available_tokens_int -= token_count
            else:
                if available_tokens_int > 200:
                    content = msg['content']
                    role = msg['role']
                    if isinstance(content, str):
                        truncated_content = self.text_cleaner.truncate_text(content, int(available_tokens_int / 1.3))
                        truncated_tokens = self.token_estimator(truncated_content) + self.token_estimator(role) + 4
                        if truncated_tokens <= available_tokens_int:
                            truncated_msg: Dict[str, Any] = {
                                'role': role,
                                'content': truncated_content + "\n[Message truncated to respect context limit]",
                                'tokens': truncated_tokens
                            }
                            included_messages.insert(0, truncated_msg)
                            available_tokens_int -= truncated_tokens
                break
        final_messages = preserved_messages + included_messages
        return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in final_messages]

    def _compress_context(self, messages: List[Dict[str, Any]], preserved_tokens: int) -> List[Dict[str, Any]]:
        # TODO: Refactor en sous-méthodes pour respecter 11 lignes max/méthode
        preserved_messages = messages[:self.preserved_prompts]
        remaining_messages = messages[self.preserved_prompts:]
        if len(remaining_messages) <= 5:
            return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in messages]
        recent_messages = remaining_messages[-3:]
        older_messages = remaining_messages[:-3]
        recent_tokens_int: int = int(sum(int(msg['tokens']) for msg in recent_messages))
        max_context_length_int: int = int(self.max_context_length)
        reserved_tokens_int: int = int(self.reserved_tokens)
        preserved_tokens_int: int = int(preserved_tokens)
        available_tokens_int: int = max_context_length_int - reserved_tokens_int - preserved_tokens_int - recent_tokens_int
        summary = {'role': 'system', 'content': f"[Summary of {len(older_messages)} previous messages: "}
        points = []
        for msg in older_messages:
            if isinstance(msg['content'], str):
                content = msg['content'].strip()
                first_sentence_match = re.match(r'^(.*?[.!?])\s', content)
                if first_sentence_match:
                    summary_point = first_sentence_match.group(1)
                else:
                    summary_point = content[:100] + ("..." if len(content) > 100 else "")
                points.append(f"{msg['role']}: {summary_point}")
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
        summary['tokens'] = str(int(self.token_estimator(summary_content)))
        final_messages = preserved_messages + [summary] + recent_messages
        return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in final_messages]

@dataclass
class RESK_MessageBasedContextManager(RESK_ContextManager):
    max_messages: int = 50
    smart_pruning: bool = False
    message_importance: Dict[int, float] = field(default_factory=dict)

    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2, max_messages: int = 50, smart_pruning: bool = False):
        super().__init__(model_info, preserved_prompts)
        self.config.update({
            "max_messages": max_messages,
            "smart_pruning": smart_pruning
        })
        self.max_messages = max_messages
        self.smart_pruning = smart_pruning
        self.message_importance: Dict[int, float] = {}

    def _validate_config(self) -> None:
        super()._validate_config()
        if "max_messages" in self.config and not isinstance(self.config["max_messages"], int):
            raise ValueError("max_messages must be an integer")
        if "smart_pruning" in self.config and not isinstance(self.config["smart_pruning"], bool):
            raise ValueError("smart_pruning must be a boolean")

    def update_config(self, config: Dict[str, Any]) -> None:
        super().update_config(config)
        if "max_messages" in config:
            self.max_messages = config["max_messages"]
        if "smart_pruning" in config:
            self.smart_pruning = config["smart_pruning"]

    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # TODO: Refactor en sous-méthodes pour respecter 11 lignes max/méthode
        cleaned_messages = []
        for msg in messages:
            content = msg.get('content', '')
            role = msg.get('role', '')
            if isinstance(content, str):
                cleaned_content = self.clean_message(content)
                cleaned_messages.append({'role': role, 'content': cleaned_content})
            else:
                inner_cleaned_content: List[Any] = []
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text = item.get('text', '')
                        cleaned_text = self.clean_message(text)
                        inner_cleaned_content.append({**item, 'text': cleaned_text})
                    else:
                        inner_cleaned_content.append(item)
                cleaned_messages.append({'role': role, 'content': inner_cleaned_content})
        if len(cleaned_messages) <= self.max_messages:
            return cleaned_messages
        preserved_messages = cleaned_messages[:self.preserved_prompts]
        remaining_messages = cleaned_messages[self.preserved_prompts:]
        if self.smart_pruning:
            return self._smart_prune_messages(preserved_messages, remaining_messages)
        retained_messages = remaining_messages[-(self.max_messages - len(preserved_messages)):]
        return preserved_messages + retained_messages

    def _smart_prune_messages(self, preserved_messages: List[Dict[str, Any]], remaining_messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # TODO: Refactor en sous-méthodes pour respecter 11 lignes max/méthode
        num_to_retain = self.max_messages - len(preserved_messages)
        if num_to_retain >= len(remaining_messages):
            return preserved_messages + remaining_messages
        num_recent = min(3, len(remaining_messages))
        recent_messages = remaining_messages[-num_recent:]
        older_messages = remaining_messages[:-num_recent]
        num_older_to_retain = num_to_retain - num_recent
        if num_older_to_retain <= 0:
            return preserved_messages + recent_messages
        scored_messages = []
        for idx, msg in enumerate(older_messages):
            content = msg.get('content', '')
            role = msg.get('role', '')
            if isinstance(content, list):
                text_content = ""
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text_content += item.get('text', '')
                content = text_content
            importance = self._calculate_message_importance(content, role, idx, len(older_messages))
            scored_messages.append((importance, msg))
        scored_messages.sort(key=lambda x: x[0], reverse=True)
        selected_older_messages = [msg for _, msg in scored_messages[:num_older_to_retain]]
        selected_message_indices = [older_messages.index(msg) for msg in selected_older_messages]
        selected_message_indices.sort()
        ordered_selected_messages = [older_messages[i] for i in selected_message_indices]
        return preserved_messages + ordered_selected_messages + recent_messages

    def _calculate_message_importance(self, content: str, role: str, index: int, total_messages: int) -> float:
        role_scores = {'system': 10.0, 'assistant': 7.0, 'user': 5.0, 'function': 3.0, 'tool': 3.0}
        base_score = role_scores.get(role.lower(), 1.0)
        recency_score = index / total_messages * 3.0
        content_score = 0.0
        if isinstance(content, str):
            if '```' in content or re.search(r'<code>\s*[\s\S]*?\s*</code>', content):
                content_score += 5.0
            if re.search(r'https?://\S+|file:/\S+|/\w+/\S+', content):
                content_score += 2.0
            if '?' in content:
                content_score += 1.5
            length = len(content)
            if 100 <= length <= 1000:
                content_score += 1.0
            elif length > 1000:
                content_score += 0.5
        total_score = base_score + recency_score + content_score
        return total_score

    def calculate_message_importance(self, messages: List[Dict[str, Any]]) -> Dict[int, float]:
        message_importance: Dict[int, float] = {}
        for idx, msg in enumerate(messages):
            content = msg.get('content', '')
            role = msg.get('role', '')
            if isinstance(content, list):
                text_content = ""
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text_content += item.get('text', '')
                content = text_content
            importance = self._calculate_message_importance(content, role, idx, len(messages))
            message_importance[idx] = importance
        return message_importance

    def combine_sliding_windows(self, windows: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if not windows:
            return []
        combined_context: List[Dict[str, Any]] = []
        seen_messages = set()
        for window in reversed(windows):
            for msg in reversed(window):
                msg_content = msg.get('content', '')
                if isinstance(msg_content, list):
                    text_content_inner = ""
                    for item in msg_content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            text_content_inner += item.get('text', '') + " "
                    msg_content = text_content_inner.strip()
                msg_fingerprint = f"{msg.get('role', '')}:{msg_content[:50]}"
                if msg_fingerprint not in seen_messages:
                    combined_context.insert(0, msg)
                    seen_messages.add(msg_fingerprint)
        return combined_context

@dataclass
class RESK_ContextWindowManager:
    model_info: Dict[str, Union[int, str]]
    window_size: int = 10
    max_windows: int = 5
    overlap: int = 2
    windows: List[List[Dict[str, Any]]] = field(default_factory=list)
    history_buffer: List[Dict[str, Any]] = field(default_factory=list)
    message_index: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    next_id: int = 0
    text_cleaner: Any = field(default_factory=RESK_TextCleaner)

    def add_message(self, message: Dict[str, Any]) -> None:
        content = message.get('content', '')
        role = message.get('role', '')
        if isinstance(content, str):
            cleaned_content = self.text_cleaner.clean_text(content)
            cleaned_message = {'role': role, 'content': cleaned_content}
        else:
            cleaned_content_list: List[Any] = []
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text = item.get('text', '')
                    cleaned_text = self.text_cleaner.clean_text(text)
                    cleaned_content_list.append({**item, 'text': cleaned_text})
                else:
                    cleaned_content_list.append(item)
            cleaned_message = {'role': role, 'content': cleaned_content_list}
        self.history_buffer.append(cleaned_message)
        self._update_windows()

    def get_current_context(self, max_messages: Optional[int] = None) -> List[Dict[str, Any]]:
        if not self.windows:
            context = list(self.history_buffer)
            if max_messages:
                return context[-max_messages:]
            return context
        combined_context: List[Dict[str, Any]] = []
        seen_messages = set()
        for window in reversed(self.windows):
            for msg in reversed(window):
                msg_content = msg.get('content', '')
                if isinstance(msg_content, list):
                    text_content_inner = ""
                    for item in msg_content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            text_content_inner += item.get('text', '') + " "
                    msg_content = text_content_inner.strip()
                msg_fingerprint = f"{msg.get('role', '')}:{msg_content[:50]}"
                if msg_fingerprint not in seen_messages:
                    combined_context.insert(0, msg)
                    seen_messages.add(msg_fingerprint)
        if max_messages and len(combined_context) > max_messages:
            return combined_context[-max_messages:]
        return combined_context

    def _update_windows(self) -> None:
        if len(self.history_buffer) < self.window_size:
            self.windows = [list(self.history_buffer)]
            return
        new_window = list(self.history_buffer)[-self.window_size:]
        if not self.windows:
            self.windows.append(new_window)
            return
        last_window = self.windows[-1]
        overlap_detected = False
        for i in range(1, min(self.overlap + 1, len(last_window), len(new_window))):
            if last_window[-i:] == new_window[:i]:
                overlap_detected = True
                break
        if not overlap_detected:
            self.windows.append(new_window)
            if len(self.windows) > self.max_windows:
                self.windows.pop(0)
        else:
            self.windows[-1] = new_window

    def calculate_message_importance(self, messages: List[Dict[str, Any]]) -> Dict[int, float]:
        temp_manager = RESK_MessageBasedContextManager(self.model_info)
        return temp_manager.calculate_message_importance(messages)

    def combine_sliding_windows(self, windows: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        temp_manager = RESK_MessageBasedContextManager(self.model_info)
        return temp_manager.combine_sliding_windows(windows)
