class ContextManager:
    def __init__(self, model_info, preserved_prompts=2, reserved_tokens=1000):
        self.max_context_length = model_info["context_window"]
        self.preserved_prompts = preserved_prompts
        self.reserved_tokens = reserved_tokens

    def clean_message(self, message):
        return ' '.join(message.split())  # Supprime les espaces multiples, tabulations et sauts de ligne

    def truncate_message(self, message, available_tokens):
        words = message.split()
        return ' '.join(words[:available_tokens])

    def manage_sliding_context(self, messages):
        cleaned_messages = [{'role': msg['role'], 'content': self.clean_message(msg['content'])} for msg in messages]
        total_tokens = sum(len(msg['content'].split()) for msg in cleaned_messages)
        
        if total_tokens <= self.max_context_length:
            return cleaned_messages

        preserved_messages = cleaned_messages[:self.preserved_prompts]
        remaining_messages = cleaned_messages[self.preserved_prompts:]

        available_tokens = self.max_context_length - self.reserved_tokens
        preserved_tokens = sum(len(msg['content'].split()) for msg in preserved_messages)
        available_tokens -= preserved_tokens

        while remaining_messages and available_tokens > 0:
            message = remaining_messages.pop(0)
            message_tokens = len(message['content'].split())
            
            if message_tokens > available_tokens:
                truncated_content = self.truncate_message(message['content'], available_tokens)
                preserved_messages.append({'role': message['role'], 'content': truncated_content})
                break
            else:
                preserved_messages.append(message)
                available_tokens -= message_tokens

        return preserved_messages
