import unittest
from unittest.mock import patch, MagicMock
from resk_llm.openai_protector import OpenAIProtector, TokenBasedContextManager, MessageBasedContextManager

class TestOpenAIProtector(unittest.TestCase):

    def setUp(self):
        self.protector = OpenAIProtector(model="gpt-4o", context_manager=TokenBasedContextManager({"context_window": 4096}, preserved_prompts=2))

    def test_sanitize_input(self):
        input_text = "<script>alert('XSS')</script>Hello<|endoftext|>"
        sanitized = self.protector.sanitize_input(input_text)
        self.assertEqual(sanitized, "&lt;script&gt;alert('XSS')&lt;/script&gt;Hello")

    def test_close_html_tags(self):
        input_text = "<p>Unclosed paragraph<div>Nested <b>bold"
        closed = self.protector.context_manager._close_html_tags(input_text)
        self.assertEqual(closed, "<p>Unclosed paragraph<div>Nested <b>bold</b></div></p>")

    def test_truncate_text(self):
        long_text = "a" * (self.protector.context_manager.max_context_length * 5)
        truncated = self.protector.context_manager.text_cleaner.truncate_text(long_text, self.protector.context_manager.max_context_length)
        self.assertEqual(len(truncated), self.protector.context_manager.max_context_length)

    def test_manage_sliding_context_token_based(self):
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"},
            {"role": "user", "content": "How are you?"},
            {"role": "assistant", "content": "I'm doing well, thank you for asking!"},
        ]
        managed = self.protector.context_manager.manage_sliding_context(messages)
        
        self.assertEqual(managed[:self.protector.context_manager.preserved_prompts], messages[:self.protector.context_manager.preserved_prompts])
        
        total_tokens = sum(len(msg['content'].split()) for msg in managed)
        self.assertLessEqual(total_tokens, self.protector.context_manager.max_context_length - self.protector.context_manager.reserved_tokens)
        
        self.assertIn(messages[-1], managed)
        self.assertIn(messages[-2], managed)

    def test_manage_sliding_context_message_based(self):
        message_based_manager = MessageBasedContextManager({"context_window": 4096}, preserved_prompts=2, max_messages=3)
        protector = OpenAIProtector(model="gpt-4o", context_manager=message_based_manager)
        
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "system", "content": "You are also very knowledgeable."},
            {"role": "user", "content": "Message 1"},
            {"role": "assistant", "content": "Response 1"},
            {"role": "user", "content": "Message 2"},
            {"role": "assistant", "content": "Response 2"},
            {"role": "user", "content": "Message 3"},
            {"role": "assistant", "content": "Response 3"},
        ]
        managed = protector.context_manager.manage_sliding_context(messages)

        
        self.assertEqual(len(managed), 5)  # 2 preserved + 3 context
        self.assertEqual(managed[0], messages[0])  # First system message preserved
        self.assertEqual(managed[1], messages[1])  # Second system message preserved
        self.assertEqual(managed[2], messages[-3])  # Third-to-last message
        self.assertEqual(managed[3], messages[-2])  # Second-to-last message
        self.assertEqual(managed[4], messages[-1])  # Last message

    @patch('openai.ChatCompletion.create')
    def test_protect_openai_call(self, mock_create):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message={"content": "Test response"})]
        mock_create.return_value = mock_response

        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello<s>"},
        ]

        response = self.protector.protect_openai_call(
            mock_create,
            model="gpt-4o",
            messages=messages
        )

        self.assertEqual(response.choices[0].message["content"], "Test response")
        mock_create.assert_called_once()
        called_args = mock_create.call_args[1]
        self.assertEqual(called_args['model'], "gpt-4o-2024-05-13")  # Le nom du modèle est modifié dans le protecteur
        self.assertEqual(len(called_args['messages']), 2)
        #self.assertNotIn("<s>", called_args['messages'][1]['content'])

    def test_clean_message(self):
        input_text = "Hello   world\n\nHow   are\tyou?"
        cleaned = self.protector.context_manager.clean_message(input_text)
        self.assertEqual(cleaned, "Hello world How are you?")

    def test_update_special_tokens(self):
        new_tokens = {"test": ["<test>", "</test>"]}
        OpenAIProtector.update_special_tokens(new_tokens)
        self.assertEqual(OpenAIProtector.get_special_tokens(), new_tokens)

    def test_update_control_chars(self):
        new_chars = {'\r': '\\r', '\n': '\\n'}
        OpenAIProtector.update_control_chars(new_chars)
        self.assertEqual(OpenAIProtector.get_control_chars(), new_chars)

if __name__ == '__main__':
    unittest.main()