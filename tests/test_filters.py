"""
Tests for RESK-LLM filters.
"""

import pytest
from unittest.mock import Mock, patch

from resk_llm.filters.resk_heuristic_filter import RESK_HeuristicFilter
from resk_llm.filters.resk_content_policy_filter import RESK_ContentPolicyFilter
from resk_llm.filters.resk_word_list_filter import RESK_WordListFilter


class TestRESKHeuristicFilter:
    """Test the RESK_HeuristicFilter class."""
    
    def test_heuristic_filter_initialization(self):
        """Test heuristic filter initialization."""
        filter_obj = RESK_HeuristicFilter()
        assert filter_obj is not None
        assert filter_obj.enabled is True
    
    def test_heuristic_filter_safe_text(self, safe_text):
        """Test heuristic filter with safe text."""
        filter_obj = RESK_HeuristicFilter()
        result = filter_obj.process(safe_text)
        
        assert result.is_safe is True
        assert result.confidence > 0.5
    
    def test_heuristic_filter_malicious_text(self, malicious_text):
        """Test heuristic filter with malicious text."""
        filter_obj = RESK_HeuristicFilter()
        result = filter_obj.process(malicious_text)
        
        assert result.is_safe is False
        assert result.confidence > 0.5
    
    def test_heuristic_filter_pii_text(self, pii_text):
        """Test heuristic filter with PII text."""
        filter_obj = RESK_HeuristicFilter()
        result = filter_obj.process(pii_text)
        
        assert result.is_safe is False
        assert result.confidence > 0.5
    
    def test_heuristic_filter_toxic_text(self, toxic_text):
        """Test heuristic filter with toxic text."""
        filter_obj = RESK_HeuristicFilter()
        result = filter_obj.process(toxic_text)
        
        assert result.is_safe is False
        assert result.confidence > 0.5
    
    def test_heuristic_filter_disable(self):
        """Test disabling heuristic filter."""
        filter_obj = RESK_HeuristicFilter()
        filter_obj.disable()
        
        result = filter_obj.process("malicious text")
        assert result.is_safe is True  # Should allow everything when disabled
    
    def test_heuristic_filter_custom_threshold(self):
        """Test heuristic filter with custom threshold."""
        filter_obj = RESK_HeuristicFilter(threshold=0.9)  # Very strict
        result = filter_obj.process("slightly suspicious text")
        
        # Should be more lenient with higher threshold
        assert isinstance(result.is_safe, bool)
        assert isinstance(result.confidence, float)


class TestRESKContentPolicyFilter:
    """Test the RESK_ContentPolicyFilter class."""
    
    def test_content_policy_filter_initialization(self):
        """Test content policy filter initialization."""
        filter_obj = RESK_ContentPolicyFilter()
        assert filter_obj is not None
        assert filter_obj.enabled is True
    
    def test_content_policy_filter_safe_content(self, safe_text):
        """Test content policy filter with safe content."""
        filter_obj = RESK_ContentPolicyFilter()
        result = filter_obj.process(safe_text)
        
        assert result.is_safe is True
        assert result.violations == []
    
    def test_content_policy_filter_violations(self, toxic_text):
        """Test content policy filter with policy violations."""
        filter_obj = RESK_ContentPolicyFilter()
        result = filter_obj.process(toxic_text)
        
        assert result.is_safe is False
        assert len(result.violations) > 0
    
    def test_content_policy_filter_custom_policies(self):
        """Test content policy filter with custom policies."""
        custom_policies = {
            "no_numbers": r"\d+",
            "no_uppercase": r"[A-Z]"
        }
        
        filter_obj = RESK_ContentPolicyFilter(policies=custom_policies)
        
        # Test with policy violation
        result = filter_obj.process("Text with 123 and UPPERCASE")
        assert result.is_safe is False
        assert len(result.violations) >= 2
    
    def test_content_policy_filter_no_violations(self):
        """Test content policy filter with no violations."""
        custom_policies = {
            "no_numbers": r"\d+",
            "no_uppercase": r"[A-Z]"
        }
        
        filter_obj = RESK_ContentPolicyFilter(policies=custom_policies)
        
        # Test with compliant text
        result = filter_obj.process("text without numbers or uppercase")
        assert result.is_safe is True
        assert result.violations == []


class TestRESKWordListFilter:
    """Test the RESK_WordListFilter class."""
    
    def test_word_list_filter_initialization(self):
        """Test word list filter initialization."""
        filter_obj = RESK_WordListFilter()
        assert filter_obj is not None
        assert filter_obj.enabled is True
    
    def test_word_list_filter_safe_text(self, safe_text):
        """Test word list filter with safe text."""
        filter_obj = RESK_WordListFilter()
        result = filter_obj.process(safe_text)
        
        assert result.is_safe is True
        assert result.matched_words == []
    
    def test_word_list_filter_prohibited_words(self, sample_word_lists):
        """Test word list filter with prohibited words."""
        filter_obj = RESK_WordListFilter(
            word_lists={"prohibited": sample_word_lists["prohibited"]}
        )
        
        result = filter_obj.process("This text contains hack and exploit")
        assert result.is_safe is False
        assert len(result.matched_words) >= 2
    
    def test_word_list_filter_sensitive_words(self, sample_word_lists):
        """Test word list filter with sensitive words."""
        filter_obj = RESK_WordListFilter(
            word_lists={"sensitive": sample_word_lists["sensitive"]}
        )
        
        result = filter_obj.process("This contains password and secret information")
        assert result.is_safe is False
        assert len(result.matched_words) >= 2
    
    def test_word_list_filter_case_insensitive(self, sample_word_lists):
        """Test word list filter case insensitivity."""
        filter_obj = RESK_WordListFilter(
            word_lists={"prohibited": ["hack"]},
            case_sensitive=False
        )
        
        result = filter_obj.process("This contains HACK and Hack")
        assert result.is_safe is False
        assert len(result.matched_words) >= 2
    
    def test_word_list_filter_case_sensitive(self, sample_word_lists):
        """Test word list filter case sensitivity."""
        filter_obj = RESK_WordListFilter(
            word_lists={"prohibited": ["hack"]},
            case_sensitive=True
        )
        
        result = filter_obj.process("This contains HACK and hack")
        assert result.is_safe is False
        assert len(result.matched_words) == 1  # Only "hack" should match
    
    def test_word_list_filter_multiple_lists(self, sample_word_lists):
        """Test word list filter with multiple word lists."""
        filter_obj = RESK_WordListFilter(word_lists=sample_word_lists)
        
        result = filter_obj.process("This contains hack, password, and hate")
        assert result.is_safe is False
        assert len(result.matched_words) >= 3
    
    def test_word_list_filter_add_words(self):
        """Test adding words to word list filter."""
        filter_obj = RESK_WordListFilter()
        filter_obj.add_words("custom", ["test_word"])
        
        result = filter_obj.process("This contains test_word")
        assert result.is_safe is False
        assert "test_word" in result.matched_words
    
    def test_word_list_filter_remove_words(self):
        """Test removing words from word list filter."""
        filter_obj = RESK_WordListFilter(
            word_lists={"test": ["word1", "word2"]}
        )
        filter_obj.remove_words("test", ["word1"])
        
        result = filter_obj.process("This contains word1 and word2")
        assert result.is_safe is False
        assert "word2" in result.matched_words
        assert "word1" not in result.matched_words


class TestFilterIntegration:
    """Test integration between different filters."""
    
    def test_multiple_filters_safe_text(self, safe_text):
        """Test multiple filters with safe text."""
        heuristic_filter = RESK_HeuristicFilter()
        content_filter = RESK_ContentPolicyFilter()
        word_filter = RESK_WordListFilter()
        
        # All filters should pass safe text
        h_result = heuristic_filter.process(safe_text)
        c_result = content_filter.process(safe_text)
        w_result = word_filter.process(safe_text)
        
        assert h_result.is_safe is True
        assert c_result.is_safe is True
        assert w_result.is_safe is True
    
    def test_multiple_filters_malicious_text(self, malicious_text):
        """Test multiple filters with malicious text."""
        heuristic_filter = RESK_HeuristicFilter()
        content_filter = RESK_ContentPolicyFilter()
        word_filter = RESK_WordListFilter()
        
        # At least heuristic filter should catch malicious text
        h_result = heuristic_filter.process(malicious_text)
        c_result = content_filter.process(malicious_text)
        w_result = word_filter.process(malicious_text)
        
        # At least one should catch it
        caught = not h_result.is_safe or not c_result.is_safe or not w_result.is_safe
        assert caught is True
    
    def test_filter_chain_processing(self, malicious_text):
        """Test processing through a chain of filters."""
        filters = [
            RESK_HeuristicFilter(),
            RESK_ContentPolicyFilter(),
            RESK_WordListFilter()
        ]
        
        # Process through all filters
        current_text = malicious_text
        for filter_obj in filters:
            result = filter_obj.process(current_text)
            if not result.is_safe:
                break  # Stop if any filter catches it
        
        # Should be caught by at least one filter
        assert result.is_safe is False 