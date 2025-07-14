"""
Test module for embedding utilities without torch dependency.

This test suite verifies that the alternative embedding options (scikit-learn)
work correctly without requiring PyTorch.
"""

import pytest
import numpy as np
from resk_llm.embedding_utils import create_embedder

class TestEmbeddings:
    """Test cases for embedding utilities."""
    
    @pytest.fixture(scope="class")
    def vector_db_class(self):
        """Try to import VectorDatabase or skip tests that need it."""
        try:
            from resk_llm.vector_db import VectorDatabase
            return VectorDatabase
        except ImportError:
            pytest.skip("VectorDatabase not available")
            return None
    
    def test_sklearn_embedder_creation(self):
        """Test that SklearnEmbedder can be created and trained."""
        try:
            # Create a small corpus for training
            corpus = [
                "This is the first document",
                "This document is the second document",
                "And this is the third one",
                "Is this the first document?",
                "This is the fifth document in the corpus",
                "The sixth document has some new words",
                "Adding the seventh document with more text",
                "The eighth document has different vocabulary",
                "The ninth document adds more text for better dimensionality reduction",
                "The tenth document helps to have enough features for reduction"
            ]
            
            embedder = create_embedder(
                embedder_type="sklearn",
                dimension=3,  # Use a very small dimension for testing
                use_pca=False  # Use TruncatedSVD instead of PCA
            )
            
            # Train on corpus
            embedder.train(corpus)
            assert embedder is not None
            # No isinstance check for SklearnEmbedder
        except Exception as e:
            pytest.fail(f"Failed to create and train SklearnEmbedder: {e}")
    
    def test_sklearn_embedding_shape(self):
        """Test that SklearnEmbedder produces correct shape embeddings."""
        # Create and train embedder
        corpus = [
            "This is the first document",
            "This document is the second document",
            "And this is the third one", 
            "Is this the first document?",
            "This is the fifth document in the corpus",
            "The sixth document has some new words",
            "Adding the seventh document with more text",
            "The eighth document has different vocabulary",
            "The ninth document adds more text for better dimensionality reduction",
            "The tenth document helps to have enough features for reduction"
        ]
        
        dimension = 3  # Use a very small dimension for testing
        embedder = create_embedder(
            embedder_type="sklearn",
            dimension=dimension,
            use_pca=False  # Use TruncatedSVD instead of PCA
        )
        
        embedder.train(corpus)
        
        # Generate embedding
        text = "This is a new document for embedding"
        embedding = embedder.embed(text)
        
        # Verify embedding shape
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (dimension,)
        
        # Verify embedding is not all zeros or all the same value
        assert not np.all(embedding == 0)
        assert np.std(embedding) > 0.0001  # Lower threshold for small embeddings
    
    # Les tests liés à Gensim ont été supprimés.

if __name__ == "__main__":
    pytest.main(["-xvs", __file__]) 