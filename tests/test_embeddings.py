"""
Test module for embedding utilities without torch dependency.

This test suite verifies that the alternative embedding options (Gensim, scikit-learn)
work correctly without requiring PyTorch.
"""

import pytest
import numpy as np
from resk_llm.embedding_utils import create_embedder, GensimEmbedder, SklearnEmbedder, SimpleEmbedder

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
    
    def test_gensim_embedder_creation(self):
        """Test that GensimEmbedder can be created."""
        try:
            # Try to import scipy.linalg.triu first to check for the specific import error
            try:
                from scipy.linalg import triu
            except ImportError:
                pytest.skip("scipy.linalg.triu not available, skipping GensimEmbedder test")
                
            embedder = GensimEmbedder(model_type="word2vec")
            assert embedder is not None
            assert embedder.dimension == 300  # Default dimension
        except Exception as e:
            pytest.fail(f"Failed to create GensimEmbedder: {e}")
    
    def test_create_embedder_gensim(self):
        """Test create_embedder factory function with gensim."""
        try:
            embedder = create_embedder(embedder_type="gensim", model_type="word2vec")
            assert embedder is not None
            # The embedder could be either GensimEmbedder or SimpleEmbedder (fallback)
            assert isinstance(embedder, (GensimEmbedder, SimpleEmbedder))
        except Exception as e:
            pytest.fail(f"Failed to create embedder via factory function: {e}")
    
    def test_gensim_embedding_shape(self):
        """Test that GensimEmbedder produces correct shape embeddings."""
        embedder = create_embedder(embedder_type="gensim", model_type="word2vec")
        text = "This is a test sentence for embedding"
        embedding = embedder.embed(text)
        
        # Verify embedding is a numpy array with correct shape (could be 300 for gensim or 100 for SimpleEmbedder)
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape[0] in (100, 300)
        
        # Verify embedding is not all zeros or all the same value
        assert not np.all(embedding == 0)
        assert np.std(embedding) > 0.01  # Should have some variance
    
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
            assert isinstance(embedder, SklearnEmbedder)
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
    
    def test_vector_db_with_gensim_embeddings(self, vector_db_class):
        """Test that VectorDatabase works with Gensim embeddings."""
        if vector_db_class is None:
            pytest.skip("VectorDatabase not available")
            
        # Create embedder
        embedder = create_embedder(embedder_type="gensim", model_type="word2vec")
        
        # Get embedding dimension
        sample_embedding = embedder.embed("test")
        embedding_dim = sample_embedding.shape[0]  # Either 100 or 300
        
        # Create vector database
        db = vector_db_class(embedding_dim=embedding_dim, similarity_threshold=0.8)
        
        # Add entries
        texts = [
            "This is a test document",
            "Here is another document", 
            "This document is completely different",
            "This one is similar to the first document"
        ]
        
        # Add embeddings to database
        for i, text in enumerate(texts):
            embedding = embedder.embed(text)
            db.add_entry(embedding=embedding, metadata={"id": i, "text": text})
        
        # Test similarity search
        query = "This is a test"
        query_embedding = embedder.embed(query)
        
        result = db.detect(query_embedding)
        
        # Should detect similarity with the first document
        assert result["detected"] == True
        assert len(result["similar_entries"]) > 0
        
        # The most similar entry should be the first text
        most_similar = result["similar_entries"][0]
        assert most_similar["metadata"]["text"] == texts[0]
        
        # Check that similarity score is in the expected range [0,1]
        assert 0 <= most_similar["similarity"] <= 1
    
    def test_multiple_gensim_models(self):
        """Test different Gensim model types."""
        model_types = ["word2vec", "fasttext", "glove"]
        
        for model_type in model_types:
            try:
                embedder = create_embedder(embedder_type="gensim", model_type=model_type)
                text = "Testing different model types"
                embedding = embedder.embed(text)
                
                assert isinstance(embedding, np.ndarray)
                # Check for shape - could be 300 (gensim) or 100 (SimpleEmbedder fallback)
                assert embedding.shape[0] in (100, 300)
            except Exception as e:
                pytest.fail(f"Failed with model type {model_type}: {e}")

if __name__ == "__main__":
    pytest.main(["-xvs", __file__]) 