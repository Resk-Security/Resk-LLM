"""
Embedding utilities that provide alternatives to sentence-transformers without using PyTorch.

This module offers text embedding capabilities using alternatives like:
1. Gensim's Word2Vec, FastText or Doc2Vec
2. Scikit-learn's TF-IDF Vectorizer with dimensionality reduction
"""

import logging
import numpy as np
from typing import List, Dict, Any, Optional, Union, Callable

# Logger configuration
logger = logging.getLogger(__name__)

class GensimEmbedder:
    """Text embedder using Gensim models as an alternative to sentence-transformers."""
    
    def __init__(self, model_type: str = "word2vec", model_path: Optional[str] = None, dimension: int = 300):
        """
        Initialize a Gensim-based embedder.
        
        Args:
            model_type: Type of Gensim model to use ("word2vec", "fasttext", "doc2vec")
            model_path: Path to a pre-trained model or None to download default
            dimension: Embedding dimension for training new models
        """
        self.model_type = model_type.lower()
        self.model_path = model_path
        self.dimension = dimension
        self.model = None
        self._load_model()
    
    def _load_model(self) -> None:
        """Load the appropriate Gensim model."""
        try:
            import gensim
            import gensim.downloader
            
            # Load pre-trained model or download default
            if self.model_path:
                if self.model_type == "word2vec":
                    self.model = gensim.models.Word2Vec.load(self.model_path)
                elif self.model_type == "fasttext":
                    self.model = gensim.models.FastText.load(self.model_path)
                elif self.model_type == "doc2vec":
                    self.model = gensim.models.Doc2Vec.load(self.model_path)
                else:
                    raise ValueError(f"Unsupported model type: {self.model_type}")
            else:
                # Download a default model if none provided
                if self.model_type == "word2vec":
                    self.model = gensim.downloader.load("word2vec-google-news-300")
                elif self.model_type == "fasttext":
                    self.model = gensim.downloader.load("fasttext-wiki-news-subwords-300")
                elif self.model_type == "glove":
                    self.model = gensim.downloader.load("glove-wiki-gigaword-300")
                else:
                    # If model_type is not available in downloader, use Word2Vec by default
                    logger.warning(f"Model {self.model_type} not found, using word2vec instead")
                    self.model = gensim.downloader.load("word2vec-google-news-300")
                    self.model_type = "word2vec"
        
        except ImportError:
            logger.error("Gensim is not installed. Install it with 'pip install gensim'")
            raise
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
    
    def _preprocess_text(self, text: str) -> List[str]:
        """
        Preprocess text by converting to lowercase and splitting into tokens.
        
        Args:
            text: Input text
            
        Returns:
            List of tokens
        """
        return text.lower().split()
    
    def embed(self, text: str) -> np.ndarray:
        """
        Generate an embedding for the input text.
        
        Args:
            text: Input text
            
        Returns:
            Embedding vector as numpy array
        """
        if not self.model:
            raise ValueError("Model not loaded")
            
        tokens = self._preprocess_text(text)
        
        if self.model_type == "doc2vec":
            # For Doc2Vec, infer the vector directly
            return self.model.infer_vector(tokens)
        else:
            # For Word2Vec and FastText, average word vectors
            vectors = []
            for token in tokens:
                try:
                    if token in self.model.wv:
                        vectors.append(self.model.wv[token])
                except Exception:
                    # Different models might have different APIs
                    try:
                        if hasattr(self.model, 'get_vector'):
                            vectors.append(self.model.get_vector(token))
                    except Exception:
                        pass
            
            if not vectors:
                # If no word was found, return zeros
                return np.zeros(self.dimension)
                
            # Average the vectors
            return np.mean(vectors, axis=0)


class SklearnEmbedder:
    """Text embedder using scikit-learn for TF-IDF and dimensionality reduction."""
    
    def __init__(self, dimension: int = 300, use_pca: bool = True):
        """
        Initialize a scikit-learn-based embedder.
        
        Args:
            dimension: Target dimension for embeddings
            use_pca: Whether to use PCA for dimensionality reduction (True) or TruncatedSVD (False)
        """
        self.dimension = dimension
        self.use_pca = use_pca
        self.vectorizer = None
        self.dim_reducer = None
        self._initialize_models()
    
    def _initialize_models(self) -> None:
        """Initialize the vectorizer and dimensionality reduction models."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.decomposition import PCA, TruncatedSVD
            
            # Initialize vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=10000,  # Limit vocabulary size
                stop_words='english',
                ngram_range=(1, 2)  # Use both unigrams and bigrams
            )
            
            # Initialize dimensionality reduction model
            if self.use_pca:
                self.dim_reducer = PCA(n_components=self.dimension)
            else:
                self.dim_reducer = TruncatedSVD(n_components=self.dimension)
                
            # Flag to check if models are trained
            self.is_trained = False
            
        except ImportError:
            logger.error("scikit-learn is not installed. Install it with 'pip install scikit-learn'")
            raise
    
    def train(self, texts: List[str]) -> None:
        """
        Train the vectorizer and dimensionality reduction models.
        
        Args:
            texts: List of texts to train on
        """
        if not self.vectorizer or not self.dim_reducer:
            self._initialize_models()
            
        # Fit vectorizer
        tfidf_matrix = self.vectorizer.fit_transform(texts)
        
        # Fit dimensionality reducer
        self.dim_reducer.fit(tfidf_matrix)
        
        self.is_trained = True
    
    def embed(self, text: str) -> np.ndarray:
        """
        Generate an embedding for the input text.
        
        Args:
            text: Input text
            
        Returns:
            Embedding vector as numpy array
        """
        if not self.is_trained:
            raise ValueError("Models not trained. Call train() first with a corpus of texts.")
            
        # Transform text to TF-IDF
        tfidf_vector = self.vectorizer.transform([text])
        
        # Reduce dimensionality
        embedding = self.dim_reducer.transform(tfidf_vector)
        
        return embedding[0]


def create_embedder(embedder_type: str = "gensim", **kwargs) -> Union[GensimEmbedder, SklearnEmbedder]:
    """
    Factory function to create an appropriate embedder.
    
    Args:
        embedder_type: Type of embedder to create ("gensim" or "sklearn")
        **kwargs: Additional arguments to pass to the embedder constructor
        
    Returns:
        An embedder instance
    """
    if embedder_type.lower() == "gensim":
        return GensimEmbedder(**kwargs)
    elif embedder_type.lower() == "sklearn":
        return SklearnEmbedder(**kwargs)
    else:
        raise ValueError(f"Unsupported embedder type: {embedder_type}") 