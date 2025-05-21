"""
Embedding utilities that provide alternatives to sentence-transformers without using PyTorch.

This module offers text embedding capabilities using alternatives like:
1. Gensim's Word2Vec, FastText or Doc2Vec
2. Scikit-learn's TF-IDF Vectorizer with dimensionality reduction
"""

import logging
import numpy as np
import hashlib
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
            if 'scipy' in str(e) and 'triu' in str(e):
                logger.error(f"Missing scipy.linalg.triu dependency: {e}. Install scipy with 'pip install scipy>=1.8.0'")
                raise ImportError(f"Missing scipy dependency: {e}")
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
            
            # Initialize vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=10000,  # Limit vocabulary size
                stop_words='english',
                ngram_range=(1, 2)  # Use both unigrams and bigrams
            )
            
            # Try to initialize dimensionality reduction
            try:
                from sklearn.decomposition import PCA, TruncatedSVD
                
                # Initialize dimensionality reduction model
                if self.use_pca:
                    self.dim_reducer = PCA(n_components=self.dimension)
                else:
                    self.dim_reducer = TruncatedSVD(n_components=self.dimension)
            except ImportError as e:
                logger.warning(f"Error importing dimensionality reduction: {e}")
                self.dim_reducer = None
                
            # Flag to check if models are trained
            self.is_trained = False
            
        except ImportError as e:
            logger.error(f"scikit-learn is not installed: {e}")
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
        if self.vectorizer is not None:
            tfidf_matrix = self.vectorizer.fit_transform(texts)
            
            # Fit dimensionality reducer
            if self.dim_reducer is not None:
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
        if self.vectorizer is not None:
            tfidf_vector = self.vectorizer.transform([text])
            
            # Reduce dimensionality
            if self.dim_reducer is not None:
                embedding = self.dim_reducer.transform(tfidf_vector)
                return embedding[0]
                
        # If we get here, something went wrong
        return np.zeros(self.dimension)


class SimpleEmbedder:
    """
    A very lightweight embedder that doesn't require any external models.
    Creates embeddings based on simple word hashing techniques.
    This is mainly for testing or environments where downloading models is not feasible.
    Not recommended for production use.
    """
    
    def __init__(self, dimension: int = 100, seed: int = 42, **kwargs):
        """Initialize the simple embedder.
        
        Args:
            dimension: Dimension of embedding vectors
            seed: Random seed for reproducibility
            **kwargs: Additional arguments that are ignored (for compatibility with other embedders)
        """
        self.dimension = dimension
        self.seed = seed
        self.rng = np.random.RandomState(seed)
        self.word_vectors: Dict[str, np.ndarray] = {}  # Cache for word vectors
        logger.info(f"SimpleEmbedder initialized with dimension {dimension}")
    
    def _hash_word(self, word: str) -> np.ndarray:
        """Create a deterministic vector for a word using its hash."""
        # Use hash of the word as a seed
        word_hash = int(hashlib.md5(word.encode()).hexdigest(), 16) % (2**32)
        word_rng = np.random.RandomState(word_hash + self.seed)
        # Generate a random vector but deterministic for the same word
        return word_rng.randn(self.dimension)
    
    def embed(self, text: str) -> np.ndarray:
        """Create embedding for the given text.
        
        Args:
            text: Input text to embed
            
        Returns:
            Numpy array of embedding with shape (dimension,)
        """
        if not text or not isinstance(text, str):
            # Return zero vector for empty input
            return np.zeros(self.dimension)
        
        # Simple preprocessing
        words = text.lower().split()
        
        if not words:
            return np.zeros(self.dimension)
        
        # Get or compute vectors for each word
        word_vectors = []
        for word in words:
            if word not in self.word_vectors:
                self.word_vectors[word] = self._hash_word(word)
            word_vectors.append(self.word_vectors[word])
        
        # Average the word vectors
        embedding = np.mean(word_vectors, axis=0)
        
        # Normalize to unit length
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
            
        return embedding
    
    def train(self, corpus: List[str]) -> None:
        """Pretend to train on a corpus (for API compatibility with other embedders).
        
        For SimpleEmbedder, this just pre-computes vectors for words in the corpus.
        
        Args:
            corpus: List of text documents
        """
        # Pre-compute word vectors for all words in the corpus
        all_words = set()
        for doc in corpus:
            all_words.update(doc.lower().split())
        
        for word in all_words:
            if word not in self.word_vectors:
                self.word_vectors[word] = self._hash_word(word)
        
        logger.info(f"SimpleEmbedder pre-computed vectors for {len(all_words)} words")


def create_embedder(embedder_type: str = "simple", **kwargs) -> Any:
    """Create an embedder based on the specified type.
    
    Args:
        embedder_type: Type of embedder to create ('gensim', 'sklearn', or 'simple')
        **kwargs: Additional arguments to pass to the embedder constructor
    
    Returns:
        An embedder instance
    
    Raises:
        ValueError: If an unsupported embedder_type is specified
    """
    if embedder_type == "gensim":
        try:
            return GensimEmbedder(**kwargs)
        except ImportError:
            logger.warning("Gensim is not installed, falling back to SimpleEmbedder")
            return SimpleEmbedder(**kwargs)
    elif embedder_type == "sklearn":
        try:
            return SklearnEmbedder(**kwargs)
        except ImportError:
            logger.warning("scikit-learn is not installed, falling back to SimpleEmbedder")
            return SimpleEmbedder(**kwargs)
    elif embedder_type == "simple":
        return SimpleEmbedder(**kwargs)
    else:
        raise ValueError(f"Unsupported embedder type: {embedder_type}. "
                         f"Supported types are: 'gensim', 'sklearn', 'simple'") 