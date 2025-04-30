import logging
import numpy as np
from typing import List, Dict, Optional, Tuple, Any, Union, TypeVar, cast, Collection
import os
import json
import time
from datetime import datetime

from resk_llm.core.abc import DetectorBase

# Type definitions
VectorDBConfig = Dict[str, Any]

class VectorDatabase(DetectorBase[np.ndarray, VectorDBConfig]):
    """
    A vector database for storing and comparing embeddings of prompt injection attacks.
    
    Supports both in-memory storage and optional integration with external vector databases.
    This class provides methods for adding, searching, and comparing embeddings with
    efficient similarity calculations.
    
    Implements DetectorBase for detecting similarity to known attack patterns.
    """
    
    def __init__(self, embedding_dim: int = 1536, similarity_threshold: float = 0.85, config: Optional[VectorDBConfig] = None):
        """
        Initialize the vector database.
        
        Args:
            embedding_dim: Dimension of the embeddings to store
            similarity_threshold: Threshold above which two embeddings are considered similar
            config: Additional configuration parameters
        """
        merged_config: VectorDBConfig = config or {}
        if 'embedding_dim' not in merged_config:
            merged_config['embedding_dim'] = embedding_dim
        if 'similarity_threshold' not in merged_config:
            merged_config['similarity_threshold'] = similarity_threshold
            
        super().__init__(merged_config)
        
        self.embedding_dim = self.config['embedding_dim']
        self.similarity_threshold = self.config['similarity_threshold']
        self.logger = logging.getLogger(__name__)
        
        # In-memory storage
        self.embeddings: List[np.ndarray] = []  # List of numpy arrays
        self.metadata: List[Dict[str, Any]] = []  # List of dictionaries with metadata
        
        # External DB connector (initialized as None, set up with connect_external_db)
        self.external_db: Any = None
        self.external_db_type: Optional[str] = None
        self.external_db_client: Any = None  # For some DBs that need separate client and collection
        
        # Processing flags
        self.normalize_vectors: bool = False  # Set to True for cosine similarity in some backends
        
        # Counters for statistics
        self.total_queries = 0
        self.total_matches = 0
        self.creation_time = datetime.now()
    
    def _validate_config(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if 'embedding_dim' in self.config and not isinstance(self.config['embedding_dim'], int):
            raise ValueError("embedding_dim must be an integer")
            
        if 'similarity_threshold' in self.config and not isinstance(self.config['similarity_threshold'], float):
            raise ValueError("similarity_threshold must be a float")
    
    def update_config(self, config: VectorDBConfig) -> None:
        """
        Update the configuration with new values.
        
        Args:
            config: New configuration values
        """
        self.config.update(config)
        self._validate_config()
        
        # Update instance attributes
        if 'embedding_dim' in config:
            self.embedding_dim = config['embedding_dim']
        
        if 'similarity_threshold' in config:
            self.similarity_threshold = config['similarity_threshold']

    def detect(self, data: np.ndarray) -> Dict[str, Any]:
        """
        Detect if the provided embedding is similar to any known attacks.
        
        Args:
            data: The embedding to check, as a numpy array
            
        Returns:
            A dictionary containing detection results:
            - detected: True if similarity exceeds threshold, False otherwise
            - max_similarity: The highest similarity score found
            - similar_entries: List of entries with similarity scores above threshold
            - threshold: The similarity threshold used for detection
        """
        self.total_queries += 1
        
        # Search for similar vectors
        similar_entries = self.search_similar(data, top_k=3)
        
        # Check if any similarity exceeds the threshold
        detected = False
        max_similarity = 0.0
        
        if similar_entries:
            max_similarity = max(entry.get('similarity', 0.0) for entry in similar_entries)
            detected = max_similarity >= self.similarity_threshold
            
            if detected:
                self.total_matches += 1
                self.logger.info(f"Detected similarity to known pattern: {max_similarity:.3f}")
        
        return {
            'detected': detected,
            'max_similarity': max_similarity,
            'similar_entries': similar_entries,
            'threshold': self.similarity_threshold
        }
        
    def connect_external_db(self, db_type: str, **connection_params) -> bool:
        """
        Connect to an external vector database.
        
        Args:
            db_type: Type of database ('faiss', 'pinecone', 'milvus', 'qdrant', 'weaviate', 'chromadb', etc.)
            connection_params: Parameters specific to the database connection
            
        Returns:
            bool: True if connection was successful, False otherwise
        """
        try:
            # FAISS (local, file-based)
            if db_type.lower() == 'faiss':
                try:
                    import faiss  # type: ignore [import-not-found]
                    
                    # For FAISS, we need to create an index
                    if 'index_type' in connection_params:
                        index_type = connection_params['index_type']
                    else:
                        # Default to L2 distance
                        index_type = 'L2'
                    
                    if index_type == 'L2':
                        self.external_db = faiss.IndexFlatL2(self.embedding_dim)
                    elif index_type == 'IP':  # Inner Product
                        self.external_db = faiss.IndexFlatIP(self.embedding_dim)
                    elif index_type == 'Cosine':
                        # For cosine similarity, we need normalized vectors
                        self.external_db = faiss.IndexFlatIP(self.embedding_dim)
                        # Set flag to normalize vectors before adding/searching
                        self.normalize_vectors = True
                    else:
                        self.logger.error(f"Unsupported FAISS index type: {index_type}")
                        return False
                    
                    self.external_db_type = 'faiss'
                    self.logger.info(f"Connected to FAISS with index type: {index_type}")
                    return True
                    
                except ImportError:
                    self.logger.error("Failed to import FAISS. Please install it with 'pip install faiss-cpu' or 'pip install faiss-gpu'")
                    return False
            
            # Pinecone (cloud-based)
            elif db_type.lower() == 'pinecone':
                try:
                    import pinecone  # type: ignore [import-untyped]
                    
                    # For Pinecone, we need API key and environment
                    if 'api_key' not in connection_params or 'environment' not in connection_params or 'index_name' not in connection_params:
                        self.logger.error("Missing required Pinecone connection parameters: api_key, environment, index_name")
                        return False
                    
                    api_key = connection_params['api_key']
                    environment = connection_params['environment']
                    index_name = connection_params['index_name']
                    
                    # Initialize Pinecone
                    pinecone.init(api_key=api_key, environment=environment)
                    
                    # Check if index exists, create it if not
                    if index_name not in pinecone.list_indexes():
                        pinecone.create_index(
                            name=index_name,
                            dimension=self.embedding_dim,
                            metric='cosine'  # Default to cosine similarity
                        )
                    
                    # Connect to the index
                    self.external_db = pinecone.Index(index_name)
                    self.external_db_type = 'pinecone'
                    self.logger.info(f"Connected to Pinecone index: {index_name}")
                    return True
                    
                except ImportError:
                    self.logger.error("Failed to import Pinecone. Please install it with 'pip install pinecone-client'")
                    return False
            
            # Milvus (self-hosted or cloud)
            elif db_type.lower() == 'milvus':
                try:
                    from pymilvus import connections, Collection, utility  # type: ignore [import-untyped]
                    
                    # For Milvus, we need host, port, and collection name
                    if 'host' not in connection_params or 'port' not in connection_params or 'collection_name' not in connection_params:
                        self.logger.error("Missing required Milvus connection parameters: host, port, collection_name")
                        return False
                    
                    host = connection_params['host']
                    port = connection_params['port']
                    collection_name = connection_params['collection_name']
                    
                    # Connect to Milvus
                    connections.connect(alias="default", host=host, port=port)
                    
                    # Check if collection exists
                    if utility.has_collection(collection_name):
                        collection = Collection(name=collection_name)
                        collection.load()
                        self.external_db = collection
                    else:
                        self.logger.error(f"Milvus collection {collection_name} does not exist. Please create it first.")
                        return False
                    
                    self.external_db_type = 'milvus'
                    self.logger.info(f"Connected to Milvus collection: {collection_name}")
                    return True
                    
                except ImportError:
                    self.logger.error("Failed to import PyMilvus. Please install it with 'pip install pymilvus'")
                    return False
            
            # Qdrant (self-hosted or cloud)
            elif db_type.lower() == 'qdrant':
                try:
                    from qdrant_client import QdrantClient
                    from qdrant_client.models import Distance, VectorParams
                    
                    # For Qdrant, check if we have URL or local path
                    if 'url' in connection_params:
                        url = connection_params['url']
                        api_key = connection_params.get('api_key', None)
                        qdrant_client = QdrantClient(url=url, api_key=api_key)
                    elif 'path' in connection_params:
                        path = connection_params['path']
                        qdrant_client = QdrantClient(path=path)
                    else:
                        # Default to localhost
                        qdrant_client = QdrantClient(host="localhost", port=6333)
                    
                    # Get collection name
                    if 'collection_name' not in connection_params:
                        self.logger.error("Missing required Qdrant parameter: collection_name")
                        return False
                    
                    collection_name = connection_params['collection_name']
                    
                    # Get or create collection using list_collections
                    collections_list = qdrant_client.get_collections().collections
                    collection_exists = any(c.name == collection_name for c in collections_list)
                    
                    if not collection_exists and connection_params.get('create_if_not_exists', False):
                        qdrant_client.create_collection(
                            collection_name=collection_name,
                            vectors_config=VectorParams(
                                size=self.embedding_dim,
                                distance=Distance.COSINE
                            )
                        )
                    elif not collection_exists:
                        self.logger.error(f"Qdrant collection {collection_name} does not exist. Set create_if_not_exists=True to create it.")
                        return False
                    
                    self.external_db_client = qdrant_client
                    self.external_db = collection_name  # Store collection name as string
                    self.external_db_type = 'qdrant'
                    self.logger.info(f"Connected to Qdrant collection: {collection_name}")
                    return True
                    
                except ImportError:
                    self.logger.error("Failed to import Qdrant. Please install it with 'pip install qdrant-client'")
                    return False
            
            # Weaviate (self-hosted or cloud)
            elif db_type.lower() == 'weaviate':
                try:
                    import weaviate  # type: ignore [import-not-found]
                    from weaviate.client import Client as WeaviateClient  # type: ignore [import-not-found]
                    
                    # For Weaviate, we need URL and optionally API key
                    if 'url' not in connection_params:
                        self.logger.error("Missing required Weaviate parameter: url")
                        return False
                    
                    url = connection_params['url']
                    api_key = connection_params.get('api_key', None)
                    
                    # For cloud installations
                    auth_config = None
                    if api_key:
                        auth_config = weaviate.auth.AuthApiKey(api_key=api_key)
                    
                    # Connect to Weaviate
                    weaviate_client = weaviate.Client(url=url, auth_client_secret=auth_config)
                    
                    # Get class name
                    if 'class_name' not in connection_params:
                        self.logger.error("Missing required Weaviate parameter: class_name")
                        return False
                    
                    class_name = connection_params['class_name']
                    
                    # Check if class exists and create if needed
                    class_exists = False
                    try:
                        schema = weaviate_client.schema.get()
                        classes = schema.get('classes', [])
                        class_exists = any(c.get('class') == class_name for c in classes)
                    except Exception as e:
                        self.logger.warning(f"Error checking Weaviate schema: {str(e)}")
                        
                    if not class_exists and connection_params.get('create_if_not_exists', False):
                        class_obj = {
                            "class": class_name,
                            "vectorizer": "none",  # We'll provide vectors manually
                            "properties": [
                                {
                                    "name": "content",
                                    "dataType": ["text"]
                                },
                                {
                                    "name": "metadata",
                                    "dataType": ["object"]
                                }
                            ]
                        }
                        try:
                            weaviate_client.schema.create_class(class_obj)
                            class_exists = True
                        except Exception as e:
                            self.logger.error(f"Error creating Weaviate class: {str(e)}")
                            return False
                    elif not class_exists:
                        self.logger.error(f"Weaviate class {class_name} does not exist. Set create_if_not_exists=True to create it.")
                        return False
                    
                    self.external_db = weaviate_client
                    self.external_db_type = 'weaviate'
                    self.external_db_client = class_name  # Store class name
                    self.logger.info(f"Connected to Weaviate class: {class_name}")
                    return True
                    
                except ImportError:
                    self.logger.error("Failed to import Weaviate. Please install it with 'pip install weaviate-client'")
                    return False
            
            # ChromaDB (local or cloud)
            elif db_type.lower() == 'chromadb':
                try:
                    import chromadb
                    
                    # For ChromaDB, check if we have URL or local path
                    if 'path' in connection_params:
                        path = connection_params['path']
                        client = chromadb.PersistentClient(path=path)
                    elif 'host' in connection_params and 'port' in connection_params:
                        host = connection_params['host']
                        port = connection_params['port']
                        client = chromadb.HttpClient(host=host, port=port)
                    else:
                        # Default to in-memory client
                        client = chromadb.Client()
                    
                    # Get collection name
                    if 'collection_name' not in connection_params:
                        self.logger.error("Missing required ChromaDB parameter: collection_name")
                        return False
                    
                    collection_name = connection_params['collection_name']
                    
                    # Get or create collection
                    try:
                        # Check if we need embedding function
                        collection = client.get_collection(name=collection_name)
                    except Exception:
                        if connection_params.get('create_if_not_exists', False):
                            collection = client.create_collection(name=collection_name)
                        else:
                            self.logger.error(f"ChromaDB collection {collection_name} does not exist. Set create_if_not_exists=True to create it.")
                            return False
                    
                    self.external_db_client = client
                    self.external_db = collection
                    self.external_db_type = 'chromadb'
                    self.logger.info(f"Connected to ChromaDB collection: {collection_name}")
                    return True
                    
                except ImportError:
                    self.logger.error("Failed to import ChromaDB. Please install it with 'pip install chromadb'")
                    return False
            
            else:
                self.logger.error(f"Unsupported vector database type: {db_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error connecting to external vector database: {str(e)}")
            return False
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        Calculate cosine similarity between two vectors.
        
        Args:
            vec1: First vector
            vec2: Second vector
            
        Returns:
            Cosine similarity score (0-1)
        """
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0
            
        return np.dot(vec1, vec2) / (norm1 * norm2)
    
    def _normalize_vector(self, vec: np.ndarray) -> np.ndarray:
        """
        Normalize a vector to unit length.
        
        Args:
            vec: Vector to normalize
            
        Returns:
            Normalized vector
        """
        norm = np.linalg.norm(vec)
        if norm == 0:
            return vec
        return vec / norm
        
    def add_entry(self, embedding: np.ndarray, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add an embedding and its metadata to the vector database.
        
        Args:
            embedding: The embedding vector to add
            metadata: Optional metadata to associate with the embedding
            
        Returns:
            String ID for the added entry
        """
        try:
            # Validate embedding dimension
            if len(embedding) != self.embedding_dim:
                self.logger.error(f"Invalid embedding dimension: expected {self.embedding_dim}, got {len(embedding)}")
                return ""
                
            # Ensure embedding is a numpy array
            embedding_np = np.array(embedding, dtype=np.float32)
            
            # Default metadata if none provided
            if metadata is None:
                metadata = {
                    'timestamp': datetime.now().isoformat(),
                    'id': len(self.embeddings)
                }
            else:
                # Ensure timestamp is present in metadata
                if 'timestamp' not in metadata:
                    metadata['timestamp'] = datetime.now().isoformat()
                if 'id' not in metadata:
                    metadata['id'] = len(self.embeddings)
            
            # Add to in-memory storage
            self.embeddings.append(embedding_np)
            self.metadata.append(metadata)
            
            # If using external DB, add there too
            if self.external_db is not None:
                if self.external_db_type == 'faiss':
                    # FAISS requires a 2D array with shape (n_vectors, dimension)
                    emb_to_add = embedding_np.reshape(1, -1)
                    
                    # Normalize if using cosine similarity
                    if hasattr(self, 'normalize_vectors') and self.normalize_vectors:
                        emb_to_add = self._normalize_vector(emb_to_add.squeeze()).reshape(1, -1)
                        
                    self.external_db.add(emb_to_add)
                    
                elif self.external_db_type == 'pinecone':
                    # Pinecone requires a unique ID
                    vector_id = str(metadata.get('id', f"vec_{len(self.embeddings)-1}"))
                    self.external_db.upsert(
                        vectors=[(vector_id, embedding_np.tolist(), metadata)]
                    )
                
                elif self.external_db_type == 'milvus':
                    # Milvus requires a unique ID and specific format
                    vector_id = metadata.get('id', len(self.embeddings)-1)
                    vector_id_int = 0
                    if isinstance(vector_id, str) and vector_id.isdigit():
                        vector_id_int = int(vector_id)
                    elif isinstance(vector_id, int):
                        vector_id_int = vector_id
                    else:
                        # If the ID can't be converted to an integer, use a hash
                        vector_id_int = hash(str(vector_id)) % (2**31)
                    
                    # Prepare data
                    data = [
                        [vector_id_int],  # pk
                        [embedding_np.tolist()],  # vector
                        [json.dumps(metadata)]  # metadata as JSON
                    ]
                    
                    # Insert data
                    self.external_db.insert(data)
                
                elif self.external_db_type == 'qdrant':
                    # Qdrant needs client and collection name
                    client = self.external_db_client
                    collection_name = cast(str, self.external_db)
                    
                    # Generate ID
                    vector_id = metadata.get('id', f"vec_{len(self.embeddings)-1}")
                    if isinstance(vector_id, int):
                        vector_id_str = str(vector_id)
                    else:
                        vector_id_str = str(vector_id)
                    
                    # Add point
                    client.upsert(
                        collection_name=collection_name,
                        points=[
                            {
                                "id": vector_id_str,
                                "vector": embedding_np.tolist(),
                                "payload": metadata
                            }
                        ]
                    )
                
                elif self.external_db_type == 'weaviate':
                    # Weaviate client and class name
                    client = self.external_db
                    class_name = cast(str, self.external_db_client)
                    
                    # Generate ID (Weaviate uses UUIDs)
                    import uuid
                    vector_id = str(uuid.uuid4())
                    
                    # Add with properties
                    properties = {
                        "content": metadata.get("text_preview", ""),
                        "metadata": metadata
                    }
                    
                    # Add object
                    client.data_object.create(
                        properties,
                        class_name,
                        vector=embedding_np.tolist(),
                        uuid=vector_id
                    )
                
                elif self.external_db_type == 'chromadb':
                    # ChromaDB collection
                    collection = self.external_db
                    
                    # Generate ID
                    vector_id = metadata.get('id', f"vec_{len(self.embeddings)-1}")
                    if isinstance(vector_id, int):
                        vector_id_str = str(vector_id)
                    else:
                        vector_id_str = str(vector_id)
                    
                    # Add document
                    collection.add(
                        embeddings=[embedding_np.tolist()],
                        metadatas=[metadata],
                        ids=[vector_id_str],
                        documents=[metadata.get("text_preview", "")]
                    )
            
            return str(metadata['id'])
            
        except Exception as e:
            self.logger.error(f"Error adding embedding to database: {str(e)}")
            return ""
    
    def search_similar(self, query_embedding: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for embeddings similar to the query embedding.
        
        Args:
            query_embedding: The embedding to search for
            top_k: Maximum number of results to return
            
        Returns:
            List of dictionaries containing similarity scores and metadata
        """
        self.total_queries += 1
        
        try:
            # Validate embedding dimension
            if len(query_embedding) != self.embedding_dim:
                self.logger.error(f"Invalid query embedding dimension: expected {self.embedding_dim}, got {len(query_embedding)}")
                return []
                
            # Ensure embedding is a numpy array
            query_embedding_np = np.array(query_embedding, dtype=np.float32)
            
            results: List[Dict[str, Any]] = []
            
            # If using external DB
            if self.external_db is not None:
                if self.external_db_type == 'faiss':
                    # Reshape for FAISS
                    query_vector = query_embedding_np.reshape(1, -1)
                    
                    # Normalize if using cosine similarity
                    if hasattr(self, 'normalize_vectors') and self.normalize_vectors:
                        query_vector = self._normalize_vector(query_vector.squeeze()).reshape(1, -1)
                    
                    # Search in FAISS
                    distances, indices = self.external_db.search(query_vector, top_k)
                    
                    # Convert to results format
                    for i, idx in enumerate(indices[0]):
                        if idx < len(self.metadata) and idx >= 0:  # Valid index
                            similarity = 1.0 - float(distances[0][i])  # Convert distance to similarity
                            if similarity >= self.similarity_threshold:
                                self.total_matches += 1
                                results.append({
                                    'similarity': similarity,
                                    'metadata': self.metadata[idx],
                                    'is_match': True
                                })
                    
                elif self.external_db_type == 'pinecone':
                    # Search in Pinecone
                    query_results = self.external_db.query(
                        vector=query_embedding_np.tolist(),
                        top_k=top_k,
                        include_metadata=True
                    )
                    
                    # Convert to results format
                    for match in query_results.matches:
                        similarity = match.score
                        if similarity >= self.similarity_threshold:
                            self.total_matches += 1
                            results.append({
                                'similarity': similarity,
                                'metadata': match.metadata,
                                'is_match': True
                            })
                
                elif self.external_db_type == 'milvus':
                    # Search in Milvus
                    search_params = {"metric_type": "IP", "params": {"nprobe": 10}}
                    self.external_db.search(
                        data=[query_embedding_np.tolist()],
                        anns_field="embedding",
                        param=search_params,
                        limit=top_k,
                        output_fields=["metadata"]
                    )
                    
                    # Convert to results format
                    for hit in self.external_db.hits:
                        similarity = hit.score
                        if similarity >= self.similarity_threshold:
                            self.total_matches += 1
                            metadata = json.loads(hit.entity.get('metadata'))
                            results.append({
                                'similarity': similarity,
                                'metadata': metadata,
                                'is_match': True
                            })
                
                elif self.external_db_type == 'qdrant':
                    # Search in Qdrant
                    client = self.external_db_client
                    collection_name = cast(str, self.external_db)
                    
                    # Query
                    search_results = client.search(
                        collection_name=collection_name,
                        query_vector=query_embedding_np.tolist(),
                        limit=top_k
                    )
                    
                    # Convert to results format
                    for hit in search_results:
                        similarity = hit.score
                        if similarity >= self.similarity_threshold:
                            self.total_matches += 1
                            results.append({
                                'similarity': similarity,
                                'metadata': hit.payload,
                                'is_match': True
                            })
                
                elif self.external_db_type == 'weaviate':
                    # Search in Weaviate
                    client = self.external_db
                    class_name = cast(str, self.external_db_client)
                    
                    # Query
                    results_raw = (
                        client.query
                        .get(class_name, ["metadata"])
                        .with_near_vector({
                            "vector": query_embedding_np.tolist()
                        })
                        .with_limit(top_k)
                        .do()
                    )
                    
                    # Convert to results format
                    if 'data' in results_raw and 'Get' in results_raw['data']:
                        for item in results_raw['data']['Get'][class_name]:
                            # Weaviate doesn't return raw scores, using 0.9 as default
                            similarity = 0.9  
                            metadata = item.get('metadata', {})
                            
                            if similarity >= self.similarity_threshold:
                                self.total_matches += 1
                                results.append({
                                    'similarity': similarity,
                                    'metadata': metadata,
                                    'is_match': True
                                })
                
                elif self.external_db_type == 'chromadb':
                    # Search in ChromaDB
                    collection = self.external_db
                    
                    # Query
                    search_results = collection.query(
                        query_embeddings=[query_embedding_np.tolist()],
                        n_results=top_k,
                        include=["metadatas", "distances"]
                    )
                    
                    # Convert to results format
                    distances = search_results.get('distances', [[]])[0]
                    metadatas = search_results.get('metadatas', [[]])[0]
                    
                    for i, (distance, metadata) in enumerate(zip(distances, metadatas)):
                        # ChromaDB uses L2 distance, convert to similarity
                        similarity = 1.0 / (1.0 + distance)
                        
                        if similarity >= self.similarity_threshold:
                            self.total_matches += 1
                            results.append({
                                'similarity': similarity,
                                'metadata': metadata,
                                'is_match': True
                            })
            
            # If no external DB or if using hybrid search, also search in-memory
            if not self.external_db or len(results) < top_k:
                # Calculate similarities
                in_memory_results = []
                for i, stored_embedding in enumerate(self.embeddings):
                    similarity = self._cosine_similarity(query_embedding_np, stored_embedding)
                    if similarity >= self.similarity_threshold:
                        in_memory_results.append({
                            'similarity': similarity,
                            'metadata': self.metadata[i],
                            'is_match': True
                        })
                
                # Sort by similarity (highest first)
                # Use a safer key function for sorting to help mypy
                def safe_float_key(item: Dict[str, Any]) -> float:
                    sim = item.get('similarity', 0.0)
                    try:
                        return float(sim)
                    except (ValueError, TypeError):
                        return 0.0
                in_memory_results.sort(key=safe_float_key, reverse=True)
                
                # Add top results that aren't already in the results list
                existing_ids = set()
                for r in results:
                    if isinstance(r, dict) and 'metadata' in r and isinstance(r['metadata'], dict) and 'id' in r['metadata']:
                        existing_ids.add(r['metadata']['id'])
                        
                for result in in_memory_results[:top_k]:
                    meta_id = None
                    if isinstance(result, dict) and 'metadata' in result and isinstance(result['metadata'], dict) and 'id' in result['metadata']:
                        meta_id = result['metadata']['id']
                        
                    if meta_id is not None and meta_id not in existing_ids:
                        results.append(result)
                        self.total_matches += 1
                        existing_ids.add(meta_id)
                        
                        # Stop if we've reached top_k
                        if len(results) >= top_k:
                            break
            
            # Helper function for safe sorting key
            def get_similarity_score(item: Dict[str, Any]) -> float:
                similarity = item.get('similarity')

                if isinstance(similarity, (int, float)):
                    return float(similarity)
                elif isinstance(similarity, str):
                    try:
                        # Attempt to convert if it's a string
                        # Cast to str to satisfy mypy after isinstance check
                        return float(cast(str, similarity)) 
                    except ValueError:
                        # String is not a valid float representation
                        return 0.0
                # For any other type (including None or types that don't support float), return 0.0
                return 0.0

            # Sort final results using the helper function
            results.sort(key=get_similarity_score, reverse=True)

            return results[:top_k]
            
        except Exception as e:
            self.logger.error(f"Error searching database: {str(e)}")
            return []
    
    def get_size(self) -> int:
        """
        Get the number of entries in the vector database.
        
        Returns:
            Number of entries
        """
        if self.external_db_type is None:
            return len(self.embeddings)
        
        # Handle external DB types
        if self.external_db_type == 'faiss':
             return self.external_db.ntotal if self.external_db else 0
        elif self.external_db_type == 'pinecone':
             # Pinecone index stats might need API call
             try:
                 stats = self.external_db.describe_index_stats()
                 return stats.total_vector_count if stats else 0
             except Exception as e:
                 self.logger.error(f"Failed to get Pinecone index size: {e}")
                 return 0 # Or handle error differently
        elif self.external_db_type == 'milvus':
             try:
                 stats = self.external_db.get_collection_stats()
                 return stats.row_count
             except Exception as e:
                 self.logger.error(f"Failed to get Milvus collection size: {e}")
                 return 0
        elif self.external_db_type == 'qdrant':
             try:
                 count = self.external_db.count(collection_name=self.config.get('qdrant_collection_name', 'resk_vectors')).count
                 return count
             except Exception as e:
                 self.logger.error(f"Failed to get Qdrant collection size: {e}")
                 return 0
        elif self.external_db_type == 'weaviate':
             try:
                 # Weaviate counts might require a query
                 result = self.external_db.query.aggregate(self.config.get('weaviate_class_name', 'VectorEntry')).with_meta_count().do()
                 return result['data']['Aggregate'][self.config.get('weaviate_class_name', 'VectorEntry')][0]['meta']['count']
             except Exception as e:
                 self.logger.error(f"Failed to get Weaviate class size: {e}")
                 return 0
        elif self.external_db_type == 'chromadb':
             try:
                  return self.external_db.count()
             except Exception as e:
                  self.logger.error(f"Failed to get ChromaDB collection size: {e}")
                  return 0
        else:
             # Fallback for unknown external DB or if connection failed
             self.logger.warning(f"get_size not fully implemented for external DB type: {self.external_db_type}. Returning in-memory size.")
             return len(self.embeddings) # Return in-memory size as fallback

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the vector database.
        
        Returns:
            Dictionary containing statistics
        """
        return {
            'embedding_count': len(self.embeddings),
            'total_queries': self.total_queries,
            'total_matches': self.total_matches,
            'creation_time': self.creation_time.isoformat(),
            'uptime_seconds': (datetime.now() - self.creation_time).total_seconds(),
            'external_db_type': self.external_db_type,
            'similarity_threshold': self.similarity_threshold,
            'embedding_dimension': self.embedding_dim
        }
        
    def save_to_disk(self, file_path: str) -> bool:
        """
        Save the vector database to disk.
        
        Args:
            file_path: Path to save the database to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Save embeddings and metadata
            data = {
                'embeddings': [e.tolist() for e in self.embeddings],
                'metadata': self.metadata,
                'statistics': self.get_statistics(),
                'config': self.config
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f)
                
            self.logger.info(f"Saved vector database to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving database to disk: {str(e)}")
            return False
    
    def load_from_disk(self, file_path: str) -> bool:
        """
        Load the vector database from disk.
        
        Args:
            file_path: Path to load the database from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False
                
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Load embeddings and metadata
            self.embeddings = [np.array(e, dtype=np.float32) for e in data['embeddings']]
            self.metadata = data['metadata']
            
            # Update config if present
            if 'config' in data:
                self.update_config(data['config'])
            
            # Also add to external DB if connected
            if self.external_db is not None:
                if self.external_db_type == 'faiss':
                    # Create a combined array for all embeddings
                    if self.embeddings:
                        combined = np.vstack(self.embeddings)
                        self.external_db.add(combined)
                        
                elif self.external_db_type == 'pinecone':
                    # Add to Pinecone in batches
                    batch_size = 100
                    for i in range(0, len(self.embeddings), batch_size):
                        batch_vectors = []
                        for j in range(i, min(i + batch_size, len(self.embeddings))):
                            vector_id = str(self.metadata[j].get('id', f"vec_{j}"))
                            batch_vectors.append(
                                (vector_id, self.embeddings[j].tolist(), self.metadata[j])
                            )
                        
                        if batch_vectors:
                            self.external_db.upsert(vectors=batch_vectors)
                
                elif self.external_db_type in ['milvus', 'qdrant', 'weaviate', 'chromadb']:
                    # Add vectors one by one
                    for i, embedding in enumerate(self.embeddings):
                        self.add_entry(embedding, self.metadata[i])
            
            self.logger.info(f"Loaded vector database from {file_path} with {len(self.embeddings)} embeddings")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading database from disk: {str(e)}")
            return False 