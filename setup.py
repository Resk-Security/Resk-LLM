from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("LICENSE.txt", "r", encoding="utf-8") as f:
    license_text = f.read()

setup(
    name="resk-llm",
    version="1.2.0",
    author="Resk",
    author_email="contact@resk.fr",
    description="Resk-LLM is a robust Python library designed to enhance security and manage context when interacting with LLM APIs. It provides a protective layer for API calls, safeguarding against common vulnerabilities and ensuring optimal performance.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Resk-Security/Resk-LLM",
    packages=find_packages(),
    package_data={"resk_llm": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "openai>=1.41.0",
        "transformers>=4.44.2",
        "flask>=2.0.0",
        "fastapi>=0.110.0",
        "uvicorn>=0.28.0",
        "starlette>=0.36.0",
        "anthropic>=0.22.0",
        "cohere>=4.46.0",
        "langchain>=0.1.0",
        "langchain-core>=0.1.0",
        "langchain-community>=0.1.0",
        "langchain-openai>=0.1.0",
        "numpy>=1.20.0",
        "pillow>=9.0.0",
        "pydantic>=2.0.0",
        "requests>=2.25.0",
        "rich>=10.0.0",
        "typing-extensions>=4.0.0",
        "urllib3>=1.26.0",
        "httpx>=0.27.0",
        "pytest>=7.4.3",
        "pytest-asyncio>=0.23.5",
        "tldextract>=3.4.4",  # For URL domain extraction
        "mypy",
        "PyJWT>=2.0.0",  # Pour la gestion des tokens JWT
    ],
    extras_require={
        "embeddings": [
            "scikit-learn>=1.2.0",  # Provides alternatives for embeddings
        ],
        "all": [
            "tiktoken>=0.5.0",
            "scikit-learn>=1.2.0",
            "faiss-cpu>=1.7.4",  # For CPU-based vector search
            "pinecone-client>=2.2.1",  # For cloud-based vector database
            "pymilvus>=2.3.0",  # For Milvus vector database
            "qdrant-client>=1.7.0",  # For Qdrant vector database
            "weaviate-client>=3.25.0",  # For Weaviate vector database
            "chromadb>=0.4.22",  # For ChromaDB vector database
            "tldextract>=3.4.4",  # For URL domain extraction
            "ipaddress>=1.0.23",  # For IP address handling
        ],
        "vector": [
            "faiss-cpu>=1.7.4",  # For CPU-based vector search
            "scikit-learn>=1.2.0",  # For creating embeddings without torch
        ],
        "vector-all": [
            "faiss-cpu>=1.7.4",
            "pinecone-client>=2.2.1",
            "pymilvus>=2.3.0",
            "qdrant-client>=1.7.0",
            "weaviate-client>=3.25.0",
            "chromadb>=0.4.22",
        ],
        "url-security": [
            "tldextract>=3.4.4",
            "ipaddress>=1.0.23",
        ],
        "text-analysis": [
            "unicodedata2>=15.0.0",  # Enhanced Unicode database
        ],
        "competitor-filter": [
            "spacy>=3.5.0",  # For NER and entity recognition
        ],
    },
    license=license_text,
)
