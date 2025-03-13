from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("LICENCE.txt", "r", encoding="utf-8") as f:
    license_text = f.read()

setup(
    name="resk-llm",
    version="0.4.0",
    author="Resk",
    author_email="nielzac@proton.me",
    description="Resk-LLM is a robust Python library designed to enhance security and manage context when interacting with LLM APIs. It provides a protective layer for API calls, safeguarding against common vulnerabilities and ensuring optimal performance.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Resk-Security/Resk-LLM",
    packages=find_packages(),
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
    ],
    extras_require={
        "cuda": ["torch>=2.0.0"],
        "all": [
            "torch>=2.0.0",
            "tiktoken>=0.5.0",
            "sentence-transformers>=2.2.2",
            "scikit-learn>=1.2.0",
        ],
    },
    license=license_text,
)
