from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("LICENCE.txt", "r", encoding="utf-8") as f:
    license_text = f.read()

setup(
    name="resk-llm",
    version="0.2.1",
    author="Resk",
    author_email="nielzac@proton.me",
    description="Resk-LLM is a robust Python library designed to enhance security and manage context when interacting with OpenAI's language models. It provides a protective layer for API calls, safeguarding against common vulnerabilities and ensuring optimal performance.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Resk-Security/Resk-LLM",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "openai",
    ],
    license=license_text,
)
