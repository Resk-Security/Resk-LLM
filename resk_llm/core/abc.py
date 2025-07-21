# resk_llm/core/abc.py

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, Generic, TypeVar, cast

# Generic type for configuration dictionaries
ConfigType = TypeVar("ConfigType", bound=Dict[str, Any])
# Generic type for input data (e.g., text, request objects)
InputType = TypeVar("InputType")
# Generic type for output data (e.g., processed text, security report)
OutputType = TypeVar("OutputType")

class SecurityComponent(ABC, Generic[ConfigType]):
    """
    Base class for all security components in RESK-LLM.
    Ensures components can be configured.
    """
    config: ConfigType  # Add type annotation for instance variable

    def __init__(self, config: Optional[ConfigType] = None):
        self.config = config if config is not None else cast(ConfigType, {})
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate the provided configuration."""
        pass

    @abstractmethod
    def update_config(self, config: ConfigType) -> None:
        """Update the component's configuration."""
        pass

class FilterBase(SecurityComponent[ConfigType], Generic[InputType, OutputType, ConfigType]):
    """
    Abstract Base Class for filtering components.
    Filters typically analyze input and may modify it or flag it based on criteria.
    """
    @abstractmethod
    def filter(self, data: InputType) -> OutputType:
        """
        Apply the filter to the input data.

        Args:
            data: The input data to be filtered.

        Returns:
            The processed data or a report indicating findings.
        """
        pass

class DetectorBase(SecurityComponent[ConfigType], Generic[InputType, ConfigType]):
    """
    Abstract Base Class for detection components.
    Detectors analyze input to identify specific patterns or threats, usually returning a boolean or score.
    """
    @abstractmethod
    def detect(self, data: InputType) -> Union[bool, float, Dict[str, Any]]:
        """
        Analyze the input data to detect specific threats or patterns.

        Args:
            data: The input data to be analyzed.

        Returns:
            A boolean indicating detection, a score, or a dictionary with detection details.
        """
        pass

class ProtectorBase(SecurityComponent[ConfigType], Generic[InputType, OutputType, ConfigType]):
    """
    Abstract Base Class for LLM provider-specific protectors.
    These often wrap API calls or interact directly with provider SDKs.
    """
    @abstractmethod
    def protect_input(self, prompt: InputType, **kwargs) -> InputType:
        """
        Apply security measures to the input before sending to the LLM.

        Args:
            prompt: The input prompt or data.
            **kwargs: Additional provider-specific arguments.

        Returns:
            The potentially modified/validated input prompt or data.
        """
        pass

    @abstractmethod
    def protect_output(self, response: OutputType, **kwargs) -> OutputType:
        """
        Apply security measures to the output received from the LLM.

        Args:
            response: The response from the LLM.
            **kwargs: Additional provider-specific arguments.

        Returns:
            The potentially modified/validated response.
        """
        pass

class PatternProviderBase(SecurityComponent[ConfigType], Generic[ConfigType]):
    """
    Abstract Base Class for components that load and provide access to patterns (regex, keywords, etc.).
    """
    @abstractmethod
    def load_patterns(self) -> None:
        """Load patterns from their source (files, database, etc.)."""
        pass

    @abstractmethod
    def get_patterns(self, category: Optional[str] = None, lang: Optional[str] = None) -> Any:
        """
        Retrieve patterns, potentially filtered by category or language.

        Args:
            category: The type of patterns to retrieve (e.g., 'pii', 'injection').
            lang: The language code (e.g., 'en', 'fr').

        Returns:
            The requested patterns (e.g., list of strings, dict of regex).
        """
        pass

# Example of a more complex SecurityManager structure (optional, can be refined later)
class SecurityManagerBase(SecurityComponent[ConfigType], Generic[InputType, OutputType, ConfigType]):
    """
    Abstract Base Class for orchestrating multiple security components.
    """
    def __init__(self, config: Optional[ConfigType] = None):
        super().__init__(config)
        self.filters: List[FilterBase] = []
        self.detectors: List[DetectorBase] = []
        # Potentially other component types

    @abstractmethod
    def add_component(self, component: Union[FilterBase, DetectorBase, Any]) -> None:
        """Add a security component (filter, detector, etc.) to the manager."""
        pass

    @abstractmethod
    def process_input(self, data: InputType) -> InputType:
        """Process input data through the configured security components."""
        pass

    @abstractmethod
    def process_output(self, data: OutputType) -> OutputType:
        """Process output data through the configured security components."""
        pass

    @abstractmethod
    def generate_report(self) -> Dict[str, Any]:
        """Generate a report summarizing the security checks performed."""
        pass 

class RESK_UtilityBase(ABC):
    """
    Abstract Base Class for utility components (embedding, text analysis, etc.).
    """
    @abstractmethod
    def process(self, *args, **kwargs) -> Any:
        """Process input and return output (to be implemented by utility classes)."""
        pass 