class ReskError(Exception):
    """Base exception for all RESK errors."""

    pass


class DetectionError(ReskError):
    """Raised when a detection module fails."""

    def __init__(self, detector: str, message: str, original: Exception | None = None):
        self.detector = detector
        self.original = original
        super().__init__(f"[{detector}] {message}")


class PipelineError(ReskError):
    """Raised when the security pipeline fails."""

    def __init__(self, message: str, results: list | None = None):
        self.results = results or []
        super().__init__(message)


class ConfigurationError(ReskError):
    """Raised when configuration is invalid."""

    pass


class ValidationError(ReskError):
    """Raised when input/output validation fails."""

    def __init__(self, message: str, details: dict | None = None):
        self.details = details or {}
        super().__init__(message)
