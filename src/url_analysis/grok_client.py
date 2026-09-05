"""
Grok AI Client
Interfaces with the xAI Grok API (OpenAI-compatible) with built-in
circuit breaking, exponential retry, timeout enforcement, and graceful degradation.
"""

import time
import logging
from typing import Optional, Dict, Any

from config import settings
from .prompts import SYSTEM_PROMPT, build_analysis_prompt, parse_grok_response

logger = logging.getLogger("grok_client")


class GrokUnavailableError(Exception):
    """Raised when Grok API is unreachable, unconfigured, or circuit breaker is open."""
    pass


class CircuitBreakerState:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class GrokClient:
    """Client for xAI Grok API with circuit breaker and fallback resilience."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ):
        self.api_key = api_key if api_key is not None else settings.GROK_API_KEY
        self.base_url = base_url or settings.GROK_BASE_URL
        self.model = model or settings.GROK_MODEL
        self.timeout = timeout if timeout is not None else settings.GROK_TIMEOUT_SECONDS
        self.max_retries = max_retries if max_retries is not None else settings.GROK_MAX_RETRIES

        # Circuit breaker parameters
        self.failure_threshold = settings.GROK_CIRCUIT_BREAKER_FAILURES
        self.reset_timeout = settings.GROK_CIRCUIT_BREAKER_RESET_SECONDS

        self.consecutive_failures = 0
        self.last_failure_time = 0.0
        self.state = CircuitBreakerState.CLOSED

        self.client = None
        self._init_client()

    def _init_client(self) -> None:
        """Initialize the OpenAI client if a valid key is present."""
        clean_key = (self.api_key or "").strip()
        if clean_key and not clean_key.startswith("xai-example-key"):
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=clean_key,
                    base_url=self.base_url,
                    timeout=self.timeout
                )
                logger.info(f"Grok client initialized for model {self.model} at {self.base_url}")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI client for Grok: {e}")
                self.client = None
        else:
            logger.info("No valid Grok API key configured - running in deterministic/offline mode.")
            self.client = None

    @property
    def is_available(self) -> bool:
        """Check if client is configured and circuit breaker allows execution."""
        if not self.client:
            return False

        if self.state == CircuitBreakerState.OPEN:
            if time.time() - self.last_failure_time >= self.reset_timeout:
                logger.info("Circuit breaker transitioning to HALF_OPEN (probing API)")
                self.state = CircuitBreakerState.HALF_OPEN
                return True
            return False

        return True

    def _record_success(self) -> None:
        """Record successful call, resetting circuit breaker to CLOSED."""
        self.consecutive_failures = 0
        self.state = CircuitBreakerState.CLOSED

    def _record_failure(self) -> None:
        """Record failed call and trip breaker to OPEN if threshold exceeded."""
        self.consecutive_failures += 1
        self.last_failure_time = time.time()
        if self.consecutive_failures >= self.failure_threshold:
            logger.warning(
                f"Grok circuit breaker TRIPPED to OPEN after {self.consecutive_failures} consecutive failures. "
                f"Suppressing calls for {self.reset_timeout}s."
            )
            self.state = CircuitBreakerState.OPEN

    def analyze(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query Grok to evaluate a URL.
        Raises GrokUnavailableError if client is offline or circuit breaker is OPEN.
        """
        if not self.is_available:
            raise GrokUnavailableError(
                f"Grok service is unavailable (configured={self.client is not None}, state={self.state})"
            )

        prompt = build_analysis_prompt(url, features)
        attempts = 0
        last_err = None

        while attempts <= self.max_retries:
            attempts += 1
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=250,
                )
                self._record_success()
                content = response.choices[0].message.content or ""
                return parse_grok_response(content)

            except Exception as e:
                last_err = e
                logger.warning(f"Grok API call attempt {attempts} failed for '{url}': {e}")
                if attempts <= self.max_retries:
                    time.sleep(0.5 * attempts)

        self._record_failure()
        raise GrokUnavailableError(f"Grok API failed after {attempts} attempts: {last_err}")


_default_grok_client: Optional[GrokClient] = None


def get_grok_client() -> GrokClient:
    """Get singleton GrokClient."""
    global _default_grok_client
    if _default_grok_client is None:
        _default_grok_client = GrokClient()
    return _default_grok_client
