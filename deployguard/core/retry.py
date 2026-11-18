"""
deployguard/core/retry.py — Resilient asynchronous retry utilities for external integrations.

Provides exponential backoff and jitter for transient failures when communicating
with upstream services (GitHub API, MongoDB Atlas, OpenAI endpoints).
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryExhaustedError(Exception):
    """Raised when all retry attempts fail."""


async def with_retry(
    func: Callable[[], Awaitable[T]],
    max_attempts: int = 3,
    initial_delay_sec: float = 0.5,
    backoff_multiplier: float = 2.0,
    jitter_factor: float = 0.1,
    retry_on: tuple[type[Exception], ...] = (Exception,),
) -> T:
    """
    Execute an asynchronous function with exponential backoff and jitter.

    Args:
        func: Zero-argument coroutine factory to execute.
        max_attempts: Maximum total attempts before raising ``RetryExhaustedError``.
        initial_delay_sec: Base delay in seconds before the first retry.
        backoff_multiplier: Multiplier applied to delay after each failure.
        jitter_factor: Uniform random jitter factor (+/- fraction) to avoid thundering herd.
        retry_on: Tuple of exception types that should trigger a retry.

    Returns:
        The return value of ``func()`` upon success.

    Raises:
        RetryExhaustedError: If all attempts fail.
    """
    delay = initial_delay_sec
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            return await func()
        except retry_on as exc:
            last_error = exc
            if attempt == max_attempts:
                logger.error("Retry exhausted after %d attempts: %s", max_attempts, exc)
                break

            jitter = delay * jitter_factor * (random.random() * 2 - 1)
            sleep_duration = max(0.01, delay + jitter)
            logger.warning(
                "Attempt %d/%d failed with %s; retrying in %.2fs",
                attempt,
                max_attempts,
                type(exc).__name__,
                sleep_duration,
            )
            await asyncio.sleep(sleep_duration)
            delay *= backoff_multiplier

    raise RetryExhaustedError(
        f"Operation failed after {max_attempts} attempts. Last error: {last_error}"
    ) from last_error
