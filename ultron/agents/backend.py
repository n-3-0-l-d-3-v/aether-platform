"""Pluggable local-LLM backends for specialist agents.

Kept deliberately minimal: text in, text out, one call at a time. No chat
history, no streaming, no tool-calling protocol - a specialist agent here only
ever needs a single structured completion per batch of candidates.

``OllamaBackend`` is the only real backend, and it is local-only by hard
requirement, not a default that could silently regress into a cloud call.
Ultron has zero runtime dependencies (ADR 0001); this module talks to Ollama's
HTTP API with nothing but the standard library.

``FakeLLMBackend`` exists for tests and for anyone experimenting with the
agent's parsing logic without running a model at all. It is not reachable from
the CLI - a CLI user has no reason to run a fake backend - only from the
Python API, which is exactly where tests use it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from ultron.errors import AdapterUnavailable

#: Default Ollama HTTP endpoint. Overridable per instance; never assumed by
#: anything outside this module.
DEFAULT_OLLAMA_HOST = "http://localhost:11434"

#: Default wall-clock ceiling for one completion call.
DEFAULT_TIMEOUT_SECONDS = 60.0


class LLMBackend(Protocol):
    """Anything that can turn a prompt into text, locally."""

    def complete(self, prompt: str, *, max_tokens: int = 512) -> str:
        """Return the model's completion for ``prompt``.

        Raises :class:`ultron.errors.AdapterUnavailable` when the backend
        cannot be reached at all. Never raises for a merely unhelpful or
        malformed response - callers are expected to parse defensively.
        """
        ...


@dataclass(frozen=True)
class Availability:
    """Whether a backend can be reached here, mirroring
    :class:`ultron.adapters.base.Availability` for the same reason: so the CLI
    can report "unreachable" cleanly before doing any work.
    """

    available: bool
    detail: str = ""
    remedy: str = ""

    def to_record(self) -> dict[str, Any]:
        return {"available": self.available, "detail": self.detail, "remedy": self.remedy}


class FakeLLMBackend:
    """A deterministic, no-network backend for tests and experimentation.

    ``responder`` is either a fixed string (every call returns it) or a
    callable that receives the prompt and returns the response - which is
    what a test simulating malformed output, or varying per-batch behaviour,
    wants.
    """

    def __init__(self, responder: str | Callable[[str], str]) -> None:
        self._responder = responder

    def complete(self, prompt: str, *, max_tokens: int = 512) -> str:
        if callable(self._responder):
            return self._responder(prompt)
        return self._responder

    def probe(self) -> Availability:
        return Availability(available=True, detail="fake backend; no network involved")


class OllamaBackend:
    """Talks to a locally-running Ollama server, stdlib HTTP only.

    ``model`` names a model the caller has already pulled (``ollama pull
    <model>``) - there is no hardcoded default model, on purpose. Ollama's own
    defaults change over time and silently binding to one would mean this
    code picks a model on the user's behalf without them knowing.

    ``host`` is checked against Ultron's ``private`` sensitivity tier
    (``ultron.network_policy``) at construction time: a non-local host raises
    unless ``ULTRON_ALLOW_REMOTE_AGENT_HOST=1`` is set explicitly. This was
    already local-only by convention (ADR 0010); it is now local-only by
    construction too.
    """

    def __init__(
        self,
        model: str,
        *,
        host: str = DEFAULT_OLLAMA_HOST,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not model:
            raise ValueError("OllamaBackend requires a model name, e.g. 'llama3.2'")
        from ultron.network_policy import assert_local_host

        assert_local_host(host)
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def _remedy(self) -> str:
        return (
            "Install Ollama from https://ollama.com, run "
            f"'ollama pull {self.model}', then 'ollama serve' (or start the "
            f"Ollama app) so {self.host} answers. This call is fully local - "
            "no data ever leaves the machine."
        )

    def probe(self) -> Availability:
        url = f"{self.host}/api/tags"
        try:
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    return Availability(
                        available=False,
                        detail=f"Ollama at {self.host} returned HTTP {response.status}",
                        remedy=self._remedy(),
                    )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return Availability(
                available=False,
                detail=f"could not reach Ollama at {self.host}: {exc}",
                remedy=self._remedy(),
            )
        return Availability(available=True, detail=f"Ollama reachable at {self.host}")

    def complete(self, prompt: str, *, max_tokens: int = 512) -> str:
        url = f"{self.host}/api/generate"
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise AdapterUnavailable(
                        f"Ollama at {self.host} returned HTTP {response.status} for "
                        f"model {self.model!r}.\n  {self._remedy()}"
                    )
                body = response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AdapterUnavailable(
                f"could not reach Ollama at {self.host} for model {self.model!r}: "
                f"{exc}.\n  {self._remedy()}"
            ) from exc

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AdapterUnavailable(
                f"Ollama at {self.host} returned a response that was not valid "
                f"JSON.\n  {self._remedy()}"
            ) from exc

        response_text = parsed.get("response")
        if not isinstance(response_text, str):
            raise AdapterUnavailable(
                f"Ollama at {self.host} returned no 'response' field for model "
                f"{self.model!r}.\n  {self._remedy()}"
            )
        return response_text


def probe(backend: LLMBackend) -> Availability:
    """Probe any backend that exposes its own ``.probe()``.

    Backends without a meaningful availability check (there are none today,
    but the protocol does not require one) are reported optimistically -
    the first real call will surface the failure instead.
    """
    prober = getattr(backend, "probe", None)
    if callable(prober):
        return prober()
    return Availability(available=True, detail="backend has no probe(); assumed reachable")


__all__ = [
    "Availability",
    "DEFAULT_OLLAMA_HOST",
    "DEFAULT_TIMEOUT_SECONDS",
    "FakeLLMBackend",
    "LLMBackend",
    "OllamaBackend",
    "probe",
]
