"""
Agent session and token handling.
Manages the agent's connection to Guardian and stores
sensitive data in memory only.
"""
from __future__ import annotations
import ctypes
from typing import Optional


class AgentSession:
    """
    Holds session state for an agent running on a droplet.

    LLM API key and access token are stored in memory only — never disk.
    clear() zeros sensitive fields.
    llm_api_key uses bytearray so it can be zeroed in place.
    The property setter enforces bytearray storage on every assignment.
    """
    def __init__(self) -> None:
        self._llm_api_key: Optional[bytearray] = bytearray()
        self.access_token: str = ""
        self.session_id: str = ""
        self.agent_id: str = ""
        self.guardian_url: str = ""

    @property
    def llm_api_key(self) -> Optional[bytearray]:
        return self._llm_api_key

    @llm_api_key.setter
    def llm_api_key(self, value) -> None:
        """
        Enforce bytearray storage for in-place zeroing.
        Automatically converts str/bytes to bytearray.
        Zeros the old key before replacement.
        """
        if self._llm_api_key is not None:
            for i in range(len(self._llm_api_key)):
                self._llm_api_key[i] = 0

        if value is None:
            self._llm_api_key = None
        elif isinstance(value, bytearray):
            self._llm_api_key = value
        elif isinstance(value, str):
            self._llm_api_key = bytearray(value.encode("utf-8"))
        elif isinstance(value, bytes):
            self._llm_api_key = bytearray(value)
        else:
            raise TypeError(
                f"llm_api_key must be str, bytes, or bytearray, "
                f"got {type(value)}"
            )

    def set_llm_api_key(self, key: str) -> None:
        """Set the LLM API key from a string, storing as bytearray."""
        self.llm_api_key = key

    def get_llm_api_key(self) -> str:
        """Return the LLM API key as a string."""
        return self._llm_api_key.decode("utf-8") if self._llm_api_key else ""

    def clear(self) -> None:
        """Zero out sensitive fields on session end."""
        if self._llm_api_key is not None:
            for i in range(len(self._llm_api_key)):
                self._llm_api_key[i] = 0
            self._llm_api_key = None

        # Best-effort zero for access_token (immutable str)
        val = self.access_token
        if val:
            try:
                buf = ctypes.create_string_buffer(val.encode("utf-8"))
                ctypes.memset(buf, 0, len(val))
            except Exception:
                pass
        self.access_token = ""
        self.session_id = ""
        self.agent_id = ""
        self.guardian_url = ""
