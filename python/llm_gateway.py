"""A small API-key gateway to a hosted LLM (nothing installed locally).

Two request formats cover most providers:

    openai     POST <base_url>/chat/completions   OpenAI, and the many
               providers that offer an OpenAI-compatible endpoint
    anthropic  POST <base_url>/v1/messages        Anthropic Messages API

Configuration comes from environment variables:

    LLM_PROVIDER   openai (default) or anthropic
    LLM_MODEL      model name (required for openai; anthropic has a default)
    LLM_BASE_URL   optional, defaults below
    LLM_API_KEY    the key; if it is not set, from_env() asks for it with
                   getpass, so it is not shown while you type

The key is only ever put in a request header. It is never printed,
logged, saved to a file, or included in an exception message. Only the
standard library (urllib) is used.

Provider-specific code lives here and nowhere else: the planner only
calls chat(), and the bridge never sees the model at all.
"""
import getpass
import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
}
DEFAULT_MODEL = {
    "anthropic": "claude-haiku-5-5",
}
ANTHROPIC_VERSION = "2023-06-01"


class LLMError(Exception):
    """The model could not be reached or gave an unusable reply."""


class LLMGateway:
    def __init__(self, provider, api_key, model, base_url=None, timeout=30):
        if provider not in DEFAULT_BASE:
            raise LLMError(f"unknown provider {provider!r} (use openai or anthropic)")
        if not api_key:
            raise LLMError("no API key given")
        if not model:
            raise LLMError("no model given (set LLM_MODEL)")
        self.provider = provider
        self._key = api_key
        self.model = model
        self.base_url = (base_url or DEFAULT_BASE[provider]).rstrip("/")
        self.timeout = timeout

    def __repr__(self):
        # Never show the key.
        return f"LLMGateway(provider={self.provider!r}, model={self.model!r}, base_url={self.base_url!r})"

    @classmethod
    def from_env(cls, env=None, ask=getpass.getpass):
        env = os.environ if env is None else env
        provider = env.get("LLM_PROVIDER", "openai").strip().lower()
        model = env.get("LLM_MODEL", DEFAULT_MODEL.get(provider, "")).strip()
        key = env.get("LLM_API_KEY", "").strip()
        if not key:
            key = ask(f"API key for {provider}: ").strip()
        return cls(provider, key, model, env.get("LLM_BASE_URL") or None)

    def chat(self, system, messages):
        """Send a system prompt and a list of {"role", "content"} messages,
        return the model's reply text."""
        if self.provider == "anthropic":
            url = self.base_url + "/v1/messages"
            headers = {"x-api-key": self._key, "anthropic-version": ANTHROPIC_VERSION}
            body = {"model": self.model, "max_tokens": 300,
                    "system": system, "messages": messages}
        else:
            url = self.base_url + "/chat/completions"
            headers = {"Authorization": "Bearer " + self._key}
            body = {"model": self.model,
                    "messages": [{"role": "system", "content": system}] + messages}
        data = self._post(url, headers, body)
        try:
            if self.provider == "anthropic":
                return "".join(b["text"] for b in data["content"] if b.get("type") == "text")
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise LLMError("unexpected response format from the provider") from None

    def _post(self, url, headers, body):
        # Some providers (e.g. Groq, behind Cloudflare) reject urllib's
        # default "Python-urllib" User-Agent with 403 / error 1010.
        headers = dict(headers, **{"Content-Type": "application/json",
                                   "User-Agent": "xv6-taint-agent/1.0"})
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise LLMError(self._redact(f"HTTP {e.code} from {self.provider}: {detail}")) from None
        except urllib.error.URLError as e:
            raise LLMError(self._redact(f"cannot reach {self.base_url}: {e.reason}")) from None
        except (TimeoutError, OSError) as e:
            raise LLMError(self._redact(f"request to {self.provider} failed: {e}")) from None
        except json.JSONDecodeError:
            raise LLMError(f"{self.provider} did not return JSON") from None

    def _redact(self, text):
        return text.replace(self._key, "***")
