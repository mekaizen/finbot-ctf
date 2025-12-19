import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---- mock ollama  ----
mock_ollama = MagicMock()
mock_ollama.AsyncClient = MagicMock()
sys.modules["ollama"] = mock_ollama
# --------------------------------------------------------------

from finbot.core.llm.ollama_client import OllamaClient
from finbot.core.data.models import LLMRequest


@pytest.mark.asyncio
async def test_ollama_chat_success():
    fake_message = AsyncMock()
    fake_message.content = "hello"
    fake_message.tool_calls = None

    fake_response = AsyncMock()
    fake_response.message = fake_message

    with patch("finbot.core.llm.ollama_client.AsyncClient") as mock_client:
        instance = mock_client.return_value
        instance.chat = AsyncMock(return_value=fake_response)

        client = OllamaClient()

        request = LLMRequest(
            messages=[{"role": "user", "content": "hi"}]
        )

        response = await client.chat(request)

        assert response.success is True
        assert response.provider == "ollama"
        assert response.content == "hello"
        assert len(response.messages) == 2  


@pytest.mark.asyncio
async def test_ollama_retry():
    with patch("finbot.core.llm.ollama_client.AsyncClient") as mock_client:
        instance = mock_client.return_value
        instance.chat = AsyncMock(
            side_effect=[
                TimeoutError("fail"),
                AsyncMock(
                    message=AsyncMock(content="ok", tool_calls=None)
                ),
            ]
        )

        client = OllamaClient()
        request = LLMRequest(messages=[{"role": "user", "content": "hi"}])

        response = await client.chat(request)

        assert response.content == "ok"
        assert instance.chat.call_count == 2

@pytest.mark.asyncio
async def test_ollama_retry_exhausted():
    with patch("finbot.core.llm.ollama_client.AsyncClient") as mock_client:
        instance = mock_client.return_value
        instance.chat = AsyncMock(side_effect=TimeoutError("fail"))

        client = OllamaClient()
        request = LLMRequest(messages=[{"role": "user", "content": "hi"}])

        with pytest.raises(TimeoutError):
            await client.chat(request)

        # default max_retries=3 → total attempts = 4
        assert instance.chat.call_count == 4
