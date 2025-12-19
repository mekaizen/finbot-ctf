"""Ollama Client with configurable model"""

import logging
import json

from ollama import AsyncClient
from finbot.core.llm.utils import retry
from finbot.config import settings
from finbot.core.data.models import LLMRequest, LLMResponse

logger = logging.getLogger(__name__)


class OllamaClient:
    """Ollama Client with configurable model"""

    def __init__(self):
        self.default_model = settings.LLM_DEFAULT_MODEL
        self.default_temperature = settings.LLM_DEFAULT_TEMPERATURE
        self.host = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")

        
        self._client = AsyncClient(
            host=self.host,
            timeout=settings.LLM_TIMEOUT,
        )

    @retry(max_retries=3, backoff_seconds=0.5)
    async def chat(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """
        Chat with Ollama
        """
        try:
            model = request.model or self.default_model
            temperature = request.temperature or self.default_temperature
            messages = request.messages or []
            tool_calls = []

            options = {
                "temperature": temperature,
                "num_predict": settings.LLM_MAX_TOKENS,
            }

            chat_params = {
                "model": model,
                "messages": messages,
                "options": options,
            }

            
            if request.output_json_schema:
                chat_params["format"] = request.output_json_schema.get("schema")

            
            if request.tools:
                chat_params["tools"] = request.tools

            response = await self._client.chat(**chat_params)

            message = response.message
            content = message.content or ""

            
            if message.tool_calls:
                for idx, tc in enumerate(message.tool_calls):
                    tool_calls.append(
                        {
                            "name": tc.function.name,
                            "call_id": f"ollama_call_{idx}",
                            "arguments": tc.function.arguments,
                        }
                    )

            # Append assistant turn to conversation history
            history_entry = {
                "role": "assistant",
                "content": content,
            }
            if message.tool_calls:
                history_entry["tool_calls"] = message.tool_calls

            messages.append(history_entry)

            metadata = {
                "total_duration": getattr(response, "total_duration", None),
                "load_duration": getattr(response, "load_duration", None),
                "eval_count": getattr(response, "eval_count", None),
            }

            return LLMResponse(
                content=content,
                provider="ollama",
                success=True,
                metadata=metadata,
                messages=messages,
                tool_calls=tool_calls,
            )

        except Exception as e: 
            logger.error("Ollama chat failed: %s", e)
            raise 
