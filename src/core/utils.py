"""
Lab 11 — Helper Utilities
"""
from core.config import get_llm_provider, PROVIDER_OPENROUTER  # noqa: F401
from core.openai_runtime import OpenAIRunner


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Works with OpenAIRunner (OpenAI Red / OpenRouter Blue) and Google ADK (Gemini Red).
    """
    provider = getattr(runner, "provider", None)
    if isinstance(runner, OpenAIRunner) or provider in ("openrouter", "openai"):
        text = await runner.chat(agent, user_message)
        return text, None

    from google.genai import types

    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    import asyncio

    max_attempts = 4
    for attempt in range(max_attempts):
        if session is None:
            try:
                session = await runner.session_service.create_session(
                    app_name=app_name, user_id=user_id
                )
            except Exception:
                session = await runner.session_service.create_session(
                    app_name=app_name, user_id=user_id
                )

        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=user_message)],
        )

        final_response = ""
        try:
            async for event in runner.run_async(
                user_id=user_id, session_id=session.id, new_message=content
            ):
                if hasattr(event, "content") and event.content and event.content.parts:
                    for part in event.content.parts:
                        if hasattr(part, "text") and part.text:
                            final_response += part.text
            return final_response, session
        except Exception as e:
            if attempt < max_attempts - 1 and any(
                k in str(e) or k in type(e).__name__ for k in ("429", "RESOURCE_EXHAUSTED", "ResourceExhausted")
            ):
                wait_sec = (attempt + 1) * 8
                print(f"Rate limited (429), waiting {wait_sec}s before retrying...")
                await asyncio.sleep(wait_sec)
                session = None
            else:
                raise e
