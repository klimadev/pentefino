"""Gemini AI wrapper — reads key from GEMINI_API_KEY env var."""

import json
import os
import re

from dotenv import load_dotenv

load_dotenv()


def get_client():
    """Return genai.Client using GEMINI_API_KEY env var."""
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError(
            "GEMINI_API_KEY not set. "
            "Get a key at https://aistudio.google.com/apikey\n"
            '  export GEMINI_API_KEY="your-key-here"'
        )
    from google import genai

    return genai.Client(api_key=key)


_DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")


async def analyze_image(image_bytes: bytes, prompt: str, model: str | None = None) -> dict | None:
    """Send image + prompt to Gemini Vision, return parsed JSON."""
    from google.genai import types

    try:
        client = get_client()
        response = client.models.generate_content(
            model=model or _DEFAULT_MODEL,
            contents=[prompt, types.Part.from_bytes(data=image_bytes, mime_type="image/png")],
            config={"response_mime_type": "application/json"},
        )
        text = response.text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        return json.loads(text)
    except Exception:
        return None
