import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)
client = OpenAI(base_url="https://openrouter.ai/api/v1",
                api_key=os.environ["OPENROUTER_API_KEY"])
MODEL = "anthropic/claude-haiku-4.5"   # check exact name on openrouter.ai/models
r = client.chat.completions.create(
    model=MODEL, max_tokens=20,
    messages=[{"role": "user", "content": "Reply with exactly: OK"}],
)
print(r.choices[0].message.content)