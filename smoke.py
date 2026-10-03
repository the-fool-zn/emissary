from dotenv import load_dotenv
from anthropic import Anthropic

load_dotenv()
r = Anthropic().messages.create(
    model="claude-haiku-4-5-20251001",
    max_tokens=20,
    messages=[{"role": "user", "content": "Reply with exactly: OK"}],
)
print(r.content[0].text)