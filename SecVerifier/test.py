# from openai import OpenAI

# client = OpenAI(api_key="")

# resp = client.chat.completions.create(
#     model="gpt-4o",
#     messages=[{"role": "user", "content": "Hello"}]
# )

# print(resp.choices[0].message.content)

from litellm import completion
import os

os.environ["OPENAI_API_KEY"] =""

response = completion(
  model="openai/gpt-4o",
  messages=[{ "content": "Hello, how are you?","role": "user"}]
)

print(response)