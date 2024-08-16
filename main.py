from resk.openai_protector import OpenAIProtector
from openai import OpenAI

# Initialiser le client OpenAI
client = OpenAI(api_key="sk-proj-9TXQW53Z4fmGQTWlfHHiT3BlbkFJ34Jj04d2opnu1uYwHE5u")

# Initialiser le protecteur
protector = OpenAIProtector(model="gpt-4o-mini", preserved_prompts=2)

# Définir les messages
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Who won the world series in 2020?"},
    {"role": "assistant", "content": "The Los Angeles Dodgers won the World Series in 2020."},
    {"role": "user", "content": "Where was it played?"}
]

# Utiliser le protecteur pour sécuriser l'appel à l'API
response = protector.protect_openai_call(
    client.chat.completions.create,
    model="gpt-4o-mini",
    messages=messages
)

# Afficher la réponse
print(response.choices[0].message.content)