from google import genai

MODEL = "gemini-3.1-flash-lite"   # if this errors, try "gemini-flash-latest"

client = genai.Client()   # reads GEMINI_API_KEY from your environment

try:
    resp = client.models.generate_content(
        model=MODEL,
        contents="In two sentences, what is a port scan in cybersecurity?",
    )
    print("MODEL:", MODEL)
    print(resp.text)
except Exception as e:
    print("ERROR:", e)