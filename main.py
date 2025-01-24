import ollama_api_wrapper

def prompt_marco_o1_model(prompt_text):
    apiWrapper = ollama_api_wrapper.OllamaAPIWrapper(base_url='http://localhost:11434')

    payload = {
        "model": "marco-o1",
        "stream": False,
        "prompt": prompt_text
    }

    response = apiWrapper.post('api/generate', payload)

    print(response)

if __name__ == "__main__":
    prompt_text = "1+1?"
    result = prompt_marco_o1_model(prompt_text)
    print(result)