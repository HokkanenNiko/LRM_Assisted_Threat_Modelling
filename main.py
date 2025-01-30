import ollama_api_wrapper
import vector_search
import os

def prompt_model(prompt_text):
    apiWrapper = ollama_api_wrapper.OllamaAPIWrapper(base_url='http://localhost:11434')

    payload = {
        "model": "deepseek-r1:latest",
        "stream": False,
        "prompt": prompt_text,
        "options": {
            "num_ctx": 8192
        }
    }

    response = apiWrapper.post('api/generate', payload)
    return response['response']

def fetch_context(context, query):
    results = context.search(query, top_k=5)
    return "\n\n---\n\n".join(result['text'] for result in results)

def read_context_document(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        exit(1)

    with open(file_path, 'r', encoding='utf-8') as file:
        context_text = file.read().strip()
        return context_text


def initialize_vector_database(context):
    return vector_search.initialize_vector_database(context)

def format_prompt_text(context, user_query):
    return "start of context:\n\n({})\n\nend of context\n\nstart of query:({})\n\nend of query".format(context, user_query)

if __name__ == "__main__":
    prompt_text = "Tell me about EU declaration of conformity in the context of cyber resilience act"
    context = read_context_document("context.txt")
    vector_db = initialize_vector_database("context.txt")
    context = fetch_context(vector_db, prompt_text)
    prompt_text = format_prompt_text(context, prompt_text)
    result = prompt_model(prompt_text)
    print("context: " + context)
    print("result: " + result)