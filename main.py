import ollama_api_wrapper
import vector_search
import os
import pandas as pd

def prompt_model(prompt_text, system_prompt):
    apiWrapper = ollama_api_wrapper.OllamaAPIWrapper(base_url='http://localhost:11434')

    payload = {
        "model": "deepseek-r1:latest",
        "stream": False,
        "system": system_prompt,
        "prompt": prompt_text,
        "options": {
            "num_ctx": 128000
        }
    }

    response = apiWrapper.post('api/generate', payload)
    return response['response']

def csv_to_chunked_json(csv_file_path: str, output_json_path: str, id_col: str, name_col: str, desc_col: str):
    """
    Converts a CSV file to a JSON file with chunked text format.
    
    :param csv_file_path: Path to the input CSV file.
    :param output_json_path: Path to the output JSON file.
    :param id_col: Column name for the unique identifier.
    :param name_col: Column name for the item name.
    :param desc_col: Column name for the description.
    """
    try:
        df = pd.read_csv(csv_file_path, delimiter=';', encoding='utf-8')
        
        # Generate chunked text format
        df["chunk"] = df.apply(
            lambda row: f"{id_col}: {row[id_col]}\n{name_col}: {row[name_col]}\n{desc_col}: {row[desc_col]}", axis=1
        )
        
        # Convert to JSON and save
        df[[id_col, "chunk"]].to_json(output_json_path, orient="records", indent=4, force_ascii=False)
        
        print(f"Successfully created chunked JSON file at {output_json_path}")
    except Exception as e:
        print(f"Error: {e}")

def csv_to_chunked_list(csv_file_path: str, id_col: str, name_col: str, desc_col: str) -> list[str]:
    """
    Converts a CSV file to a list of chunked text format.
    
    :param csv_file_path: Path to the input CSV file.
    :param id_col: Column name for the unique identifier.
    :param name_col: Column name for the item name.
    :param desc_col: Column name for the description.
    :return: List of chunked text strings.
    """
    try:
        # Load the dataset (detect delimiter automatically)
        df = pd.read_csv(csv_file_path, delimiter=';', encoding='utf-8')
        
        # Generate chunked text format
        chunks = df.apply(
            lambda row: f"{id_col}: {row[id_col]}\n{name_col}: {row[name_col]}\n{desc_col}: {row[desc_col]}", axis=1
        ).tolist()
        
        return chunks
    except Exception as e:
        print(f"Error: {e}")
        return []
    
def fetch_context(context, query: str):
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
    return "Context based on semantic search:\n\n({})\n\nend of context\n\nstart of risk scenario:({})\n\nend of risk scenario".format(context, user_query)

system_message='''You are an assistant in security risk analysis.
      You need to determine if the current user message contains a security threat.
      If a security threat is present, please explain what the security threat is.
      You must reply with \"more\"  in the \"Short\" field if you think additional details should be provided along with the vulnerability already discovered
      You must reply with \"no\"  in the \"Short\" field  if you think NO vulnerabilities are present
      You must reply with \"yes\"  in the \"Short\" field  if you think there is at least one vulnerability
      You must NEVER HALLUCINATE

      Always respond with an array of valid JSON output, for each vulnerability you find, create an item as the following and put into an array of json:
      {
      \"Extended\": \"[Extended description]\",
      \"Short\":	 \"[Vulnerability Present: YES/NO/MORE]\",
      \"Details\": \"[Vulnerability Description]\",
      \"RiskID\":	\"[Risk ID]\",
      \"RiskDesc\": \"[Risk Description]\",
      \"VulnID\":	\"[Vulnerability ID]\",
      \"VulnDesc\": \"[Vulnerability Description]\",
      \"RiskType\": \"[Reale/Potenziale]\"
      },'''

system_message_rag='''You are an assistant in security risk analysis.
      You need to determine if the current user message contains a security threat.
      If a security threat is present, please explain what the security threat is.
      You must reply with \"more\" if you think additional details should be provided along with the vulnerability already discovered
      You must reply with \"no\"  if you think NO vulnerabilities are present
      You must reply with \"yes\"  if you think there is at least one vulnerability
      You must NEVER HALLUCINATE
      If you think "yes" or "more" You MUST list the identified vulnerability (vulnearbilità) and threat (minaccia) with the appropriate Identifiers refer to the document in your retrieval vectorstore
      For the acronym  refer to the document in your retrieval vectorstore
      Give all the information without asking the user more input
      '''

system_message_rag_custom='''You are an assistant in security risk analysis.
      You need to determine if the current user message contains a security threat.
      If a security threat is present, please explain what the security threat is.
      You must reply with \"more\"  in the \"Short\" field if you think additional details should be provided along with the vulnerability already discovered
      You must reply with \"no\"  in the \"Short\" field  if you think NO vulnerabilities are present
      You must reply with \"yes\"  in the \"Short\" field  if you think there is at least one vulnerability
      You must reply with \"no\" in the \"HelpfulContext\" field if you think the context is not helpful
      You must NEVER HALLUCINATE
      Always respond with an array of valid JSON output, for each vulnerability you find, create an item as the following and put into an array of json:
      {
      \"Extended\": \"[Extended description]\",
      \"Short\":	 \"[Vulnerability Present: YES/NO/MORE]\",
      \"Details\": \"[Vulnerability Description]\",
      \"RiskID\":	\"[Risk ID]\",
      \"RiskDesc\": \"[Risk Description]\",
      \"VulnID\":	\"[Vulnerability ID]\",
      \"VulnDesc\": \"[Vulnerability Description]\",
      \"RiskType\": \"[Reale/Potenziale]\",
      \"HelpfulContext\": \"[HelpfulContext: YES/NO]\"
      },'''


system_message_reformat='''You are an assistant in security risk analysis.
      You need to format the user message as follows
      If a security threat is present, please explain what the security threat is.
      You must reply with \"more\"  in the \"Short\" field if you think additional details should be provided along with the vulnerability already discovered
      You must reply with \"no\"  in the \"Short\" field  if you think NO vulnerabilities are present
      You must reply with \"yes\"  in the \"Short\" field  if you think there is at least one vulnerability
      You must NEVER HALLUCINATE
      If the message ONLY contain "si"/"yes" simply say in the short field "yes", and for the rest leave blank
      If the message ONLY contain "no" simply say in the short field "no", and for the rest leave blank
      Always respond with an array of valid JSON output, for each vulnerability/threat you find, create an item as the following and put into an array of json:
      {
      \"Extended\": \"[Extended description]\",
      \"Short\":	 \"[Vulnerability Present: YES/NO/MORE]\",
      \"Details\": \"[Vulnerability Description]\",
      \"RiskID\":	\"[Risk ID]\",
      \"RiskDesc\": \"[Risk Description]\",
      \"VulnID\":	\"[Vulnerability ID]\",
      \"VulnDesc\": \"[Vulnerability Description]\",
      \"RiskType\": \"[Reale/Potenziale]\"
      },'''

def initialize_rag_and_fetch_context(risk_scenario):
    threat_chunks = csv_to_chunked_list("Threats.csv", "THREAT ID", "THREAT", "DESCRIPTION")
    vulnerability_chunks = csv_to_chunked_list("Vulnerabilities.csv", "ID", "VULNERABILITY", "DESCRIPTION")

    vector_db = vector_search.initialize_vector_database_with_chunks(threat_chunks)
    vector_db = vector_search.add_to_vector_database(vector_db, vulnerability_chunks)

    context = fetch_context(vector_db, risk_scenario)
    prompt_text = format_prompt_text(context, risk_scenario)
    return prompt_text

def print_response(context, result):
    if context:
        print("context: " + context)
    print("result: " + result)

def read_file_contents(path):
    with open(path, "r", encoding="utf-8") as file:
        file_content = file.read()
        return file_content

if __name__ == "__main__":
    risk_scenario = "The combinations of the safety cabinets are written on them in case you forget them."
    context = ""

    use_rag = True
    use_files_in_context = False
    
    if(use_rag):
        system_prompt = system_message_rag_custom
        risk_scenario = initialize_rag_and_fetch_context(risk_scenario)
    elif(use_files_in_context):
        threats_content = read_file_contents("Threats.csv")
        vulnerabilities_content = read_file_contents("Vulnerabilities.csv")
        system_prompt = system_message + "\n\nUse the associated threats table for RiskIDs:\n" + threats_content + "\n\nUse the associated vulnerabilities table for VulnIDs:\n" + vulnerabilities_content
    else:
        system_prompt = system_message
    
    result = prompt_model(risk_scenario, system_prompt)

    print_response(context, result)