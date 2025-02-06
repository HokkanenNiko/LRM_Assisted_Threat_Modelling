import ollama_api_wrapper
import vector_search
import os
import pandas as pd
import time
import datetime
import file_operations
import json

def prompt_model(prompt_text, system_prompt):
    apiWrapper = ollama_api_wrapper.OllamaAPIWrapper(base_url='http://localhost:11434')

    payload = {
        "model": 'marco-o1:latest',
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
      Always respond with an array of valid JSON output in the following format:
      {
      \"Reasoning"\: \"[Extended reasoning]\",
      \"Short\":	 \"[Vulnerability Present: YES/NO/MORE]\",
      \"Details\": \"[Vulnerability Description]\",
      \"RiskID\":	\"[Risk ID]\",
      \"RiskDesc\": \"[Risk Description]\",
      \"VulnID\":	\"[Vulnerability ID]\",
      \"VulnDesc\": \"[Vulnerability Description]\",
      \"RiskType\": \"[Real/Potential]\"
      },
      NOTE: YOU MUST NEVER INCLUDE MORE THAN ONE RISK OR VULNERABILITY IN A SINGLE JSON ITEM. EACH ITEM MUST BE A SINGLE VULNERABILITY AND RISK MAPPING. PRODUCE MULTIPLE JSON ITEMS IF YOU FIND MULTIPLE VULNERABILITIES!
      '''

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
      Always respond with an array of valid JSON output, for each vulnerability you find, create an item as the following and put into an array of json:
      {
      \"Reasoning"\: \"[Reasoning]\",
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

def print_response(system_message:str, model_prompt:str, result:str):
    response_data = {
        "system_message": system_message,
        "model_prompt": model_prompt,
        "result": result
    }
    jsonl_line = json.dumps(response_data)
    print(jsonl_line)

if __name__ == "__main__":
    use_rag = False
    use_files_in_context = True
    process_scenarios = True

    if(process_scenarios):
        risk_scenarios = file_operations.get_unique_scenarios_from_csv("Inputs/Scenarios.csv")
    else:
        risk_scenario = "The CIS System services are managed based on user access rights, identification and assignment of access rights are managed directly by the system users."
        risk_scenarios = [risk_scenario]

    if(use_files_in_context):
        threats_content = file_operations.read_file_contents("ContextInfo/Threats.csv")
        vulnerabilities_content = file_operations.read_file_contents("ContextInfo/Vulnerabilities.csv")
        system_prompt = system_message + "\n\nUse the associated threats table for RiskIDs:\n" + threats_content + "\n\nUse the associated vulnerabilities table for VulnIDs:\n" + vulnerabilities_content
    else:
        system_prompt = system_message
        
    output_file_path = f"Outputs/Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    with open(output_file_path, "a", encoding="utf-8") as file:
        jsonl_line = json.dumps({"system_prompt": system_prompt})
        file.write(f"{jsonl_line}\n")
    counter = 0 
    for risk_scenario in risk_scenarios:
        counter += 1
        print(f"Processing scenario {counter}/{len(risk_scenarios)}")
        if(use_rag):
            system_prompt = system_message_rag_custom
            risk_scenario = initialize_rag_and_fetch_context(risk_scenario)

        start_time = time.time()
        result = prompt_model(risk_scenario, system_prompt)
        elapsed_time = time.time() - start_time
        print(f"Elapsed time for model prompt: {elapsed_time:.2f} seconds")
        print_response("", risk_scenario, result)
        with open(output_file_path, "a", encoding="utf-8") as file:
            jsonl_line = json.dumps({"risk_scenario": risk_scenario, "result": result})
            file.write(f"{jsonl_line}\n")
