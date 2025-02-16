import json

def read_lines_to_json(lines):
    json_data = []
    for line in lines:
        try:
            json_data.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"Error decoding line: {line}")
    return json_data

def extract_risk_data(data):
    extracted_data = []
    
    for entry in data:
        risk_scenario = entry.get("risk_scenario", "")
        result = entry.get("result", "")
        
        try:
            # Extract JSON data from result string
            if result.startswith("```json"):
                result_json = json.loads(result.strip("```json\n"))
            else:
                result_json = json.loads(result)
            
            if isinstance(result_json, dict):
                # no risks. Add to list for unified handling
                result_json = [result_json]
            
            for risk in result_json:
                extracted_data.append({
                    "RiskScenario": risk_scenario,
                    "RiskScenarioShort": risk_scenario.split(':')[0] if ':' in risk_scenario else risk_scenario,
                    "Reasoning": risk.get("Reasoning", ""),
                    "Short": risk.get("Short", ""),
                    "Details": risk.get("Details", ""),
                    "RiskID": risk.get("RiskID", ""),
                    "RiskDesc": risk.get("RiskDesc", ""),
                    "VulnID": risk.get("VulnID", ""),
                    "VulnDesc": risk.get("VulnDesc", ""),
                    "RiskType": risk.get("RiskType", ""),
                })
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON for entry: {entry} exception:{e}")
            
    return extracted_data