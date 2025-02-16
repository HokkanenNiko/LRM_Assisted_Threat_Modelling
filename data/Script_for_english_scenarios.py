import json
import pandas as pd

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
      \"RiskType\": \"[Real/Potential]\"
      },'''

df = pd.read_excel('english_examples.xlsx')
# Create conversations list
scenarios = []

for index, row in df.iterrows():
    # Create a single scenario
    scenario = {
        "messages": [
            { 
                "role": "system",
                "content": system_message_reformat
            },
            {
                "role": "user",
                "content": row['User']
            },

            {
                "role": "assistant",
                "content": json.dumps([{
                    'extended': row['Assistant - Extended'],
                    'short': row['Assistant - Short'],
                    'details': row['Assistant - Details'],
                    'risk_id': row['Assistant - Risk ID'],
                    'risk_description': row['Assistant - Risk description'],
                    'vulnerability': row['Assistant - Vulnerability ID'],
                    'vulnerability_description': row['Assistant - Vulnerability description'],
                    'risk_occurrence': row['Assistant - Risk occurrence type']
                }], ensure_ascii=False)
            }
        ]
    }
    
    # Add the conversation to the list
    scenarios.append(json.dumps(scenario, ensure_ascii=False))

# save the scenarios to a jsonl file
with open('scenarios.jsonl', 'w', encoding='utf-8') as f:
    for scenario in scenarios:
        f.write(scenario + '\n')

# Read the scenarios from the jsonl file
scenarios = []
with open('scenarios.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        scenarios.append(json.loads(line))


# Calculate split indices
train_size = int(0.7 * len(scenarios))

# Split into training and validation sets
training_scenarios = scenarios[:train_size]
validation_scenarios = scenarios[train_size:]

# Save training data
with open('training.jsonl', 'w', encoding='utf-8') as f:
    for scenario in training_scenarios:
        f.write(json.dumps(scenario, ensure_ascii=False) + '\n')

# Save validation data  
with open('validation.jsonl', 'w', encoding='utf-8') as f:
    for scenario in validation_scenarios:
        f.write(json.dumps(scenario, ensure_ascii=False) + '\n')
