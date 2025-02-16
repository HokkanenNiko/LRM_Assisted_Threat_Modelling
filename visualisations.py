import pandas as pd
import matplotlib.pyplot as plt
import json

# Load the JSONL file
data = []
file_name = "Results_20250216_172532_results.jsonl"
file_path = "Outputs/" + file_name
with open(file_path, 'r') as file:
    for line in file:
        data.append(json.loads(line))

df = pd.DataFrame(data)

# 1. Overall Accuracy
metrics = {
    'Threat Match': df['threat_match'].mean(),
    'Vulnerability Match': df['vulnerability_match'].mean(),
    'Full Match': df['full_match'].mean(),
    'Partial Match': df['partial_match'].mean()
}

plt.figure(figsize=(8, 6))
plt.bar(metrics.keys(), metrics.values(), color='skyblue')
plt.title('Marco-o1 Model Accuracy Across Metrics')
plt.ylabel('Proportion Correct')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("outputs/" + file_name.replace(".jsonl", "") + "_overall_accuracy.png")
plt.close()

# 2. Scenario-Level Performance
scenario_summary = df.groupby('scenario_id')[['full_match', 'partial_match']].mean()
scenario_summary.plot(kind='bar', figsize=(10, 6), color=['green', 'orange'])
plt.title('Scenario-Level Accuracy')
plt.ylabel('Proportion Correct')
plt.xlabel('Scenario ID')
plt.legend(['Full Match', 'Partial Match'])
plt.xticks(rotation=90)
plt.tight_layout()
plt.savefig("outputs/" + file_name.replace(".jsonl", "") + "_scenario_Level_accuracy.png")
plt.close()

# 3. Accuracy Based on Ground Truth Threat Existence
threat_exists_summary = df.groupby('ground_truth_threat_exists')[['full_match', 'partial_match']].mean()
threat_exists_summary.plot(kind='bar', figsize=(6, 5), color=['blue', 'red'])
plt.title('Accuracy by Threat Existence')
plt.ylabel('Proportion Correct')
plt.xlabel('Ground Truth Threat Exists')
plt.legend(['Full Match', 'Partial Match'])
plt.xticks([0, 1], ['False', 'True'], rotation=0)
plt.tight_layout()
plt.savefig("outputs/" + file_name.replace(".jsonl", "") + "_threat_accuracy.png")
plt.close()
