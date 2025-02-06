import pandas as pd
import os

def write_scenarios_to_file(scenarios: list[str], output_file_path: str):
    """
    Write unique scenarios to a text file.
    
    :param scenarios: List of unique scenarios.
    :param output_file_path: Path to the output text file.
    """
    with open(output_file_path, "w", encoding="utf-8") as file:
        for scenario in scenarios:
            file.write(f"{scenario}\n")

    print(f"Successfully wrote unique scenarios to {output_file_path}")

def get_unique_scenarios_from_csv(csv_file_path: str) -> list[str]:
    """
    Get unique scenarios from a CSV file.
    
    :param csv_file_path: Path to the input CSV file.
    :return: List of unique scenarios.
    """
    id_col = "Scenario ID"
    name_col = "User"
    desc_col = "Assistant - Extended"

    try:
        # Load the dataset (detect delimiter automatically)
        df = pd.read_csv(csv_file_path, delimiter=';', encoding='utf-8')
        
        # Generate unique scenarios
        unique_scenarios = df.apply(
            lambda row: f"{row[id_col]}: {row[name_col]}", axis=1
        ).unique().tolist()
        
        return unique_scenarios
    except Exception as e:
        print(f"Error: {e}")
        return []

def read_file_contents(path):
    with open(path, "r", encoding="utf-8") as file:
        file_content = file.read()
        return file_content

def read_context_document(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        exit(1)

    with open(file_path, 'r', encoding='utf-8') as file:
        context_text = file.read().strip()
        return context_text