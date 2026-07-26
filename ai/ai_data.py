import json
import os

DATA_FILE = "ai/analysis.json"


def save_analysis(result):

    os.makedirs("ai", exist_ok=True)

    with open(DATA_FILE, "w") as f:
        json.dump(result, f, indent=4)


def load_analysis():

    if not os.path.exists(DATA_FILE):
        return {}

    with open(DATA_FILE) as f:
        return json.load(f)