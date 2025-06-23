import os
import json
from dotenv import load_dotenv
import psycopg2
from sentence_transformers import SentenceTransformer

# Load environment variables
load_dotenv()
conn = psycopg2.connect(os.getenv("DB_URL"))
cursor = conn.cursor()

# Load JSON data
with open("complaints.json", "r") as f:
    data = json.load(f)

# Clear the table
cursor.execute("DELETE FROM complaints;")
conn.commit()

# Load model
model = SentenceTransformer('paraphrase-MPNet-base-v2')

# Insert all complaints with embeddings
for item in data:
    situation = item["situation"]
    solution = item["solution"]
    db_embedding = model.encode(situation).tolist()

    cursor.execute(
        "INSERT INTO complaints (situation, solution, embedding) VALUES (%s, %s, %s);",
        (situation, solution, db_embedding)
    )
    print("Inserted:", situation)

conn.commit()
cursor.close()
conn.close()
print("All complaints embedded and saved.")
