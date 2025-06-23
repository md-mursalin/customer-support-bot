import os
import json
from dotenv import load_dotenv
import psycopg2
from sentence_transformers import SentenceTransformer

# Load environment variables from .env
load_dotenv()
conn = psycopg2.connect(os.getenv("DB_URL"))
cursor = conn.cursor()

model = SentenceTransformer('paraphrase-MPNet-base-v2')  # embedding model 768

# 3. Hardcoded user-like input for testing purpose for now...
text = "My eyes are hurting"

# Creating the embedding of user input
text_embedding = model.encode(text).tolist()

# 4. Vector similarity search in the complaints table
cursor.execute(
    """
    SELECT situation, solution
    FROM complaints
    ORDER BY embedding <#> %s::vector
    LIMIT 1;
    """,
    (text_embedding,)
)

# 5. Get and display the result
result = cursor.fetchone()
if result:
    situation, solution = result
    print("Your Problem : ", text)
    print("Bot Solution:", solution)
else:
    print("No similar complaint found.")

# 6. Clean up
cursor.close()
conn.close()
