import os
from dotenv import load_dotenv
import psycopg2
from sentence_transformers import SentenceTransformer
import ollama

# Load environment variables
load_dotenv()

# Load embedding model once
model = SentenceTransformer('paraphrase-MPNet-base-v2')

def get_bot_response(user_input):
    # Connect to DB
    conn = psycopg2.connect(os.getenv("DB_URL"))
    cursor = conn.cursor()

    # Embed user input
    text_embedding = model.encode(user_input).tolist()

    # Vector search

    # It takes the user's text_embedding (from their complaint), compares it with the 
    # embedding vectors stored in the complaints table, 
    # and returns the most similar situation and its corresponding solution.
    cursor.execute(
        """
        SELECT situation, solution
        FROM complaints
        ORDER BY embedding <#> %s::vector
        LIMIT 1;
        """,
        (text_embedding,)
    )
    result = cursor.fetchone()            # result stores the first row returned by the SQL query — as a Python tuple (situation, solution)

    cursor.close()
    conn.close()

    if result:
        situation, solution = result      # unpacks the tuple from result and stores it in 'situation' and 'solution' variables separately
                                          #Only try to unpack if we actually got a row from the DB (thats why its under if statement cuz it can also return none if the complaints table is empty or something goes wrong
                                    
        prompt = f"""The user said: "{user_input}".
The most similar known complaint is: "{situation}".
The stored solution is: "{solution}".

Now please respond to the user in a helpful, friendly way and very briefly."""
        response = ollama.chat(
            model='mistral',
            messages=[{'role': 'user', 'content': prompt}]
        )
        return response['message']['content']
    else:
        return "Sorry, I couldn't find anything similar in the complaints database. Try rephrasing."
