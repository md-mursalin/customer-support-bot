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
    result = cursor.fetchone()  # result stores the first row returned by the SQL query — as a Python tuple (situation, solution)

    if result:
        situation, solution = result  # unpacks the tuple from result and stores it in 'situation' and 'solution' variables separately
                                      # Only try to unpack if we actually got a row from the DB (that's why it's under if-statement; it can return None if the complaints table is empty or something goes wrong)
                                    
        prompt = f"""The user said: "{user_input}".
The most similar known complaint is: "{situation}".
The stored solution is: "{solution}".

Now please respond to the user in a helpful and friendly way and very briefly."""

        response = ollama.chat(
            model='mistral',
            messages=[{'role': 'user', 'content': prompt}]
        )

        bot_reply = response['message']['content']

        # Save chat history
        cursor.execute(
            """
            INSERT INTO chat_history (user_id, message, response)
            VALUES (%s, %s, %s)
            """,
            ('guest', user_input, bot_reply)  # Change 'guest' if you support real users
        )
        conn.commit()
        cursor.close()
        conn.close()

        return bot_reply

    else:
        # Fallback message when no similar match is found
        fallback = "Sorry, I couldn't find anything similar in the complaints database. Try rephrasing."

        # Also save this chat in history
        cursor.execute(
            """
            INSERT INTO chat_history (user_id, message, response)
            VALUES (%s, %s, %s)
            """,
            ('guest', user_input, fallback)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return fallback
