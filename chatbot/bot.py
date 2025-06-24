import os
from dotenv import load_dotenv
import psycopg2
from sentence_transformers import SentenceTransformer
import ollama

# Load environment variables
load_dotenv()

# Load embedding model once globally
model = SentenceTransformer('paraphrase-MPNet-base-v2')

def get_bot_response(user_input):
    # Connect to DB
    conn = psycopg2.connect(os.getenv("DB_URL"))
    cursor = conn.cursor()

    # Create embedding from user input
    text_embedding = model.encode(user_input).tolist()

    # Use cosine similarity 
    cursor.execute(
        """
        SELECT situation, solution, (1 - (embedding <=> %s::vector)) AS similarity
        FROM complaints
        ORDER BY similarity DESC
        LIMIT 1;
        """,
        (text_embedding,)
    )

    result = cursor.fetchone()

    if result:
        situation, solution, similarity = result

        # print(f"[DEBUG] Similarity: {similarity:.4f}")  

        # If similarity is too low, fallback
        if similarity < 0.5:
            fallback = "Sorry, I couldn't find anything similar in the complaints database. Try rephrasing."
            cursor.execute(
                """
                INSERT INTO chat_history (user_id, message, response)
                VALUES (%s, %s, %s);
                """,
                ('guest', user_input, fallback)
            )
            conn.commit()
            cursor.close()
            conn.close()
            return fallback

        # Otherwise, proceed with LLM
        prompt = f"""The user said: "{user_input}".
The most similar known complaint is: "{situation}".
The stored solution is: "{solution}".

Now please respond to the user in a helpful and friendly way and very briefly."""

        response = ollama.chat(
            model='mistral',
            messages=[{'role': 'user', 'content': prompt}]
        )
        bot_reply = response['message']['content']

        # Save to history
        cursor.execute(
            """
            INSERT INTO chat_history (user_id, message, response)
            VALUES (%s, %s, %s);
            """,
            ('guest', user_input, bot_reply)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return bot_reply

    # Rare: no result at all
    fallback = "Sorry, I couldn't find anything similar in the complaints database. Try rephrasing."
    cursor.execute(
        """
        INSERT INTO chat_history (user_id, message, response)
        VALUES (%s, %s, %s);
        """,
        ('guest', user_input, fallback)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return fallback
