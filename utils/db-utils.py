import os
from dotenv import load_dotenv
import psycopg2

# Load environment variables
load_dotenv()

def get_connection():
    """
    Returns a psycopg2 connection using DB_URL from .env
    """
    conn_string = os.getenv("DB_URL")
    return psycopg2.connect(conn_string)

def insert_chat(user_id, message, response):
    """
    Inserts a chat record into the chat_history table
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO chat_history (user_id, message, response)
        VALUES (%s, %s, %s);
        """,
        (user_id, message, response)
    )
    conn.commit()
    cursor.close()
    conn.close()

def fetch_similar_complaint(embedding):
    """
    Returns the most similar complaint from the DB based on vector similarity
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT situation, solution
        FROM complaints
        ORDER BY embedding <#> %s::vector
        LIMIT 1;
        """,
        (embedding,)
    )
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result
