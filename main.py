from chatbot.bot import get_response

def main():
    while True:
        query = input("Ask your question: ")
        if query.lower() == "exit":
            break
        print("Bot:", get_response(query))

if __name__ == "__main__":
    main()
