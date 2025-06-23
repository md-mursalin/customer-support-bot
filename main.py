from chatbot.bot import get_bot_response

def main():
    while True:
        query = input("You : ")
        if query.lower() == "exit":
            break
        print("Bot : ", get_bot_response(query))

if __name__ == "__main__":
    main()
