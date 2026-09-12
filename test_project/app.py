import auth
import database


def main():
    db = database.get_db()
    print("Database status:", db)
    result = auth.login("admin", "secret123")
    print(result)


if __name__ == "__main__":
    main()
