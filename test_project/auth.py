import database


def login(username, password):
    """Simulates user authentication using the database module."""
    db = database.get_db()
    return f"User {username} authenticated with {db['db_name']}"
