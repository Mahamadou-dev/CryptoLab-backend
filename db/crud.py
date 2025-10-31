from .connection import get_db

def save_result(data):
    db = get_db()
    return db.results.insert_one(data)
