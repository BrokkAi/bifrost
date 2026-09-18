"""The query helpers: values reach SQL command construction here."""
from sqlite3 import Cursor


def search(term, cursor: Cursor):
    sql = "SELECT * FROM items"
    sql += f" WHERE name = '{term}'"
    cursor.execute(sql)


def search_parameterized(term, cursor: Cursor):
    cursor.execute("SELECT * FROM items WHERE name = ?", (term,))
