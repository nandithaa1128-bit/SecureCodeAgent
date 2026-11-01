import sqlite3


def find_user(conn, username):
    query = "SELECT id, email FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()


def delete_user(conn, user_id):
    conn.execute("DELETE FROM users WHERE id = %s" % user_id)
    conn.commit()


def search_products(conn, term):
    sql = f"SELECT * FROM products WHERE title LIKE '%{term}%'"
    return conn.execute(sql).fetchall()


if __name__ == "__main__":
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
    print(find_user(connection, "alice"))
