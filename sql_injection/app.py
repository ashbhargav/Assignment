import sqlite3
import os
from flask import Flask, request, render_template

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'users.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user'
        );
        INSERT OR IGNORE INTO users (username, password, role) VALUES
            ('admin', 'password', 'admin'),
            ('alice', 'alice_123',   'user'),
            ('bob',   'bob_234',     'user');
    ''')
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/vulnerable', methods=['GET', 'POST'])
def vulnerable():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: input is dropped straight into an f-string that becomes the SQL query.
        # A single quote in `username` terminates the string literal early, letting the
        # attacker append extra SQL — e.g., ' OR '1'='1' -- comments out the password check.
        query = (
            f"SELECT * FROM users "
            f"WHERE username = '{username}' "
            f"AND password = '{password}'"
        )

        conn = get_db()
        try:
            row = conn.execute(query).fetchone()
            result = {
                'success': row is not None,
                'query':   query,
                'user':    dict(row) if row else None,
            }
        except Exception as exc:
            result = {'success': False, 'query': query, 'error': str(exc)}
        finally:
            conn.close()

    return render_template('login.html', mode='vulnerable', result=result)


@app.route('/secure', methods=['GET', 'POST'])
def secure():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', ''        )
        password = request.form.get('password', '')

        # The ? placeholders get bound after the query is compiled by the driver.
        # Values are passed as raw data, so quote characters in the input can't
        # affect the query structure — injection is structurally impossible.
        query_template = "SELECT * FROM users WHERE username = ? AND password = ?"

        conn = get_db()
        row = conn.execute(query_template, (username, password)).fetchone()
        conn.close()

        # build a readable form for the UI to show the template vs actual values
        display_query = (
            f"Template : SELECT * FROM users WHERE username = ? AND password = ?\n"
            f"Params   : ('{username}', '{password}')\n"
            f"Effect   : input is always treated as literal data, never as SQL"
        )

        result = {
            'success': row is not None,
            'query':   display_query,
            'user':    dict(row) if row else None,
        }

    return render_template('login.html', mode='secure', result=result)


if __name__ == '__main__':
    init_db()
    app.run(port=5007, debug=False)
