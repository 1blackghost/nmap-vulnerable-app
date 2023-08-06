from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace this with a strong secret key

# SQLite3 Database Configuration
DATABASE = 'database.db'


# Function to create the users table in the database (if it doesn't exist)
def create_users_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


# Function to add a user to the database with hashed password
def add_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()


# Function to check if the provided username and password are correct
def authenticate_user(username, password):
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
                return True
            else:
                return False
    except sqlite3.Error as e:
        print("Error occurred while authenticating user:", e)
        return False

@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if authenticate_user(username, password):
        session['username'] = username
        return redirect('/dashboard')
    else:
        return "Invalid credentials. Please try again."


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"Welcome, {session['username']}! This is your dashboard."
    else:
        return redirect('/')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')


if __name__ == '__main__':

    app.run(debug=True)
