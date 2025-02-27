from flask import Flask, jsonify, request
import sqlite3
from flask_httpauth import HTTPBasicAuth
import hashlib

app = Flask(__name__)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()  # Hash the password


authentication = HTTPBasicAuth()

def init_db():
    connection = sqlite3.connect('quiz.db')
    c = connection.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS quiz_questions
                 (id INTEGER PRIMARY KEY, question TEXT, answer TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS quiz_scores
                 (id INTEGER PRIMARY KEY, username TEXT, score INTEGER, total INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    connection.commit()
    connection.close()

@app.before_request
def setup():
    init_db()

def verify_admin_credentials(username, password):
    return username == ADMIN_USERNAME and hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH

@app.route('/admin/add_question', methods=['POST'])
@authentication.login_required
def add_question():
    # Get the data from the request
    data = request.get_json()

    question = data.get("question")
    answer = data.get("answer")

    if not question or not answer:
        return jsonify({"error": "Both 'question' and 'answer' are required"}), 400

    # Add the question to the database
    conn = sqlite3.connect('quiz.db')
    c = conn.cursor()
    c.execute("INSERT INTO quiz_questions (question, answer) VALUES (?, ?)", 
              (question, answer))
    conn.commit()
    conn.close()

    return jsonify({"message": "Question added successfully!"}), 201

@app.route('/admin/delete_question/<int:question_id>', methods=['DELETE'])
@authentication.login_required  # Requires admin authentication
def delete_question(question_id):
    """ Admin can delete a question by ID """
    conn = sqlite3.connect('quiz.db')
    c = conn.cursor()
    
    # Check if the question exists
    c.execute("SELECT * FROM quiz_questions WHERE id = ?", (question_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "Question not found"}), 404

    # Delete the question
    c.execute("DELETE FROM quiz_questions WHERE id = ?", (question_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Question deleted successfully!"}), 200

@authentication.verify_password
def verify_password(username, password):
    conn = sqlite3.connect('quiz.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    if user and user[2] == hashlib.sha256(password.encode()).hexdigest():
        return username

@app.route('/quiz', methods=['GET'])
def get_questions():
    connection = sqlite3.connect('quiz.db')
    c = connection.cursor()
    c.execute("SELECT id, question FROM quiz_questions")
    questions = [{"id": row[0], "question": row[1]} for row in c.fetchall()]
    connection.close()
    return jsonify(questions)

@app.route('/quiz/submit', methods=['POST'])
@authentication.login_required
def check_answer():
    data = request.get_json()
    username = authentication.current_user()
    
    if not isinstance(data, dict):
        return jsonify({"error": "Expected an object with question IDs as keys and answers as values"}), 400

    score = 0
    connection = sqlite3.connect('quiz.db')
    c = connection.cursor()

    for question_id, answer in data.items():
        if not isinstance(question_id, str) or not question_id.isdigit():
            continue  # Skip invalid question IDs

        answer = answer.strip().lower()
        c.execute("SELECT id, answer FROM quiz_questions WHERE id = ?", (question_id,))
        row = c.fetchone()

        if row and answer == row[1].lower():
            score += 1

    c.execute("INSERT INTO quiz_scores (username, score, total) VALUES (?, ?, ?)", (username, score, len(data)))
    connection.commit()
    connection.close()

    return jsonify({"score": score, "total": len(data), "message": "Quiz submitted successfully!"})

@app.route('/scores', methods=['GET'])
@authentication.login_required
def get_scores():
    username = authentication.current_user()
    connection = sqlite3.connect('quiz.db')
    c = connection.cursor()
    c.execute("SELECT score, total, timestamp FROM quiz_scores WHERE username = ? ORDER BY timestamp DESC", (username,))
    scores = [{"score": row[0], "total": row[1], "timestamp": row[2]} for row in c.fetchall()]
    connection.close()
    return jsonify(scores)


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    if not data.get("username") or not data.get("password"):
        return jsonify({"error": "Both 'username' and 'password' are required."}), 400

    username = data["username"]
    password = hashlib.sha256(data["password"].encode()).hexdigest()

    conn = sqlite3.connect('quiz.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "User already exists."}), 400

    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

    return jsonify({"message": "User registered successfully!"}), 201

if __name__ == '__main__':
    app.run(debug=True)
