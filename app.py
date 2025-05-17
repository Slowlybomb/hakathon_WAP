from flask import Flask, render_template, session, redirect, url_for, g, request, flash
from database import get_db, close_db
from flask_session import Session
from forms import RegistrationFrom
from functools import wraps

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "PIZDA"
Session(app)

@app.route("/", methods=['GET', 'POST'])
def index():
    human_vs_bot_analysis()
    return render_template("index.html")

def read_log(filename):
    inFile = open(filename, "r")
    db = get_db()

    for uline in inFile:
        uline = uline.split()

        ip = uline[0]
        timestamp = uline[3] + " " + uline[4]
        request = uline[5].strip('"')
        resource = uline[6] + uline[7]
        resource = resource.strip('"')
        http_code = uline[8]
        size = uline[9]

        agent = ""
        for i in range(11, len(uline)):
            agent += uline[i]
            agent += " "

        agent = agent.strip('" ')
        
        isBot = False

        if uline[-1] == '+https://openai.com/gptbot)':
            isBot = True
        db.execute("INSERT INTO logfile (ip, timestamp, request, resource, http_code, size, agent, is_bot) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", (ip, timestamp, request, resource, http_code, size, agent, isBot))
    db.commit()
    inFile.close()

def human_vs_bot_analysis():
    db = get_db()
    total_get_requests = db.execute("SELECT COUNT(*) as count FROM logfile WHERE request = 'GET';").fetchone()
    total_post_requests = db.execute("SELECT COUNT(*) as count FROM logfile WHERE request = 'POST';").fetchone()
    print(f"Total GET requests: {total_get_requests[0]}\nTotal POST requests: {total_post_requests[0]}")