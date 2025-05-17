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

@app.route('/success', methods = ['POST'])  
def success():  
    if request.method == 'POST':  
        f = request.files['file']
        f.save(f.filename)  
        read_log(f.filename)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM  logfile")
        rows = cursor.fetchall()
        error_burst_detector()
        return render_template("Analytics.html", name = f.filename, data = rows)  

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

from datetime import datetime, timedelta

def error_burst_detector():
    """
    Error burst detector
    Detects errors in log files where error responses from the same IP repeat more than 3 times in one minute
    """
    db = get_db()

    detection_list = []

    ip_list = db.execute("SELECT DISTINCT ip FROM logfile;").fetchall()

    for ip_row in ip_list:
        ip = ip_row[0]
        requests = db.execute(
            "SELECT timestamp, http_code FROM logfile WHERE ip = ? ORDER BY timestamp ASC", (ip,)
        ).fetchall()

        # Filter to only error codes (e.g. 4xx or 5xx)
        error_requests = [(parse_apache_time(row[0]), row[1]) for row in requests if str(row[1]).startswith(('4', '5'))]

        # Sliding window to detect bursts
        for i in range(len(error_requests)):
            count = 1
            start_time = error_requests[i][0]

            for j in range(i+1, len(error_requests)):
                if error_requests[j][0] - start_time <= timedelta(minutes=1):
                    count += 1
                else:
                    break

            if count > 3:
                detection_list.append({
                    'ip': ip,
                    'start_time': start_time.isoformat(),
                    'error_count': count
                })
                break  # Report once per IP
    
    for burst in detection_list:
        print(burst)

    return detection_list

def parse_apache_time(timestamp):
    # Strip the brackets and timezone if needed
    timestamp = timestamp.strip("[]")
    dt_part = timestamp.split()[0]  # e.g. '17/Apr/2025:05:14:29'
    return datetime.strptime(dt_part, "%d/%b/%Y:%H:%M:%S")
    
if __name__ == "main":
    error_burst_detector()

def get_ip_count():
    db = get_db()
    ip_dict = {}
    ips = db.execute("""
        SELECT ip, COUNT(ip) FROM logfile GROUP BY ip;
    """).fetchall()

    for ip in ips:
        ip_dict[ip[0]] = ip[1]

    ip_dict = dict(sorted(ip_dict.items(), key=lambda item: item[1], reverse=True))

    return ip_dict