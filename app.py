from datetime import datetime, timedelta
from flask import Flask, render_template, session, redirect, url_for, g, request, flash
from database import get_db, close_db
from flask_session import Session
from forms import RegistrationFrom
from functools import wraps
import time
import pandas as pd
import io
import base64
import matplotlib.pyplot as plt

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "PIZDA"
Session(app)


@app.route("/", methods=['GET', 'POST'])
def index():
    return render_template("index.html")


@app.route('/success', methods=['POST'])
def success():
    if request.method == 'POST':
        f = request.files['file'] 
        f.save(f.filename)
        read_log(f.filename)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT ip, COUNT(*) FROM logfile GROUp BY ip")
        rows = cursor.fetchall()
        error_burst_detector()
        # find_above_average_ips()
        requests_per_time()
        return render_template("Analytics.html", name = f.filename, data = rows)  


def generate_pie_chart(ip_data):
    labels, sizes = zip(*ip_data)

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    ax.axis('equal')

    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    plt.close(fig)
    img.seek(0)

    return base64.b64encode(img.getvalue()).decode('utf8')

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
        db.execute("INSERT INTO logfile (ip, timestamp, request, resource, http_code, size, agent, is_bot) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                   (ip, timestamp, request, resource, http_code, size, agent, isBot))
    db.commit()
    inFile.close()


def human_vs_bot_analysis():
    db = get_db()
    total_get_requests = db.execute(
        "SELECT COUNT(*) as count FROM logfile WHERE request = 'GET';").fetchone()
    total_post_requests = db.execute(
        "SELECT COUNT(*) as count FROM logfile WHERE request = 'POST';").fetchone()
    total_get_requests_hum = db.execute("SELECT COUNT(*) as count FROM logfile WHERE request = 'GET' AND is_bot = 0;").fetchone()
    total_post_requests_hum = db.execute("SELECT COUNT(*) as count FROM logfile WHERE request = 'POST' AND is_bot = 0;").fetchone()
    return {
        "total_get":total_get_requests,
        "total_post":total_post_requests,
        "total_get_human":total_get_requests_hum,
        "total_post_human":total_post_requests_hum
        }


def error_burst_detector():
    """
    Detects 'error bursts' — defined as 3 or more error responses (HTTP 4xx or 5xx)
    from the same IP address occurring within a 1-minute window.
    Returns a list of dictionaries containing the IP, start time of the burst, and the error count.
    """
    db = get_db()
    # Step 1: Query all error status codes (4xx and 5xx) with associated timestamps and IPs
    rows = db.execute("""
        SELECT ip, timestamp, http_code 
        FROM logfile 
        WHERE http_code LIKE '4%' OR http_code LIKE '5%';
    """).fetchall()

    # Step 2: Load query results into a pandas DataFrame for efficient processing
    df = pd.DataFrame(rows, columns=['ip', 'timestamp', 'http_code'])

    # Step 3: Clean and convert the timestamp string to pandas datetime format
    # Timestamps are in Apache format: '[17/Apr/2025:05:14:29 +0100]'
    df['timestamp'] = df['timestamp'].str.strip('[]').str.split().str[0]
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S')

    results = []

    # Step 4: Group the DataFrame by IP address
    for ip, group in df.groupby('ip'):
        # Sort each IP group chronologically
        group = group.sort_values('timestamp')
        times = group['timestamp'].values

        # Step 5: Sliding window to find 3 or more errors within a 60-second period
        for i in range(len(times)):
            count = 1
            j = i + 1
            while j < len(times) and (times[j] - times[i]).astype('timedelta64[s]').astype(int) <= 60:
                count += 1
                j += 1
            if count >= 3:
                results.append({
                    'ip': ip,
                    'start_time': times[i],
                    'error_count': count
                })
                break  # Report only the first burst per IP
    return results


def parse_apache_time(timestamp):
    # Strip the brackets and timezone if needed
    timestamp = timestamp.strip("[]")
    dt_part = timestamp.split()[0]  # e.g. '17/Apr/2025:05:14:29'
    return datetime.strptime(dt_part, "%d/%b/%Y:%H:%M:%S")


def get_ip_count():
    db = get_db()
    ip_dict = {}
    ips = db.execute("""
        SELECT ip, COUNT(ip) FROM logfile GROUP BY ip;
    """).fetchall()

    for ip in ips:
        ip_dict[ip[0]] = ip[1]

    ip_dict = dict(
        sorted(ip_dict.items(), key=lambda item: item[1], reverse=True))
    print(ip_dict)
    return ip_dict

def find_above_average_ips():
    ips = get_ip_count()
    above_average_ips = []

    num_ips = len(ips)
    total_visits = 0
    for ip in ips.values():
        total_visits += ip
    
    average_visits = total_visits / num_ips
    average_visits += (average_visits * 0.5) # Increasing average by 50% since we are only interested in addresses that visit much more than average
    for ip in ips:
        if ips[ip] > average_visits:
            above_average_ips.append(ip)
    return above_average_ips

def requests_per_time():
    """
    Calculates and prints the number of HTTP requests per day from the Apache log stored in the database.
    - Parses timestamps from the logfile table.
    - Extracts the date portion only (ignores time and timezone).
    - Aggregates and prints total requests for each day.

    Return:  req_counter{date : amount of requests}
    """

    db = get_db()
    # Step 1: Fetch all raw timestamp strings from the log table
    rows = db.execute("SELECT timestamp FROM logfile;").fetchall()
    # Step 2: Prepare a dictionary to hold request counts grouped by date
    req_counter = {}
    for row in rows:
        # Example raw timestamp: '[17/Apr/2025:05:14:29 +0100]'
        raw_ts = row[0].strip("[]")               # Remove brackets
        dt_str = raw_ts.split()[0]                # Remove timezone offset, keep datetime part
        # Step 3: Convert the cleaned string to a datetime object
        dt = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S")
        # Step 4: Truncate the datetime to just the date (year-month-day)
        day = dt.date()
        # Step 5: Count number of requests per day
        if day in req_counter:
            req_counter[day] += 1
        else:
            req_counter[day] = 1
    # Step 6: Print the request count per day in chronological order
    if __name__ == "main":
        for day in sorted(req_counter.keys()):
            print(f"{day} - {req_counter[day]} requests")