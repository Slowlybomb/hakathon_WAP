from datetime import datetime, timedelta
from flask import Flask, render_template, session, redirect, url_for, g, request, flash
from database import get_db, close_db
from flask_session import Session
from forms import RegistrationFrom
from functools import wraps
import numpy as np
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
        cursor.execute("SELECT * FROM logfile")
        rows = cursor.fetchall()

        cursor.execute("SELECT ip, COUNT(*)  FROM logfile GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 10")
        ip_data = cursor.fetchall()
        chart1 = generate_bar_chart(ip_data)
        
        error_burst_detector()
        find_above_average_ips()
        return render_template("Analytics.html", name=f.filename, data=rows, chart1=chart1)

def generate_bar_chart(ip_data):
    labels, values = zip(*ip_data)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(labels, values, color='skyblue')
    ax.set_xlabel('Number of Requests and total size')
    ax.set_title('Requests per IP')
    ax.invert_yaxis()

    img = io.BytesIO()
    plt.tight_layout()
    plt.savefig(img, format='png')
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
    db = get_db()
    rows = db.execute(
        "SELECT ip, timestamp, http_code FROM logfile WHERE http_code LIKE '4%' OR http_code LIKE '5%';").fetchall()

    # Convert to DataFrame
    df = pd.DataFrame(rows, columns=['ip', 'timestamp', 'http_code'])
    df['timestamp'] = df['timestamp'].str.strip('[]').str.split().str[0]
    df['timestamp'] = pd.to_datetime(
        df['timestamp'], format='%d/%b/%Y:%H:%M:%S')

    results = []

    for ip, group in df.groupby('ip'):
        group = group.sort_values('timestamp')
        times = group['timestamp'].values

        # Use rolling window: for each row, check if 3+ entries are within 1 minute ahead
        for i in range(len(times)):
            count = 1
            j = i + 1
            while j < len(times) and (times[j] - times[i]).astype('timedelta64[s]').astype(int) <= 60:
                count += 1
                j += 1
            if count >= 3:
                results.append(
                    {'ip': ip, 'start_time': times[i], 'error_count': count})
                break  # Report once per IP

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
    print(ip_dict)


def testing_block():
    from database import get_db
    print("Benchmarking error burst detectors...\n")

    start = time.perf_counter()
    result = error_burst_detector()
    end = time.perf_counter()
    print(
        f"Original version: {len(result)} bursts found in {end - start:.4f} seconds")
    print(result)