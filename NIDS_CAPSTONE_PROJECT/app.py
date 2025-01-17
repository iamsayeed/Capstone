from flask import Flask, render_template, redirect, url_for
from db_setup import TrafficLog, AttackLog, session

app = Flask(__name__)

@app.route("/")
def dashboard():
    return redirect(url_for("traffic_logs"))

@app.route("/traffic_logs")
def traffic_logs():
    logs = session.query(TrafficLog).all()
    return render_template("traffic_logs.html", logs=logs)

@app.route("/attack_logs")
def attack_logs():
    logs = session.query(AttackLog).all()
    return render_template("attack_logs.html", logs=logs)

@app.route("/clear_logs/<log_type>")
def clear_logs(log_type):
    if log_type == "traffic":
        session.query(TrafficLog).delete()
    elif log_type == "attack":
        session.query(AttackLog).delete()
    session.commit()
    return redirect(url_for(f"{log_type}_logs"))

if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True)
