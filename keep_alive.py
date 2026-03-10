from flask import Flask
from threading import Thread

app = Flask(__name__)

@app.route('/')
def home():
    return "OSINT Bot is running", 200

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run)
    t.daemon = True
    t.start()
