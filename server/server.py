import threading
import time
import base64
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from os import path
import smtplib
import socket
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
import pandas as pd
import ssl

def init_db():
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS client 
                 (nClient TEXT PRIMARY KEY, nTables BLOB)''')
    c.execute('''CREATE TABLE IF NOT EXISTS order_details
                 (nBeds INTEGER, nTables INTEGER, nChairs INTEGER, nArmchairs INTEGER, date DATE
                 , nClient INTEGER, FOREIGN KEY(nClient) REFERENCES client(nClient))''')
    conn.commit()
    conn.close()

def addLog(message):
    date = datetime.now().strftime('%m-%Y')
    dir_log = "logs/" + date + '.log'
    date = datetime.now().strftime('%d/%m/%Y')
    if not path.exists(dir_log):
        with open(dir_log, 'x') as f:
            f.write(message + " On day: " + date)
    else:
        with open(dir_log, 'a') as f:
            f.write("\n" + message + " On day: " + date)
 

def verify_signature(signature, public_key_pem, message, nClient):
    public_key = load_pem_public_key(public_key_pem.encode())
    signature = base64.b64decode(signature)
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        addLog('- User ' + nClient + ' message has been corrupted.')
        return False

def check_message(nBeds, nTables, nChairs, nArmchairs, nClient):
    if nBeds <= 300 and nTables <= 300 and nChairs <= 300 and nArmchairs <= 300:
        ten_minutes_ago = datetime.now() - timedelta(minutes=10)
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        query = '''
            SELECT COUNT(*)
            FROM order_details
            WHERE nClient = ?
            AND date >= ?
        '''
        c.execute(query, (nClient, ten_minutes_ago))
        count = c.fetchone()[0]
        conn.close()
        if count < 3:
            return True
        else:
            addLog('- User ' + nClient + ', has done too many requests.')
            return False
    else:
        addLog("- User " + nClient + ', has requested too many materials.')
        return False

def check_client_data(nClient, hashedMessage, message):
    res = False
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute("SELECT rsaKey FROM client WHERE nClient = ?", (nClient,))
    result = c.fetchone()
    conn.close()
    if result != None:
        rsaKey = result[0]
        verified = verify_signature(hashedMessage, rsaKey, message, nClient)
        if verified:
            res = True
    else:
        addLog('- A message from a non-verified user has been recieved.')
    return res

def insert_order_data(nBeds, nTables, nChairs, nArmchairs, nClient):
    date = datetime.now()
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute("INSERT INTO order_details (nBeds, nTables, nChairs, nArmchairs, date, nClient) VALUES (?, ?, ?, ?, ?, ?)",
              (nBeds, nTables, nChairs, nArmchairs, date, nClient))
    conn.commit()
    conn.close()

def sendMonthlyEmail(email):
    def generate_bar_chart(logs):
        data = {'positive': {}, 'negative': {}}
        for l in logs:
            if l != '':
                day = "Day " + l.split()[-1].split("/")[-3]
                if l.startswith('-'):
                    if day in data['negative']:
                        data['negative'][day] += 1
                    else:
                        data['negative'][day] = 1
                else:
                    if day in data['positive']:
                        data['positive'][day] += 1
                    else:
                        data['positive'][day] = 1
        
        days = sorted(list(set(data['positive'].keys()).union(set(data['negative'].keys()))))
        df = pd.DataFrame({
            'Day': days,
            'Positive': [data['positive'].get(day, 0) for day in days],
            'Negative': [data['negative'].get(day, 0) for day in days]
        })

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(df['Day'], df['Positive'], color='blue', label='Correct Orders')
        ax.bar(df['Day'], df['Negative'], color='red', bottom=df['Positive'], label='Incorrect Orders')
        ax.set_ylabel('Request count')
        ax.set_title("Month's summary")
        ax.legend()

        img = BytesIO()
        fig.savefig(img, format='png')
        img.seek(0)
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')
        plt.close(fig)

        total_incidents = sum(df['Negative'])
        total_correct = sum(df['Positive'])
        total_orders = total_incidents + total_correct
        
        return img_base64, total_incidents, total_correct, total_orders

    date = datetime.now().strftime('%m-%Y')
    dir_log = "logs/" + date + ".log"
    sender_email = "insegus.ssii4@hotmail.com"
    receiver_email = email
    password = "Insegus4@"
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = datetime.now().strftime("%B") + "'s monthly report from Insegus."
    
    if path.exists(dir_log):
        with open(dir_log, 'r') as f:
            content = f.read()
        logs = content.split("\n")
        chart, incidents, corrects, total = generate_bar_chart(logs)
        body = f"""
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                    }}
                    h2 {{
                        color: #333333;
                    }}
                    p {{
                        margin-bottom: 10px;
                    }}
                </style>
            </head>
            <body>
                <h2>There has been {total} orders.</h2>
                <h3>{corrects} ordes has been processed correctly.</h3>
                <h3>This month there have been found {incidents} incidents.</h3>
                <img src="data:image/png;base64,{chart}" alt="Bar Chart">
            </body>
        </html>
        """
    else:
        body = "There was no requests this month."

    message.attach(MIMEText(body, 'html'))
    with smtplib.SMTP('smtp.office365.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)

def sendEmailRepeatedly():
    while True:
        email = 'insegus.ssii4@hotmail.com'
        time.sleep(600)
        sendMonthlyEmail(email)

def run_server(port=7070):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.options |= ssl.OP_NO_TLSv1_2
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_TLSv1
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile='server.crt', keyfile='server.key', password='asAS12!"')
    server_socket.bind(('192.168.0.22', port))
    server_socket.listen(5)
    secure_server_socket = context.wrap_socket(server_socket, server_side=True)
    print("Server is waiting for incoming connections...")
    init_db()
    try:
        while True:
            (client_socket, address) = secure_server_socket.accept()
            print(f"Connection from {address} has been established.")
            try:
                signedData = client_socket.recv(1024).decode('latin-1')
                parts = signedData.split('--|--')                
                data = parts[0][2:]
                signature = parts[1][:-1]
                d = data.split('-')
                try:
                    nBeds = int(d[0]) if d[0] != '' else 0
                    nTables = int(d[1]) if d[0] != '' else 0
                    nChairs = int(d[2]) if d[0] != '' else 0
                    nArmchairs = int(d[3]) if d[0] != '' else 0
                    nClient = d[4] if d[0] != '' else 0
                    if check_message(nBeds, nTables, nChairs, nArmchairs, nClient):
                        if check_client_data(nClient, signature, data):
                            insert_order_data(nBeds, nTables, nChairs, nArmchairs, nClient)
                            addLog("+ User " + nClient + "has requested: " + str(nBeds) +" beds, " + str(nTables) + " tables, " + str(nChairs) + " chairs and " + str(nArmchairs) + " armchairs.")
                            confirmation_message = "Order has been successfully placed for user: " + nClient + "."
                            client_socket.send(confirmation_message.encode('latin-1'))
                        else:
                            client_socket.send("Invalid client data.".encode('latin-1'))
                    else:
                        client_socket.send("Too many requests or material limit exceeded.".encode('latin-1'))
                except ValueError:
                    client_socket.send("Error in message format.".encode('latin-1'))
            finally:
                client_socket.close()

    except KeyboardInterrupt:
        server_socket.close()
        print("Server shutting down.")

def main():
    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    email_thread = threading.Thread(target=sendEmailRepeatedly)
    email_thread.start()
    server_thread.join()
    email_thread.join()

if __name__ == '__main__':
    main()
