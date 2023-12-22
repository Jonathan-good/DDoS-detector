import math
from flask import Flask, request, render_template, session, redirect, url_for, g
import sqlite3
from ddos_engine import predict, predict_datalist
import threading
import platform
import subprocess

running_os = platform.platform()

app = Flask(__name__)
# set the random secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

ip_blacklist = []


# keep running this function every 1 second

def check_blacklist(ip):
    global ip_blacklist
    # if the ip is in the blacklist, block the ip

    if ip in ip_blacklist:
        block_ip(ip)
        ip_blacklist.remove(ip)
    threading.Timer(1, check_blacklist).start()


def block_ip(ip):
    # block the ip using iptables
    if "Linux" in running_os:
        subprocess.call(f"iptables -A INPUT -s {ip} -j DROP")
    elif "Windows" in running_os:
        subprocess.call(
            f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in interface=any action=block remoteip={ip}")
    elif "macOS" in running_os:
        subprocess.call(f"sudo ipfw add deny {ip}")


@app.route('/')
def index():
    return render_template('index.html', name=session.get('username', None))


@app.route('/user/<username>')
def show_user_profile(username):
    if session.get('username') == username:
        return render_template('user.html', name=username)
    else:
        return "Forbidden", 403


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # check if the username and password are correct from the sqlite database
        db = getattr(g, '_database', None)
        password = None
        if db is None:
            db = g._database = sqlite3.connect('database/users.db')
            cursor = db.cursor()
            password = cursor.execute('SELECT password FROM users where username = ?', (request.form['username'],))
            password = password.fetchone()

        if password is not None and request.form['password'] == password[0]:
            # set up a session
            session['username'] = request.form['username']
            # redirect to the main page with the session set up
            return redirect(url_for('show_user_profile', username=session.get('username')))
        else:
            return '<h1>Invalid username/password</h1>'
    else:
        return \
            '''
                <h1>Login form</h1>
                <form method="post" enctype="multipart/form-data">
                
                    <p>Username: </p><input type=text name=username placeholder=username>
                    <p>Password: </p><input type=password name=password placeholder=password>
                    <input type=submit value=Login>
                </form>

            '''


@app.route('/detect', methods=['GET'])
def detect():
    if session.get('username') is not None:

        return render_template('detect.html')

    else:
        return redirect(url_for('login'))


def result_text(infos, prediction):
    malicious = 0
    benign = 0
    for each in prediction:
        if each[2] == "NOT a DDOS attack":
            benign += 1
        else:
            malicious += 1
    txt = f"Total: {malicious} Malicious, {benign} Benign<br /><br />"
    for i, data_list in enumerate(infos):
        txt += f"packet {i + 1}:<br /> " + data_list + \
               f"<br /><p style=\"color: {'rgb(25, 156, 95)' if prediction[i][2] == 'NOT a DDOS attack' else 'rgb(233, 76, 91)'}\"" + \
               f">The packet {i + 1} from " + \
               f"{prediction[i][0]} to {prediction[i][1]} is {prediction[i][2]}</p>" + \
               f"<br /><br /><br />"
    return \
            '''
                <h1>DDoS Result</h1>
                <p>''' + txt + '''</p>

                        <a href="/detect">Go Back</a><br /><br />
        '''


@app.route('/detect_form', methods=['POST'])
def detect_form():
    if session.get('username') is not None:
        # get the data from the form

        src = request.form['src']
        dst = request.form['dst']
        pktcount = int(request.form['pktcount'])
        bytecount = int(request.form['bytecount'])
        dur = float(request.form['dur'])
        dur_nsec = int(request.form['dur_nsec'])
        pktrate = int(request.form['pktrate'])
        Protocol = request.form['Protocol']
        port_no = int(request.form['port_no'])
        tx_bytes = int(request.form['tx_bytes'])
        rx_bytes = int(request.form['rx_bytes'])

        data_dict = {
            'src': src,
            'dst': dst,
            'pktcount': pktcount,
            'bytecount': bytecount,
            'dur': dur,
            'dur_nsec': dur_nsec,
            'pktrate': pktrate,
            'Protocol_ICMP': 1 if Protocol == 'ICMP' else 0,
            'Protocol_TCP': 1 if Protocol == 'TCP' else 0,
            'Protocol_UDP': 1 if Protocol == 'UDP' else 0,
            'port_no': port_no,
            'tx_bytes': tx_bytes,
            'rx_bytes': rx_bytes,
        }

        infos, prediction = predict_datalist(data_dict)

        return result_text(infos, prediction)

    else:
        return redirect(url_for('login'))


@app.route('/detect_file', methods=['POST'])
def detect_file():
    if session.get('username') is not None:

        # check if the post request has the file part
        if 'file' not in request.files:
            return '<h1>No file part</h1>'
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return '<h1>No selected file</h1>'
        if file:
            filename = file.filename
            file.save(filename)
            infos, prediction = predict(filename)

            return result_text(infos, prediction)

    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8888)
