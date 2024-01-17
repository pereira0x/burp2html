from flask import Flask
from flask import render_template
from flask import request
from bs4 import BeautifulSoup
import os
import base64


app = Flask(__name__)


@app.route("/", methods=['GET', 'POST'])
def main():
    cols = ['Time', 'Url', 'Method', 'Status',
            'Response Length', 'MIME Type', 'Details']
    if request.method == 'POST':
        # Check if the POST request has the file part
        if 'file' not in request.files:
            return render_template('base.html', history_data=[], cols=cols)

        file = request.files['file']

        # Check if the file is selected
        if file.filename == '':
            return render_template('base.html', history_data=[], cols=cols)

        # Save the file to a temporary location
        file_path = os.path.join('/tmp', file.filename)
        file.save(file_path)

        # Parse the XML file
        data = parse_burp_xml(file_path)

        # Render the template with the parsed data
        return render_template('base.html', history_data=data, cols=cols)

    # Render the main page if it's a GET request
    return render_template('base.html', history_data=[], cols=cols)


def parse_burp_xml(xml_file):
    with open(xml_file, 'r') as f:
        file = f.read()
    soup = BeautifulSoup(file, 'xml')
    entries = []
    id = 0
    for item in soup.find_all('item'):
        entry = {}
        entry['id'] = id
        id += 1
        entry['time'] = item.find_all('time')[0].text
        entry['url'] = item.find_all('url')[0].text
        # entry['host'] = item.find_all('host')[0].text
        entry['method'] = item.find_all('method')[0].text
        # entry['path'] = item.find_all('path')[0].text
        entry['req'] = base64.b64decode(item.find_all('request')[
            0].text).decode('utf-8', 'ignore')
        entry['status'] = item.find_all('status')[0].text
        entry['responselength'] = item.find_all('responselength')[0].text
        entry['mimetype'] = item.find_all('mimetype')[0].text
        entry['res'] = base64.b64decode(item.find_all('response')[
            0].text).decode('utf-8', 'ignore')
        entries.append(entry)
    return entries
