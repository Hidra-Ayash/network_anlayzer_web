from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
from werkzeug.utils import secure_filename
import subprocess
import time

from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
import json
from werkzeug.utils import secure_filename
import subprocess
import time

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pcap'}
app.config['RESULTS_FOLDER'] = 'results'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)
 

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # معالجة الملف باستخدام البرنامج الرئيسي
        try:
            subprocess.run(['python', 'network_analyzer.py', filepath], check=True)
            time.sleep(2)  # انتظار انتهاء المعالجة
            
            return redirect(url_for('results'))
        except subprocess.CalledProcessError as e:
            return f"Error processing file: {e}", 500
    
    return "Invalid file type", 400

@app.route('/results')
def results():
    try:
        results_file = os.path.join(app.config['RESULTS_FOLDER'], 'analysis_results.json')
        
        # التحقق من وجود الملف
        if not os.path.exists(results_file):
            return render_template('no_results.html')  # أو رسالة خطأ مناسبة
            
        with open(results_file, 'r', encoding='utf-8') as f:
            file_info = json.load(f)
            
        # إضافة تحقق من صحة البيانات
        if not isinstance(file_info, dict):
            raise ValueError("Invalid data format in results file")
            
        return render_template('results.html', file_info=file_info)
        
    except json.JSONDecodeError as e:
        return f"Error decoding JSON: {e}", 500
    except Exception as e:
        return f"Error loading results: {str(e)}", 500

@app.route('/map')
def show_map():
    return send_from_directory('.', 'templates/network_map.html')

if __name__ == '__main__':
    app.run(debug=True)