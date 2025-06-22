from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
from werkzeug.utils import secure_filename
import subprocess
import time

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pcap'}

# إنشاء مجلد التحميل إذا لم يكن موجوداً
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
    # هذه بيانات نموذجية - يمكنك جلبها من ملف التحليل الفعلي
    file_info = {
        'filename': 'network_capture.pcap',
        'filesize': '3.5 MB',
        'analysis_time': '10 ثواني',
        'packets_count': '10,231',
        'ip_count': '127',
        'country_count': '14'
    }
    return render_template('results.html', file_info=file_info)

@app.route('/map')
def show_map():
    return send_from_directory('.', 'network_map.html')

if __name__ == '__main__':
    app.run(debug=True)