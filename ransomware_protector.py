import os
import time
import shutil
import psutil
import smtplib
from email.mime.text import MIMEText
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
MONITOR_FOLDER = r'C:\Path\To\Monitor'  # Folder to protect
BACKUP_FOLDER = r'C:\Path\To\Backup'  # Safe backup location
LOG_FILE = 'ransomware_log.txt'
ALERT_EMAIL = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_app_password'
TELEGRAM_BOT_TOKEN = 'your_bot_token'
TELEGRAM_CHAT_ID = 'your_chat_id'
ALERT_METHOD = 'telegram'  # 'email' or 'telegram'

# Detection thresholds
RAPID_CHANGE_THRESHOLD = 10  # Files changed in this many seconds
RAPID_COUNT = 5  # Number of files to trigger alert
SUSPICIOUS_EXTENSIONS = ['.encrypted', '.locked', '.ransom']  # Extensions to watch

# Global variables for detection
change_times = []
suspicious_processes = []  # List of known ransomware process names (add more)

class RansomwareHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            self.check_file(event.dest_path)
    
    def check_file(self, file_path):
        global change_times
        current_time = time.time()
        change_times.append(current_time)
        
        # Remove old entries (> RAPID_CHANGE_THRESHOLD seconds)
        change_times = [t for t in change_times if current_time - t < RAPID_CHANGE_THRESHOLD]
        
        # Check for rapid changes
        if len(change_times) > RAPID_COUNT:
            self.detect_ransomware(file_path)
        
        # Check for suspicious extensions
        if any(file_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            self.detect_ransomware(file_path)
    
    def detect_ransomware(self, file_path):
        log(f"Ransomware detected on file: {file_path}")
        
        # Backup the file
        self.backup_file(file_path)
        
        # Stop suspicious processes
        self.stop_processes(file_path)
        
        # Send alert
        alert(f"Ransomware Alert: Suspicious activity on {file_path}")
        
        # Optional: Quarantine or delete (commented out for safety)
        # os.remove(file_path)
    
    def backup_file(self, file_path):
        try:
            backup_path = os.path.join(BACKUP_FOLDER, os.path.basename(file_path) + '.bak')
            shutil.copy2(file_path, backup_path)
            log(f"Backed up {file_path} to {backup_path}")
        except Exception as e:
            log(f"Backup failed: {e}")
    
    def stop_processes(self, file_path):
        # Find processes accessing the file (basic check)
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                if proc.info['open_files']:
                    for open_file in proc.info['open_files']:
                        if open_file.path == file_path:
                            proc.kill()
                            log(f"Killed process {proc.info['name']} (PID: {proc.info['pid']})")
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

def log(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(message)

def alert(message):
    if ALERT_METHOD == 'email':
        msg = MIMEText(message)
        msg['Subject'] = 'Ransomware Alert'
        msg['From'] = ALERT_EMAIL
        msg['To'] = ALERT_EMAIL
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(ALERT_EMAIL, EMAIL_PASSWORD)
            server.sendmail(ALERT_EMAIL, ALERT_EMAIL, msg.as_string())
            server.quit()
        except Exception as e:
            log(f"Email alert failed: {e}")
    elif ALERT_METHOD == 'telegram':
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        try:
            requests.post(url, data={'chat_id': TELEGRAM_CHAT_ID, 'text': message})
        except Exception as e:
            log(f"Telegram alert failed: {e}")

def main():
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)
    
    event_handler = RansomwareHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_FOLDER, recursive=True)
    observer.start()
    
    log("Ransomware protector started. Monitoring folder...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
