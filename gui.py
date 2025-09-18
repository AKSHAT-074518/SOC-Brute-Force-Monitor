import tkinter as tk
from tkinter import ttk, messagebox
import datetime
from detector import BruteForceDetector

class SOCLoginGUI:
    def __init__(self):
        print("🎨 Initializing GUI...")
        self.root = tk.Tk()
        self.root.title("🛡️ SOC Brute Force Detection Tool")
        self.root.geometry("1000x800")
        self.root.configure(bg='#2c3e50')
        
        # Initialize detector
        self.detector = BruteForceDetector()
        
        # Setup GUI
        self.setup_gui()
        print("✅ GUI initialized successfully!")
        
    def setup_gui(self):
        """Setup main GUI components"""
        # Main title
        title_frame = tk.Frame(self.root, bg='#2c3e50')
        title_frame.pack(fill=tk.X, pady=10)
        
        title_label = tk.Label(title_frame, 
                              text="🛡️ SOC Brute Force Detection Tool", 
                              font=('Arial', 20, 'bold'), 
                              bg='#2c3e50', 
                              fg='#ecf0f1')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, 
                                 text="Security Operations Center - Login Monitoring System", 
                                 font=('Arial', 12), 
                                 bg='#2c3e50', 
                                 fg='#bdc3c7')
        subtitle_label.pack()
        
        # Main container with white background
        main_container = tk.Frame(self.root, bg='white')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create sections
        self.create_login_section(main_container)
        self.create_status_section(main_container)
        self.create_stats_section(main_container)
        self.create_attempts_monitor(main_container)
        self.create_history_section(main_container)
        self.create_control_buttons(main_container)
    
    def create_login_section(self, parent):
        """Create login simulation section"""
        login_frame = ttk.LabelFrame(parent, text="🔐 Login Simulation Panel", padding="20")
        login_frame.pack(fill=tk.X, pady=10)
        
        # Create grid layout
        # Username row
        ttk.Label(login_frame, text="👤 Username:", font=('Arial', 11, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=8)
        self.username_entry = ttk.Entry(login_frame, width=30, font=('Arial', 11))
        self.username_entry.grid(row=0, column=1, padx=15, pady=8)
        
        # Password row
        ttk.Label(login_frame, text="🔑 Password:", font=('Arial', 11, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=8)
        self.password_entry = ttk.Entry(login_frame, width=30, show="*", font=('Arial', 11))
        self.password_entry.grid(row=1, column=1, padx=15, pady=8)
        
        # Login button
        self.login_btn = ttk.Button(login_frame, 
                                   text="🚀 Attempt Login", 
                                   command=self.attempt_login,
                                   style='Accent.TButton')
        self.login_btn.grid(row=2, column=0, columnspan=2, pady=20)
        
        # Valid credentials info
        info_frame = tk.Frame(login_frame, bg='#f8f9fa', relief=tk.RIDGE, bd=1)
        info_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        tk.Label(info_frame, text="📋 Valid Test Credentials:", 
                font=('Arial', 10, 'bold'), bg='#f8f9fa').pack(anchor=tk.W, padx=10, pady=5)
        
        credentials_text = """• admin / password123    • user1 / welcome    • john / secure123
• test / test123         • demo / demo123"""
        
        tk.Label(info_frame, text=credentials_text, 
                font=('Arial', 9), bg='#f8f9fa', fg='#495057').pack(anchor=tk.W, padx=20, pady=5)
        
        # Bind Enter key to login
        self.username_entry.bind('<Return>', lambda e: self.attempt_login())
        self.password_entry.bind('<Return>', lambda e: self.attempt_login())
    
    def create_status_section(self, parent):
        """Create status display section"""
        status_frame = ttk.LabelFrame(parent, text="📊 System Status", padding="15")
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_label = tk.Label(status_frame, 
                                   text="🟢 System Ready - Monitoring login attempts...", 
                                   font=('Arial', 12, 'bold'), 
                                   fg='#27ae60', 
                                   bg='white', 
                                   relief=tk.RIDGE, 
                                   bd=2, 
                                   padx=15, 
                                   pady=10)
        self.status_label.pack(fill=tk.X)
    
    def create_stats_section(self, parent):
        """Create statistics section"""
        stats_frame = ttk.LabelFrame(parent, text="📈 Security Statistics", padding="15")
        stats_frame.pack(fill=tk.X, pady=10)
        
        # Create stats labels
        stats_container = tk.Frame(stats_frame)
        stats_container.pack(fill=tk.X)
        
        self.total_attempts_label = tk.Label(stats_container, text="Total Attempts: 0", 
                                           font=('Arial', 10), bg='#e3f2fd', padx=10, pady=5)
        self.total_attempts_label.pack(side=tk.LEFT, padx=5)
        
        self.failed_attempts_label = tk.Label(stats_container, text="Failed Attempts: 0", 
                                            font=('Arial', 10), bg='#ffebee', padx=10, pady=5)
        self.failed_attempts_label.pack(side=tk.LEFT, padx=5)
        
        self.locked_accounts_label = tk.Label(stats_container, text="Locked Accounts: 0", 
                                            font=('Arial', 10), bg='#fff3e0', padx=10, pady=5)
        self.locked_accounts_label.pack(side=tk.LEFT, padx=5)
        
        self.success_rate_label = tk.Label(stats_container, text="Success Rate: 0%", 
                                         font=('Arial', 10), bg='#e8f5e8', padx=10, pady=5)
        self.success_rate_label.pack(side=tk.LEFT, padx=5)
    
    def create_attempts_monitor(self, parent):
        """Create failed attempts monitor"""
        attempts_frame = ttk.LabelFrame(parent, text="⚠️ Failed Attempts Monitor", padding="15")
        attempts_frame.pack(fill=tk.X, pady=10)
        
        # Create treeview
        columns = ('Username', 'Failed Count', 'Status', 'Last Attempt', 'Risk Level')
        self.attempts_tree = ttk.Treeview(attempts_frame, columns=columns, show='headings', height=5)
        
        # Configure columns
        self.attempts_tree.heading('Username', text='👤 Username')
        self.attempts_tree.heading('Failed Count', text='📊 Failed Count')
        self.attempts_tree.heading('Status', text='🔒 Account Status')
        self.attempts_tree.heading('Last Attempt', text='⏰ Last Attempt')
        self.attempts_tree.heading('Risk Level', text='⚠️ Risk Level')
        
        # Set column widths
        self.attempts_tree.column('Username', width=120)
        self.attempts_tree.column('Failed Count', width=100)
        self.attempts_tree.column('Status', width=120)
        self.attempts_tree.column('Last Attempt', width=120)
        self.attempts_tree.column('Risk Level', width=100)
        
        self.attempts_tree.pack(fill=tk.X)
        
        # Add scrollbar
        attempts_scrollbar = ttk.Scrollbar(attempts_frame, orient=tk.VERTICAL, command=self.attempts_tree.yview)
        self.attempts_tree.configure(yscrollcommand=attempts_scrollbar.set)
    
    def create_history_section(self, parent):
        """Create login history section"""
        history_frame = ttk.LabelFrame(parent, text="📝 Login History (Recent 15 entries)", padding="15")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create treeview with scrollbar
        history_container = tk.Frame(history_frame)
        history_container.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Time', 'Username', 'Status', 'IP Address', 'Result')
        self.history_tree = ttk.Treeview(history_container, columns=columns, show='headings', height=10)
        
        # Configure columns
        self.history_tree.heading('Time', text='⏰ Timestamp')
        self.history_tree.heading('Username', text='👤 Username')
        self.history_tree.heading('Status', text='📊 Status')
        self.history_tree.heading('IP Address', text='🌐 IP Address')
        self.history_tree.heading('Result', text='✅ Result')
        
        # Set column widths
        self.history_tree.column('Time', width=150)
        self.history_tree.column('Username', width=120)
        self.history_tree.column('Status', width=100)
        self.history_tree.column('IP Address', width=130)
        self.history_tree.column('Result', width=120)
        
        # Add scrollbar
        history_scrollbar = ttk.Scrollbar(history_container, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scrollbar.set)
        
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_control_buttons(self, parent):
        """Create control buttons"""
        control_frame = ttk.LabelFrame(parent, text="🎛️ Control Panel", padding="15")
        control_frame.pack(fill=tk.X, pady=10)
        
        button_container = tk.Frame(control_frame)
        button_container.pack()
        
        # Control buttons
        ttk.Button(button_container, text="🔓 Unlock All Accounts", 
                  command=self.unlock_all_accounts).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_container, text="🗑️ Clear History", 
                  command=self.clear_history).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_container, text="💾 Export Report", 
                  command=self.export_data).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_container, text="🔄 Refresh Display", 
                  command=self.refresh_displays).pack(side=tk.LEFT, padx=10)
    
    def attempt_login(self):
        """Handle login attempt"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("⚠️ Input Error", "Please enter both username and password!")
            return
        
        print(f"\n🔍 Processing login attempt for: {username}")
        
        # Disable button during processing
        self.login_btn.config(state='disabled')
        self.root.update()
        
        try:
            # Attempt login
            status, ip_address = self.detector.simulate_login(username, password)
            
            # Update displays
            self.update_status_display(status, username, ip_address)
            self.update_all_displays()
            
            # Clear password field
            self.password_entry.delete(0, tk.END)
            
            # Check for brute force alert
            if status == "FAILED":
                failed_count = len(self.detector.failed_attempts.get(username, []))
                if failed_count >= self.detector.threshold:
                    self.show_brute_force_alert(username, ip_address, failed_count)
            
        except Exception as e:
            print(f"❌ Error during login attempt: {e}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        
        finally:
            # Re-enable button
            self.login_btn.config(state='normal')
    
    def update_status_display(self, status, username, ip_address):
        """Update status display based on login result"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        
        if status == "SUCCESS":
            self.status_label.config(
                text=f"✅ [{timestamp}] Login successful for '{username}' from {ip_address}", 
                fg='#27ae60'
            )
        elif status == "FAILED":
            failed_count = len(self.detector.failed_attempts.get(username, []))
            if failed_count >= self.detector.threshold - 1:
                self.status_label.config(
                    text=f"🚨 [{timestamp}] CRITICAL: '{username}' approaching lockout! ({failed_count}/{self.detector.threshold}) from {ip_address}", 
                    fg='#e67e22'
                )
            else:
                self.status_label.config(
                    text=f"❌ [{timestamp}] Login failed for '{username}' from {ip_address} ({failed_count}/{self.detector.threshold})", 
                    fg='#e74c3c'
                )
        elif status == "LOCKED":
            self.status_label.config(
                text=f"🔒 [{timestamp}] Account '{username}' is LOCKED - Access denied from {ip_address}", 
                fg='#8e44ad'
            )
    
    def show_brute_force_alert(self, username, ip_address, failed_count):
        """Show brute force detection alert"""
        alert_msg = f"""🚨 SECURITY ALERT: BRUTE FORCE ATTACK DETECTED! 🚨

Target Account: {username}
Source IP: {ip_address}
Failed Attempts: {failed_count}
Detection Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

AUTOMATED RESPONSE:
✅ Account automatically locked
✅ Security event logged
✅ SOC team notified

This incident requires immediate investigation."""
        
        messagebox.showerror("🚨 BRUTE FORCE DETECTED", alert_msg)
    
    def update_all_displays(self):
        """Update all display components"""
        self.update_stats_display()
        self.update_attempts_display()
        self.update_history_display()
    
    def update_stats_display(self):
        """Update statistics display"""
        total_attempts = len(self.detector.login_history)
        failed_attempts = sum(1 for entry in self.detector.login_history if entry['status'] == 'FAILED')
        locked_accounts = len(self.detector.locked_accounts)
        success_rate = ((total_attempts - failed_attempts) / total_attempts * 100) if total_attempts > 0 else 0
        
        self.total_attempts_label.config(text=f"Total Attempts: {total_attempts}")
        self.failed_attempts_label.config(text=f"Failed Attempts: {failed_attempts}")
        self.locked_accounts_label.config(text=f"Locked Accounts: {locked_accounts}")
        self.success_rate_label.config(text=f"Success Rate: {success_rate:.1f}%")
    
    def update_attempts_display(self):
        """Update failed attempts monitor"""
        # Clear existing items
        for item in self.attempts_tree.get_children():
            self.attempts_tree.delete(item)
        
        # Add current failed attempts
        for username, attempts in self.detector.failed_attempts.items():
            count = len(attempts)
            status = "🔒 LOCKED" if username in self.detector.locked_accounts else "🔓 Active"
            last_attempt = attempts[-1]['timestamp'].strftime('%H:%M:%S') if attempts else "N/A"
            
            # Determine risk level
            if count >= self.detector.threshold:
                risk_level = "🔴 CRITICAL"
            elif count >= self.detector.threshold - 1:
                risk_level = "🟡 HIGH"
            elif count >= 2:
                risk_level = "🟠 MEDIUM"
            else:
                risk_level = "🟢 LOW"
            
            self.attempts_tree.insert('', 'end', values=(
                username, count, status, last_attempt, risk_level
            ))
    
    def update_history_display(self):
        """Update login history display"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Add recent history (last 15 entries)
        recent_history = self.detector.login_history[-15:]
        for entry in reversed(recent_history):
            # Format status with icons
            if entry['status'] == "SUCCESS":
                status_display = "✅ SUCCESS"
                result = "Allowed"
            elif entry['status'] == "FAILED":
                status_display = "❌ FAILED"
                result = "Denied"
            elif entry['status'] == "LOCKED":
                status_display = "🔒 LOCKED"
                result = "Blocked"
            else:
                status_display = entry['status']
                result = "Unknown"
            
            self.history_tree.insert('', 'end', values=(
                entry['timestamp'],
                entry['username'],
                status_display,
                entry['ip_address'],
                result
            ))
    
    def unlock_all_accounts(self):
        """Unlock all locked accounts"""
        if self.detector.locked_accounts:
            count = len(self.detector.locked_accounts)
            self.detector.locked_accounts.clear()
            self.detector.failed_attempts.clear()
            self.update_all_displays()
            self.status_label.config(text=f"🔓 Successfully unlocked {count} accounts", fg='#27ae60')
            messagebox.showinfo("✅ Accounts Unlocked", f"Successfully unlocked {count} accounts!\nAll failed attempt counters have been reset.")
        else:
            messagebox.showinfo("ℹ️ No Locked Accounts", "No accounts are currently locked.")
    
    def clear_history(self):
        """Clear login history"""
        if messagebox.askyesno("🗑️ Clear History", "Are you sure you want to clear all login history?\n\nThis action cannot be undone."):
            self.detector.login_history.clear()
            self.update_all_displays()
            self.status_label.config(text="🗑️ Login history cleared", fg='#3498db')
    
    def export_data(self):
        """Export data to CSV report"""
        try:
            import csv
            filename = f"SOC_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['Timestamp', 'Username', 'Status', 'IP_Address', 'Notes'])
                
                # Write data
                for entry in self.detector.login_history:
                    notes = ""
                    if entry['status'] == "LOCKED":
                        notes = "Account locked due to brute force"
                    elif entry['status'] == "FAILED":
                        username = entry['username']
                        if username in self.detector.failed_attempts:
                            notes = f"Failed attempt {len(self.detector.failed_attempts[username])}/{self.detector.threshold}"
                    
                    writer.writerow([
                        entry['timestamp'], 
                        entry['username'], 
                        entry['status'], 
                        entry['ip_address'],
                        notes
                    ])
            
            messagebox.showinfo("💾 Export Complete", f"Security report exported successfully!\n\nFile: {filename}")
            print(f"📊 Report exported: {filename}")
            
        except Exception as e:
            messagebox.showerror("❌ Export Error", f"Failed to export data:\n{str(e)}")
    
    def refresh_displays(self):
        """Refresh all displays"""
        self.update_all_displays()
        self.status_label.config(text="🔄 Display refreshed", fg='#3498db')
    
    def run(self):
        """Start the application"""
        print("🚀 Starting SOC Brute Force Detection Tool...")
        print("📊 Ready to monitor login attempts!")
        self.root.mainloop()