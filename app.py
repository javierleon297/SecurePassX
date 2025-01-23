import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pyperclip
from database import DatabaseManager

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Manager")
        self.root.geometry("1000x600")
        self.db = DatabaseManager()
        self.master_password = None
        
        # Primera ejecución: establecer contraseña maestra
        if self.db.is_first_run():
            self.setup_master_password()
        else:
            if not self.show_login():
                self.root.destroy()
                return
        
        self.configure_styles()
        self.build_ui()
        self.load_entries()
    
    def configure_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.bg_color = "#2d2d2d"
        self.fg_color = "#ffffff"
        self.accent_color = "#3498db"
        
        self.root.configure(bg=self.bg_color)
        self.style.configure("Treeview", 
            background="#3d3d3d",
            foreground=self.fg_color,
            fieldbackground="#3d3d3d",
            borderwidth=0
        )
        self.style.configure("Treeview.Heading", 
            background=self.accent_color,
            foreground=self.fg_color,
            font=('Arial', 10, 'bold')
        )
    
    def build_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Treeview
        self.tree = ttk.Treeview(main_frame, columns=("Title", "Username", "URL"), selectmode="browse")
        self.tree.heading("#0", text="ID", anchor=tk.W)
        self.tree.heading("Title", text="Título")
        self.tree.heading("Username", text="Usuario")
        self.tree.heading("URL", text="URL")
        self.tree.column("#0", width=50, stretch=tk.NO)
        
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, pady=15, sticky="ew")
        
        actions = [
            ("➕ Añadir", self.add_entry, self.accent_color),
            ("✏️ Editar", self.edit_entry, "#f1c40f"),
            ("👁️ Mostrar", self.show_password, "#27ae60"),
            ("📋 Copiar", self.copy_password, "#9b59b6"),
            ("🗑️ Eliminar", self.delete_entry, "#e74c3c")
        ]
        
        for text, cmd, color in actions:
            btn = tk.Button(btn_frame, text=text, command=cmd, 
                           bg=color, fg=self.fg_color, borderwidth=0, padx=12)
            btn.pack(side=tk.LEFT, padx=5)
        
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
    
    def setup_master_password(self):
        password = simpledialog.askstring(
            "Configurar Contraseña Maestra",
            "Crea una nueva contraseña maestra:",
            show="*",
            parent=self.root
        )
        
        if password:
            confirm = simpledialog.askstring(
                "Confirmar Contraseña",
                "Repite la contraseña maestra:",
                show="*",
                parent=self.root
            )
            
            if password == confirm:
                self.db.initialize_master_password(password)
                self.master_password = password
                messagebox.showinfo("Éxito", "¡Contraseña maestra establecida!", parent=self.root)
            else:
                messagebox.showerror("Error", "Las contraseñas no coinciden", parent=self.root)
                self.root.destroy()
    
    def show_login(self):
        """Diálogo de inicio de sesión."""
        password = simpledialog.askstring(
            "Contraseña Maestra",
            "Ingresa tu contraseña maestra:",
            show="*",
            parent=self.root
        )
        
        if password and self.db.verify_master_password(password):
            self.master_password = password
            return True
        else:
            messagebox.showerror("Error", "Contraseña incorrecta", parent=self.root)
            return False
    
    def load_entries(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for entry in self.db.get_all_entries():
            self.tree.insert("", tk.END, iid=entry[0], values=(entry[1], entry[2], entry[3]))
    
    def add_entry(self):
        add_win = tk.Toplevel(self.root)
        add_win.title("Nueva Entrada")
        add_win.configure(bg=self.bg_color)
        
        fields = [
            ("Título:", "title"),
            ("Usuario:", "username"),
            ("Contraseña:", "password"),
            ("URL:", "url")
        ]
        
        entries = {}
        for i, (label, field) in enumerate(fields):
            tk.Label(add_win, text=label, bg=self.bg_color, fg=self.fg_color).grid(row=i, column=0, padx=10, pady=5)
            entry = tk.Entry(add_win, bg="#3d3d3d", fg=self.fg_color, insertbackground=self.fg_color)
            entry.grid(row=i, column=1, padx=10, pady=5)
            entries[field] = entry
        
        # Generar contraseña
        tk.Button(add_win, text="🎲 Generar", 
                 command=lambda: self.generate_and_insert(entries['password']),
                 bg=self.accent_color, fg=self.fg_color).grid(row=2, column=2, padx=5)
        
        # Guardar
        tk.Button(add_win, text="💾 Guardar", 
                 command=lambda: self.save_entry(entries, add_win),
                 bg="#27ae60", fg=self.fg_color).grid(row=4, columnspan=3, pady=10)
    
    def generate_and_insert(self, password_entry):
        password = self.generate_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    
    def save_entry(self, entries, window):
        if all(entry.get() for entry in entries.values()):
            try:
                self.db.add_entry(
                    entries['title'].get(),
                    entries['username'].get(),
                    entries['password'].get(),
                    self.master_password,
                    entries['url'].get()
                )
                self.load_entries()
                window.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=window)
        else:
            messagebox.showerror("Error", "Todos los campos son obligatorios", parent=window)
    
    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Advertencia", "Selecciona una entrada", parent=self.root)
            return
        
        entry_id = int(selected[0])
        old_data = self.db.get_all_entries()[entry_id - 1]  # Asume IDs secuenciales
        
        edit_win = tk.Toplevel(self.root)
        edit_win.title("Editar Entrada")
        edit_win.configure(bg=self.bg_color)
        
        fields = [
            ("Título:", "title", old_data[1]),
            ("Usuario:", "username", old_data[2]),
            ("Contraseña:", "password", ""),
            ("URL:", "url", old_data[3])
        ]
        
        entries = {}
        for i, (label, field, value) in enumerate(fields):
            tk.Label(edit_win, text=label, bg=self.bg_color, fg=self.fg_color).grid(row=i, column=0, padx=10, pady=5)
            entry = tk.Entry(edit_win, bg="#3d3d3d", fg=self.fg_color, insertbackground=self.fg_color)
            entry.insert(0, value)
            entry.grid(row=i, column=1, padx=10, pady=5)
            entries[field] = entry
        
        # Mostrar contraseña actual
        tk.Button(edit_win, text="🔍 Mostrar Actual", 
                 command=lambda: self.show_current_password(entry_id),
                 bg=self.accent_color, fg=self.fg_color).grid(row=2, column=2, padx=5)
        
        # Guardar cambios
        tk.Button(edit_win, text="💾 Guardar Cambios", 
                 command=lambda: self.save_edit(entry_id, entries, edit_win),
                 bg="#27ae60", fg=self.fg_color).grid(row=4, columnspan=3, pady=10)
    
    def show_current_password(self, entry_id):
        try:
            password = self.db.get_password(entry_id, self.master_password)
            messagebox.showinfo("Contraseña Actual", f"Contraseña actual:\n{password}", parent=self.root)
        except:
            messagebox.showerror("Error", "No se pudo recuperar la contraseña", parent=self.root)
    
    def save_edit(self, entry_id, entries, window):
        try:
            self.db.delete_entry(entry_id)
            self.db.add_entry(
                entries['title'].get(),
                entries['username'].get(),
                entries['password'].get(),
                self.master_password,
                entries['url'].get()
            )
            self.load_entries()
            window.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=window)
    
    def show_password(self):
        selected = self.tree.selection()
        if not selected:
            return
        
        entry_id = int(selected[0])
        try:
            password = self.db.get_password(entry_id, self.master_password)
            messagebox.showinfo("Contraseña", f"Contraseña:\n{password}", parent=self.root)
        except:
            messagebox.showerror("Error", "Error al descifrar", parent=self.root)
    
    def copy_password(self):
        selected = self.tree.selection()
        if selected:
            entry_id = int(selected[0])
            try:
                password = self.db.get_password(entry_id, self.master_password)
                pyperclip.copy(password)
                messagebox.showinfo("Éxito", "Contraseña copiada", parent=self.root)
            except:
                messagebox.showerror("Error", "No se pudo copiar", parent=self.root)
    
    def delete_entry(self):
        selected = self.tree.selection()
        if selected and messagebox.askyesno("Confirmar", "¿Eliminar esta entrada?", parent=self.root):
            self.db.delete_entry(int(selected[0]))
            self.load_entries()
    
    @staticmethod
    def generate_password(length=16):
        import secrets
        import string
        chars = string.ascii_letters + string.digits + "!@#$%&*"
        return ''.join(secrets.choice(chars) for _ in range(length))

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()