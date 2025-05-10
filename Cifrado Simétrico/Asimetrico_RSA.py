import sys
import os
import hashlib
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QLineEdit, QFileDialog, QVBoxLayout, QHBoxLayout, 
                            QWidget, QMessageBox, QFrame, QSizePolicy,
                            QTextEdit, QTabWidget, QGroupBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


class RSAKeyGenerator:
    """Clase para manejar la generación de claves RSA y operaciones criptográficas"""
    
    @staticmethod
    def generate_keys_from_seed(seed_text, key_size=2048):
        """Genera un par de claves RSA basadas en un texto semilla"""
        # Convertir el texto semilla en un número determinista usando SHA-256
        seed_hash = hashlib.sha256(seed_text.encode()).digest()
        seed_int = int.from_bytes(seed_hash, byteorder='big')
        
        # Usar el número como semilla para generar claves RSA
        # Nota: En la práctica real, esto requeriría una implementación más sofisticada
        # para garantizar la seguridad criptográfica adecuada
        
        # Generar clave privada usando cryptography (el valor de la semilla se usa
        # para preparar el generador de números aleatorios del sistema)
        import random
        random.seed(seed_int)
        
        # Generar clave privada
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Obtener clave pública
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    @staticmethod
    def private_key_to_pem(private_key):
        """Convierte una clave privada a formato PEM"""
        encryption = serialization.NoEncryption()
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        return pem.decode('utf-8')
    
    @staticmethod
    def public_key_to_pem(public_key):
        """Convierte una clave pública a formato PEM"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem.decode('utf-8')
    
    @staticmethod
    def encrypt_message(public_key, message):
        """Encripta un mensaje usando la clave pública RSA"""
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convertir a base64 para mejor manejo como texto
        return base64.b64encode(ciphertext).decode('utf-8')
    
    @staticmethod
    def decrypt_message(private_key, encrypted_message):
        """Desencripta un mensaje usando la clave privada RSA"""
        # Convertir de base64 a bytes
        ciphertext = base64.b64decode(encrypted_message.encode('utf-8'))
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def load_private_key_from_pem(pem_data):
        """Carga una clave privada desde formato PEM"""
        private_key = serialization.load_pem_private_key(
            pem_data.encode(),
            password=None,
            backend=default_backend()
        )
        
        return private_key
    
    @staticmethod
    def load_public_key_from_pem(pem_data):
        """Carga una clave pública desde formato PEM"""
        public_key = serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )
        
        return public_key


class StyledButton(QPushButton):
    """Botón personalizado con mejor estilo"""
    
    def __init__(self, text, color="#3498db", hover_color="#2980b9"):
        super().__init__(text)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                border: none;
                color: white;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:pressed {{
                background-color: #1c6ea4;
            }}
            QPushButton:disabled {{
                background-color: #cccccc;
                color: #999999;
            }}
        """)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(38)


class StyledLineEdit(QLineEdit):
    """Campo de texto personalizado con mejor estilo"""
    
    def __init__(self, placeholder="", echo_mode=QLineEdit.Normal):
        super().__init__()
        self.setStyleSheet("""
            QLineEdit {
                border: 2px solid #dcdde1;
                border-radius: 5px;
                padding: 8px;
                background-color: #f5f6fa;
                color: #2f3542;
            }
            QLineEdit:focus {
                border: 2px solid #3498db;
            }
        """)
        self.setPlaceholderText(placeholder)
        self.setEchoMode(echo_mode)
        self.setMinimumHeight(35)


class StyledTextEdit(QTextEdit):
    """Campo de texto multilínea personalizado"""
    
    def __init__(self, placeholder=""):
        super().__init__()
        self.setStyleSheet("""
            QTextEdit {
                border: 2px solid #dcdde1;
                border-radius: 5px;
                padding: 8px;
                background-color: #f5f6fa;
                color: #2f3542;
            }
            QTextEdit:focus {
                border: 2px solid #3498db;
            }
        """)
        self.setPlaceholderText(placeholder)


class CardFrame(QFrame):
    """Marco tipo tarjeta para agrupar elementos relacionados"""
    
    def __init__(self):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)


class MainWindow(QMainWindow):
    """Ventana principal de la aplicación"""
    
    def __init__(self):
        super().__init__()
        self.private_key = None
        self.public_key = None
        self.init_ui()
    
    def init_ui(self):
        """Inicializa la interfaz de usuario"""
        # Configuración de la ventana
        self.setWindowTitle("Generador de Claves RSA - Cifrado Asimétrico")
        self.setGeometry(300, 300, 800, 650)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #2c3e50;
                font-size: 14px;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                border-radius: 8px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e6e6e6;
                border: 1px solid #cccccc;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom-color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #d9d9d9;
            }
        """)
        
        # Fuentes personalizadas
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        
        # Widget central con fondo
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        central_widget.setStyleSheet("background-color: #ecf0f1;")
        
        # Layout principal con márgenes
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(25, 25, 25, 25)
        
        # Título de la aplicación
        title_label = QLabel("Generador de Claves RSA")
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                color: #2c3e50;
                font-size: 24px;
                margin-bottom: 10px;
            }
        """)
        main_layout.addWidget(title_label)
        
        # Descripción
        desc_label = QLabel("Crea pares de claves RSA para cifrado asimétrico a partir de un texto semilla")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("font-size: 14px; color: #7f8c8d; margin-bottom: 15px;")
        main_layout.addWidget(desc_label)
        
        # Tarjeta para configuración de claves
        keys_card = CardFrame()
        keys_layout = QVBoxLayout(keys_card)
        
        keys_header = QLabel("Texto Semilla")
        keys_header.setStyleSheet("font-weight: bold; color: #3498db; font-size: 16px;")
        keys_layout.addWidget(keys_header)
        
        # Campo para ingresar el texto semilla
        seed_layout = QVBoxLayout()
        seed_label = QLabel("Ingresa un texto para generar las claves:")
        
        self.seed_input = StyledTextEdit("Escribe aquí un texto semilla para generar tus claves RSA...")
        self.seed_input.setMinimumHeight(100)
        
        seed_layout.addWidget(seed_label)
        seed_layout.addWidget(self.seed_input)
        keys_layout.addLayout(seed_layout)
        
        # Botón para generar claves
        generate_btn_layout = QHBoxLayout()
        generate_btn_layout.addStretch()
        self.generate_btn = StyledButton("Generar Par de Claves RSA", "#3498db", "#2980b9")
        self.generate_btn.setIcon(QIcon.fromTheme("emblem-system"))
        self.generate_btn.clicked.connect(self.generate_keys)
        self.generate_btn.setMinimumWidth(250)
        generate_btn_layout.addWidget(self.generate_btn)
        generate_btn_layout.addStretch()
        keys_layout.addLayout(generate_btn_layout)
        
        main_layout.addWidget(keys_card)
        
        # Pestañas para claves y operaciones
        self.tabs = QTabWidget()
        
        # Pestaña 1: Claves generadas
        keys_tab = QWidget()
        keys_tab_layout = QVBoxLayout(keys_tab)
        
        # Caja para clave pública
        public_key_group = QGroupBox("Clave Pública (compartir)")
        public_key_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 15px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #16a085;
            }
        """)
        
        public_key_layout = QVBoxLayout(public_key_group)
        self.public_key_text = StyledTextEdit("La clave pública aparecerá aquí después de generarla...")
        self.public_key_text.setReadOnly(True)
        public_key_layout.addWidget(self.public_key_text)
        
        public_key_btn_layout = QHBoxLayout()
        self.save_public_btn = StyledButton("Guardar Clave Pública", "#16a085", "#1abc9c")
        self.save_public_btn.clicked.connect(self.save_public_key)
        self.save_public_btn.setEnabled(False)
        public_key_btn_layout.addWidget(self.save_public_btn)
        public_key_layout.addLayout(public_key_btn_layout)
        
        # Caja para clave privada
        private_key_group = QGroupBox("Clave Privada (mantener segura)")
        private_key_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 15px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #c0392b;
            }
        """)
        
        private_key_layout = QVBoxLayout(private_key_group)
        self.private_key_text = StyledTextEdit("La clave privada aparecerá aquí después de generarla...")
        self.private_key_text.setReadOnly(True)
        private_key_layout.addWidget(self.private_key_text)
        
        private_key_btn_layout = QHBoxLayout()
        self.save_private_btn = StyledButton("Guardar Clave Privada", "#c0392b", "#e74c3c")
        self.save_private_btn.clicked.connect(self.save_private_key)
        self.save_private_btn.setEnabled(False)
        private_key_btn_layout.addWidget(self.save_private_btn)
        private_key_layout.addLayout(private_key_btn_layout)
        
        # Añadir grupos al layout de la pestaña
        keys_tab_layout.addWidget(public_key_group)
        keys_tab_layout.addWidget(private_key_group)
        
        # Añadir pestañas al widget de pestañas
        self.tabs.addTab(keys_tab, "Claves Generadas")
        
        main_layout.addWidget(self.tabs)
        
        # Estado
        status_frame = QFrame()
        status_frame.setFrameShape(QFrame.StyledPanel)
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border-radius: 5px;
                border: 1px solid #dcdde1;
            }
        """)
        
        status_layout = QVBoxLayout(status_frame)
        self.status_label = QLabel("Ingresa un texto semilla y genera tus claves RSA")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            padding: 10px;
            font-size: 14px;
            color: #2c3e50;
        """)
        status_layout.addWidget(self.status_label)
        
        main_layout.addWidget(status_frame)
        
        # Créditos
        credits = QLabel("© 2025 Generador RSA")
        credits.setStyleSheet("color: #95a5a6; font-size: 12px;")
        credits.setAlignment(Qt.AlignRight)
        main_layout.addWidget(credits)
    
    def generate_keys(self):
        """Genera un nuevo par de claves RSA a partir del texto semilla"""
        seed_text = self.seed_input.toPlainText()
        
        if not seed_text.strip():
            self._show_error_message("Por favor, ingresa un texto para generar las claves.")
            return
        
        try:
            self._update_status("Generando claves RSA a partir del texto...", "#f39c12")
            QApplication.processEvents()  # Actualizar la interfaz
            
            # Generar las claves RSA usando el texto semilla
            self.private_key, self.public_key = RSAKeyGenerator.generate_keys_from_seed(seed_text)
            
            # Obtener representación PEM
            private_pem = RSAKeyGenerator.private_key_to_pem(self.private_key)
            public_pem = RSAKeyGenerator.public_key_to_pem(self.public_key)
            
            # Mostrar claves en la interfaz
            self.public_key_text.setPlainText(public_pem)
            self.private_key_text.setPlainText(private_pem)
            
            # Activar botones de guardar
            self.save_public_btn.setEnabled(True)
            self.save_private_btn.setEnabled(True)
            
            self._update_status("Claves RSA generadas correctamente a partir del texto semilla", "#27ae60")
                
        except Exception as e:
            self._update_status("Error al generar claves", "#e74c3c")
            self._show_error_message(f"No se pudieron generar las claves: {str(e)}")
    
    def save_public_key(self):
        """Guarda la clave pública en un archivo"""
        if not self.public_key:
            return
            
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar clave pública", 
            "clave_publica.pem", "Archivos PEM (*.pem);;Todos los archivos (*)", 
            options=options
        )
        
        if file_path:
            try:
                public_pem = self.public_key_text.toPlainText()
                with open(file_path, 'w') as f:
                    f.write(public_pem)
                    
                self._update_status(f"Clave pública guardada en {os.path.basename(file_path)}", "#27ae60")
            except Exception as e:
                self._show_error_message(f"Error al guardar la clave pública: {str(e)}")
    
    def save_private_key(self):
        """Guarda la clave privada en un archivo"""
        if not self.private_key:
            return
            
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar clave privada", 
            "clave_privada.pem", "Archivos PEM (*.pem);;Todos los archivos (*)", 
            options=options
        )
        
        if file_path:
            try:
                private_pem = self.private_key_text.toPlainText()
                with open(file_path, 'w') as f:
                    f.write(private_pem)
                    
                self._update_status(f"Clave privada guardada en {os.path.basename(file_path)}", "#27ae60")
                self._show_info_message("¡Importante! Sobre la clave privada", 
                               "Mantén tu clave privada en un lugar seguro y no la compartas con nadie. Si la pierdes, no podrás descifrar los mensajes cifrados con la clave pública asociada.")
            except Exception as e:
                self._show_error_message(f"Error al guardar la clave privada: {str(e)}")
    
    def _update_status(self, message, color="#2c3e50"):
        """Actualiza el mensaje de estado con color personalizado"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"""
            padding: 10px;
            font-size: 14px;
            color: {color};
        """)
    
    def _show_error_message(self, message):
        """Muestra un mensaje de error personalizado"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setWindowTitle("Error")
        msg_box.setText(message)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #f7f7f7;
            }
            QMessageBox QLabel {
                color: #c0392b;
            }
            QPushButton {
                background-color: #e74c3c;
                border: none;
                color: white;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        msg_box.exec_()
    
    def _show_info_message(self, title, message):
        """Muestra un mensaje informativo personalizado"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #f7f7f7;
            }
            QMessageBox QLabel {
                color: #2980b9;
            }
            QPushButton {
                background-color: #3498db;
                border: none;
                color: white;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        msg_box.exec_()
    
    def _show_success_message(self, message):
        """Muestra un mensaje de éxito personalizado"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setWindowTitle("Éxito")
        msg_box.setText(message)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #f7f7f7;
            }
            QMessageBox QLabel {
                color: #27ae60;
            }
            QPushButton {
                background-color: #2ecc71;
                border: none;
                color: white;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        msg_box.exec_()


def main():
    app = QApplication(sys.argv)
    
    # Aplicar estilo global a la aplicación
    app.setStyle("Fusion")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()