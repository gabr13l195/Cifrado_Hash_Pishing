import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QLineEdit, QFileDialog, QVBoxLayout, QHBoxLayout, 
                            QWidget, QMessageBox, QFrame, QSizePolicy)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont, QPixmap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib


class AESEncryptor:
    """Clase para manejar la encriptación y desencriptación AES"""
    
    @staticmethod
    def generate_key(password, salt=b'salt_estatico'):
        """Genera una clave AES de 256 bits a partir de una contraseña"""
        # Usar PBKDF2 sería más seguro, pero simplificamos para el ejemplo
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)
        return key
    
    @staticmethod
    def encrypt_file(input_path, output_path, password):
        """Encripta un archivo usando AES-256 en modo CBC"""
        key = AESEncryptor.generate_key(password)
        
        # Generar un vector de inicialización aleatorio
        iv = os.urandom(16)
        
        # Crear encriptador AES
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()
        
        # Aplicar padding a los datos
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        
        # Leer el archivo original
        with open(input_path, 'rb') as file:
            data = file.read()
        
        # Aplicar padding y encriptar
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Escribir el IV y los datos encriptados al archivo destino
        with open(output_path, 'wb') as file:
            file.write(iv + encrypted_data)
        
        return True
    
    @staticmethod
    def decrypt_file(input_path, output_path, password):
        """Desencripta un archivo encriptado con AES-256 en modo CBC"""
        key = AESEncryptor.generate_key(password)
        
        # Leer el archivo encriptado
        with open(input_path, 'rb') as file:
            data = file.read()
        
        # Extraer el IV (primeros 16 bytes)
        iv = data[:16]
        encrypted_data = data[16:]
        
        # Crear desencriptador AES
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()
        
        # Desencriptar los datos
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Quitar el padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Escribir los datos desencriptados al archivo destino
        with open(output_path, 'wb') as file:
            file.write(data)
        
        return True


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


class CardFrame(QFrame):
    """Marco tipo tarjeta para agrupar elementos relacionados"""
    
    def __init__(self):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)


class MainWindow(QMainWindow):
    """Ventana principal de la aplicación"""
    
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.init_ui()
    
    def init_ui(self):
        """Inicializa la interfaz de usuario"""
        # Configuración de la ventana
        self.setWindowTitle("Encriptador AES - Seguridad de Archivos")
        self.setGeometry(300, 300, 600, 450)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #2c3e50;
                font-size: 14px;
            }
        """)
        
        # Fuentes personalizadas
        title_font = QFont()
        title_font.setPointSize(14)
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
        title_label = QLabel("Encriptador AES")
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
        desc_label = QLabel("Cifre y descifre sus archivos con seguridad AES-256")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("font-size: 14px; color: #7f8c8d; margin-bottom: 15px;")
        main_layout.addWidget(desc_label)
        
        # Tarjeta para selección de archivo
        file_card = CardFrame()
        file_layout = QVBoxLayout(file_card)
        
        file_header = QLabel("Archivo")
        file_header.setStyleSheet("font-weight: bold; color: #3498db;")
        file_layout.addWidget(file_header)
        
        file_selector_layout = QHBoxLayout()
        self.file_label = QLabel("Ningún archivo seleccionado")
        self.file_label.setStyleSheet("""
            QLabel {
                color: #7f8c8d;
                padding: 8px;
                background-color: #f9f9f9;
                border: 1px solid #dcdde1;
                border-radius: 4px;
            }
        """)
        
        self.select_file_btn = StyledButton("Seleccionar")
        self.select_file_btn.setMaximumWidth(120)
        self.select_file_btn.clicked.connect(self.select_file)
        
        file_selector_layout.addWidget(self.file_label, 1)
        file_selector_layout.addWidget(self.select_file_btn)
        file_layout.addLayout(file_selector_layout)
        
        main_layout.addWidget(file_card)
        
        # Tarjeta para contraseña
        password_card = CardFrame()
        password_layout = QVBoxLayout(password_card)
        
        password_header = QLabel("Seguridad")
        password_header.setStyleSheet("font-weight: bold; color: #3498db;")
        password_layout.addWidget(password_header)
        
        # Password input
        password_input_layout = QHBoxLayout()
        password_label = QLabel("Contraseña:")
        password_label.setMinimumWidth(100)
        self.password_input = StyledLineEdit("Introduce una contraseña segura", QLineEdit.Password)
        password_input_layout.addWidget(password_label)
        password_input_layout.addWidget(self.password_input, 1)
        password_layout.addLayout(password_input_layout)
        
        # Confirm password
        confirm_input_layout = QHBoxLayout()
        confirm_label = QLabel("Confirmar:")
        confirm_label.setMinimumWidth(100)
        self.confirm_input = StyledLineEdit("Confirma la contraseña", QLineEdit.Password)
        confirm_input_layout.addWidget(confirm_label)
        confirm_input_layout.addWidget(self.confirm_input, 1)
        password_layout.addLayout(confirm_input_layout)
        
        main_layout.addWidget(password_card)
        
        # Botones de acción
        action_layout = QHBoxLayout()
        
        self.encrypt_btn = StyledButton("Cifrar archivo", "#27ae60", "#219653")
        self.encrypt_btn.setIcon(QIcon.fromTheme("document-encrypt"))
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.encrypt_btn.setEnabled(False)
        
        self.decrypt_btn = StyledButton("Descifrar archivo", "#e74c3c", "#c0392b")
        self.decrypt_btn.setIcon(QIcon.fromTheme("document-decrypt"))
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.decrypt_btn.setEnabled(False)
        
        action_layout.addWidget(self.encrypt_btn)
        action_layout.addWidget(self.decrypt_btn)
        main_layout.addLayout(action_layout)
        
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
        status_header = QLabel("Estado")
        status_header.setStyleSheet("font-weight: bold; color: #3498db;")
        status_layout.addWidget(status_header)
        
        self.status_label = QLabel("Listo para comenzar")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            padding: 10px;
            font-size: 14px;
            color: #2c3e50;
        """)
        status_layout.addWidget(self.status_label)
        
        main_layout.addWidget(status_frame)
        
        # Créditos
        credits = QLabel("© 2025 Encriptador AES")
        credits.setStyleSheet("color: #95a5a6; font-size: 12px;")
        credits.setAlignment(Qt.AlignRight)
        main_layout.addWidget(credits)
    
    def select_file(self):
        """Abre el diálogo para seleccionar un archivo"""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar archivo", "", "Todos los archivos (*)", options=options
        )
        
        if file_path:
            self.file_path = file_path
            file_name = os.path.basename(file_path)
            # Acortar nombre si es muy largo
            if len(file_name) > 30:
                display_name = file_name[:27] + "..."
            else:
                display_name = file_name
                
            self.file_label.setText(f"{display_name}")
            self.file_label.setStyleSheet("""
                QLabel {
                    color: #2c3e50;
                    padding: 8px;
                    background-color: #e8f4fc;
                    border: 1px solid #a9d0f5;
                    border-radius: 4px;
                }
            """)
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)
            self.status_label.setText("Archivo seleccionado correctamente")
            self.status_label.setStyleSheet("""
                padding: 10px;
                font-size: 14px;
                color: #27ae60;
            """)
    
    def encrypt_file(self):
        """Cifra el archivo seleccionado"""
        if not self.file_path:
            QMessageBox.warning(self, "Error", "No se ha seleccionado ningún archivo")
            return
        
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if not password:
            self._show_error_message("Debe introducir una contraseña")
            return
        
        if password != confirm:
            self._show_error_message("Las contraseñas no coinciden")
            return
        
        # Solicitar ubicación para guardar el archivo cifrado
        options = QFileDialog.Options()
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar archivo cifrado", 
            f"{self.file_path}.enc", "Archivos cifrados (*.enc)", options=options
        )
        
        if not output_path:
            return
        
        try:
            self._update_status("Cifrando archivo...", "#f39c12")
            QApplication.processEvents()  # Actualizar la interfaz
            
            AESEncryptor.encrypt_file(self.file_path, output_path, password)
            
            self._update_status("Archivo cifrado correctamente", "#27ae60")
            self._show_success_message(f"Archivo cifrado y guardado en:\n{output_path}")
        except Exception as e:
            self._update_status("Error al cifrar", "#e74c3c")
            self._show_error_message(f"No se pudo cifrar el archivo: {str(e)}")
    
    def decrypt_file(self):
        """Descifra el archivo seleccionado"""
        if not self.file_path:
            QMessageBox.warning(self, "Error", "No se ha seleccionado ningún archivo")
            return
        
        password = self.password_input.text()
        
        if not password:
            self._show_error_message("Debe introducir una contraseña")
            return
        
        # Solicitar ubicación para guardar el archivo descifrado
        options = QFileDialog.Options()
        suggested_name = self.file_path
        if suggested_name.endswith('.enc'):
            suggested_name = suggested_name[:-4]  # Quitar la extensión .enc
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado", suggested_name,
            "Todos los archivos (*)", options=options
        )
        
        if not output_path:
            return
        
        try:
            self._update_status("Descifrando archivo...", "#f39c12")
            QApplication.processEvents()  # Actualizar la interfaz
            
            AESEncryptor.decrypt_file(self.file_path, output_path, password)
            
            self._update_status("Archivo descifrado correctamente", "#27ae60")
            self._show_success_message(f"Archivo descifrado y guardado en:\n{output_path}")
        except Exception as e:
            self._update_status("Error al descifrar", "#e74c3c")
            self._show_error_message(f"No se pudo descifrar el archivo: {str(e)}")
    
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