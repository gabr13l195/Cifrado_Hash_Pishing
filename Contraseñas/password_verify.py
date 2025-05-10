import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal


class ComparadorThread(QThread):
    terminado = pyqtSignal(str)

    def __init__(self, archivo_ejemplo, archivo_diccionario):
        super().__init__()
        self.archivo_ejemplo = archivo_ejemplo
        self.archivo_diccionario = archivo_diccionario

    def run(self):
        try:
            with open(self.archivo_ejemplo, 'r', encoding='utf-8', errors='ignore') as f1:
                ejemplo = [line.strip() for line in f1 if line.strip()]

            total = len(ejemplo)
            if total == 0:
                self.terminado.emit("⚠️ El archivo de ejemplo está vacío.")
                return

            diccionario = set()
            with open(self.archivo_diccionario, 'r', encoding='utf-8', errors='ignore') as f2:
                for line in f2:
                    pw = line.strip()
                    if pw:
                        diccionario.add(pw)

            encontradas = sum(1 for pw in ejemplo if pw in diccionario)
            porcentaje = (encontradas / total) * 100

            salida = (
                f"🔎 Contraseñas analizadas: {total}\n"
                f"❌ Contraseñas débiles encontradas: {encontradas} ({porcentaje:.2f}%)"
            )

            self.terminado.emit(salida)

        except Exception as e:
            self.terminado.emit(f"❌ Error: {str(e)}")


class ComparadorContrasenhas(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Verificador de Contraseñas Débiles")
        self.setGeometry(100, 100, 600, 350)

        layout = QVBoxLayout()

        self.btn_cargar_ejemplo = QPushButton("Seleccionar archivo de contraseñas de ejemplo")
        self.btn_cargar_diccionario = QPushButton("Seleccionar diccionario (ej. rockyou.txt)")
        self.btn_comparar = QPushButton("Verificar contraseñas débiles")
        self.resultado = QTextEdit()
        self.resultado.setReadOnly(True)

        layout.addWidget(self.btn_cargar_ejemplo)
        layout.addWidget(self.btn_cargar_diccionario)
        layout.addWidget(self.btn_comparar)
        layout.addWidget(QLabel("Resultado:"))
        layout.addWidget(self.resultado)

        self.setLayout(layout)

        self.archivo_ejemplo = ""
        self.archivo_diccionario = ""

        self.btn_cargar_ejemplo.clicked.connect(self.seleccionar_archivo_ejemplo)
        self.btn_cargar_diccionario.clicked.connect(self.seleccionar_archivo_diccionario)
        self.btn_comparar.clicked.connect(self.iniciar_comparacion)

    def seleccionar_archivo_ejemplo(self):
        archivo, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo de contraseñas de ejemplo", "", "Text files (*.txt)")
        if archivo:
            self.archivo_ejemplo = archivo
            self.btn_cargar_ejemplo.setText(f"Ejemplo: {archivo.split('/')[-1]}")

    def seleccionar_archivo_diccionario(self):
        archivo, _ = QFileDialog.getOpenFileName(self, "Seleccionar diccionario", "", "Text files (*.txt)")
        if archivo:
            self.archivo_diccionario = archivo
            self.btn_cargar_diccionario.setText(f"Diccionario: {archivo.split('/')[-1]}")

    def iniciar_comparacion(self):
        if not self.archivo_ejemplo or not self.archivo_diccionario:
            self.resultado.setText("⚠️ Selecciona ambos archivos primero.")
            return

        self.resultado.setText("🔄 Verificando contraseñas, por favor espera...")

        self.hilo = ComparadorThread(self.archivo_ejemplo, self.archivo_diccionario)
        self.hilo.terminado.connect(self.mostrar_resultado)
        self.hilo.start()

    def mostrar_resultado(self, texto):
        self.resultado.setText(texto)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ventana = ComparadorContrasenhas()
    ventana.show()
    sys.exit(app.exec_())
