import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QTextEdit
)

class ComparadorHashes(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Comparador de Hashes")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.btn_cargar1 = QPushButton("Seleccionar archivo 1")
        self.btn_cargar2 = QPushButton("Seleccionar archivo 2")
        self.resultado = QTextEdit()
        self.resultado.setReadOnly(True)

        self.btn_comparar = QPushButton("Comparar archivos")

        layout.addWidget(self.btn_cargar1)
        layout.addWidget(self.btn_cargar2)
        layout.addWidget(self.btn_comparar)
        layout.addWidget(QLabel("Resultado:"))
        layout.addWidget(self.resultado)

        self.setLayout(layout)

        self.archivo1 = ""
        self.archivo2 = ""

        self.btn_cargar1.clicked.connect(self.seleccionar_archivo1)
        self.btn_cargar2.clicked.connect(self.seleccionar_archivo2)
        self.btn_comparar.clicked.connect(self.comparar_archivos)

    def seleccionar_archivo1(self):
        archivo, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo 1", "", "Text files (*.txt)")
        if archivo:
            self.archivo1 = archivo
            self.btn_cargar1.setText(f"Archivo 1: {archivo.split('/')[-1]}")

    def seleccionar_archivo2(self):
        archivo, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo 2", "", "Text files (*.txt)")
        if archivo:
            self.archivo2 = archivo
            self.btn_cargar2.setText(f"Archivo 2: {archivo.split('/')[-1]}")

    def comparar_archivos(self):
        if not self.archivo1 or not self.archivo2:
            self.resultado.setText("⚠️ Selecciona ambos archivos primero.")
            return

        with open(self.archivo1, 'r') as f1, open(self.archivo2, 'r') as f2:
            lineas1 = [line.strip() for line in f1.readlines()]
            lineas2 = [line.strip() for line in f2.readlines()]

        if len(lineas1) != 50 or len(lineas2) != 50:
            self.resultado.setText("❌ Los archivos deben contener exactamente 50 líneas.")
            return

        diferentes = []
        for i in range(50):
            if lineas1[i] != lineas2[i]:
                diferentes.append((i + 1, lineas1[i], lineas2[i]))

        porcentaje = (len(diferentes) / 50) * 100
        salida = ""

        if diferentes:
            salida += f"❌ Se encontraron {len(diferentes)} diferencias ({porcentaje:.2f}%).\n\n"
            salida += "Líneas diferentes:\n"
            for linea, hash1, hash2 in diferentes:
                salida += f"Línea {linea}:\n - Archivo 1: {hash1}\n - Archivo 2: {hash2}\n\n"
        else:
            salida = "✅ Los archivos son idénticos (100% coinciden)."

        self.resultado.setText(salida)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ventana = ComparadorHashes()
    ventana.show()
    sys.exit(app.exec_())
