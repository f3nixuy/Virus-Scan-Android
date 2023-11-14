#F3NIX
import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserIconView
from kivy.utils import platform
from kivy.clock import Clock

import requests

API_KEY = 'ACATUAPI'

class VirusTotalApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=10)

        # Mover el TextInput a la parte superior
        self.result_text = TextInput(height=210, size_hint_y=None, multiline=True)
        layout.add_widget(self.result_text)

        file_chooser = FileChooserIconView()
        file_chooser.bind(on_submit=self.on_file_select)

        # Ajustar el tamaño de los iconos de las carpetas
        file_chooser.icon_size = (100, 100)

        file_button = Button(text='Cargar Archivo', size_hint=(1, 0.2))
        file_button.bind(on_press=self.show_file_chooser)

        url_label = Label(text='URL a Analizar:', size_hint=(1, 0.1))
        self.url_entry = TextInput(size_hint=(1, 0.3))
        url_button = Button(text='Analizar URL', on_press=self.analizar_url, size_hint=(1, 0.2))

        exit_button = Button(text='Salir', on_press=self.stop, size_hint=(1, 0.2))

        layout.add_widget(file_button)
        layout.add_widget(file_chooser)
        layout.add_widget(url_label)
        layout.add_widget(self.url_entry)
        layout.add_widget(url_button)
        layout.add_widget(exit_button)

        # Manejo de permisos en Android
        if platform == 'android':
            permiso_escritura = 'android.permission.WRITE_EXTERNAL_STORAGE'
            permiso_lectura = 'android.permission.READ_EXTERNAL_STORAGE'

            # Verificar si el permiso ya está otorgado
            if not check_permission(permiso_escritura) or not check_permission(permiso_lectura):
                # Si el permiso no está otorgado, solicitarlo al usuario
                request_permission(permiso_escritura)
                request_permission(permiso_lectura)

        return layout

    def show_file_chooser(self, instance):
        file_chooser = self.root.children[1]
        file_chooser.path = os.path.expanduser('~')
        file_chooser.filters = ['*']
        file_chooser.show_hidden = False
        file_chooser.preview_size = (None, 64)

    def on_file_select(self, instance, selection, touch=None):
        if selection:
            file_path = selection[0]
            self.analizar_archivo(file_path)

    def analizar_archivo(self, file_path):
        def analisis_diferido(dt):
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as file:
                        files = {'file': (file_path, file)}
                        params = {'apikey': API_KEY}
                        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
                        scan_id = response.json()['scan_id']
                        params = {'apikey': API_KEY, 'resource': scan_id}
                        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                        report = response.json()
                        self.mostrar_informe(report)
                except IOError as e:
                    print(f"Error al abrir el archivo: {e}")
            else:
                print(f"El archivo {file_path} no existe.")

        Clock.schedule_once(analisis_diferido, 0)

    def analizar_url(self, instance):
        url = self.url_entry.text
        if url:
            params = {'apikey': API_KEY, 'resource': url}
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
            report = response.json()
            self.mostrar_informe(report)

    def mostrar_informe(self, report):
        self.result_text.text = ''
        red_text = ""
        black_text = ""

        self.result_text.text += 'Resultado completo del análisis:\n'

        if 'positives' in report:
            total_motores = report['total']
            motores_detectados = report['positives']
            self.result_text.text += f'Total de motores de antivirus utilizados: {total_motores}\n'
            self.result_text.text += f'Motores de antivirus que encontraron el archivo malicioso: {motores_detectados}\n'

            if 'scans' in report:
                results = []

                for scan_name, scan_info in report['scans'].items():
                    scan_result = f"{scan_name}:\n"
                    for scan_key, scan_value in scan_info.items():
                        scan_result += f"  {scan_key}: {scan_value}\n"
                    results.append((scan_result, scan_info['detected']))

                results.sort(key=lambda x: x[1], reverse=True)

                for result, detected in results:
                    if detected:
                        red_text += result
                    else:
                        black_text += result

                if report['positives'] > 0:
                    red_text = 'El archivo/URL es malicioso.\n' + red_text
                else:
                    black_text = 'El archivo/URL es seguro.\n' + black_text

            self.result_text.text += red_text
            self.result_text.text += black_text

if __name__ == '__main__':
    try:
        VirusTotalApp().run()
    except Exception as e:
        print(f"Error al ejecutar la aplicación: {e}")
