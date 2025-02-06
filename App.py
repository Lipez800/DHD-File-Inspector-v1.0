import os
import hashlib
import json
import requests
import threading
import time
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

# Configuração de estilo - ESTÉTICA REFORMULADA (Mais profissional e escura)
DARK_BG = "#242424"
MEDIUM_BG = "#383838"
LIGHT_BG = "#4f4f4f"
ACCENT_COLOR = "#29abe2"
TEXT_COLOR = "#ffffff"
FONT_NAME = "Segoe UI"

class VirusTotalScanner:
    def __init__(self):
        self.API_KEY = None
        self.API_URL_REPORT = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.API_URL_SCAN = 'https://www.virustotal.com/vtapi/v2/file/scan'

    def set_api_key(self, key):
        self.API_KEY = key

    def calcular_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()

    def verificar_por_hash(self, file_hash):
        params = {'apikey': self.API_KEY, 'resource': file_hash}
        try:
            response = requests.get(self.API_URL_REPORT, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            print(f"JSONDecodeError: {e}, Response Text: {response.text if 'response' in locals() else 'No Response'}") # Log response text
            return {"response_code": 0, "error": "Erro ao decodificar resposta JSON do VirusTotal."}
        except requests.exceptions.RequestException as e:
            print(f"RequestException: {e}")
            return {"response_code": 0, "error": f"Erro na requisição ao VirusTotal: {str(e)}"}


    def enviar_arquivo(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                params = {'apikey': self.API_KEY}
                response = requests.post(self.API_URL_SCAN, files=files, params=params)
                response.raise_for_status()
                return response.json()
        except requests.exceptions.JSONDecodeError as e:
            print(f"JSONDecodeError (enviar_arquivo): {e}, Response Text: {response.text if 'response' in locals() else 'No Response'}") # Log response text
            return {"response_code": 0, "error": "Erro ao decodificar resposta JSON do VirusTotal (envio de arquivo)."}
        except requests.exceptions.RequestException as e:
            print(f"RequestException (enviar_arquivo): {e}")
            return {"response_code": 0, "error": f"Erro na requisição ao VirusTotal (envio de arquivo): {str(e)}"}

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("DHD FILE INSPECTOR v1.0")
        self.root.geometry("1000x600")
        self.root.resizable(False, False)
        self.root.configure(bg=DARK_BG)

        self.style = ttk.Style()
        self._configurar_estilo()

        self.scanner = VirusTotalScanner()
        self.scanning = False
        self.progress_max = 0
        self.resultados = {}
        self.historico = []
        self.config_file = os.path.join(os.getenv('APPDATA'), 'secscan_config.json')
        # self.salvar_api_value = BooleanVar() # Removed BooleanVar

        self.carregar_config()
        self.criar_interface()

    def _configurar_estilo(self):
        self.style.theme_create("secscan", settings={
            "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0]}},
            "TNotebook.Tab": {
                "configure": {
                    "padding": [10, 5],
                    "background": MEDIUM_BG,
                    "foreground": TEXT_COLOR,
                    "font": (FONT_NAME, 10, 'bold')
                },
                "map": {
                    "background": [("selected", ACCENT_COLOR)],
                    "expand": [("selected", [1, 1, 1, 0])]
                }
            },
            "TFrame": {"configure": {"background": DARK_BG}},
            "TLabel": {"configure": {"background": DARK_BG, "foreground": TEXT_COLOR}},
            "TButton": {
                "configure": {
                    "background": ACCENT_COLOR,
                    "foreground": TEXT_COLOR,
                    "font": (FONT_NAME, 10, 'bold'),
                    "borderwidth": 0,
                    "relief": "flat",
                    "padding": 8
                },
                "map": {
                    "background": [("active", "#42bff5"), ("disabled", "#5a5a5a")],
                    "foreground": [("disabled", "#808080")]
                }
            },
            "Horizontal.TProgressbar": {
                "configure": {
                    "background": ACCENT_COLOR,
                    "troughcolor": MEDIUM_BG,
                    "borderwidth": 0,
                    "lightcolor": ACCENT_COLOR,
                    "darkcolor": ACCENT_COLOR
                }
            }
        })
        self.style.theme_use("secscan")

    def criar_interface(self):
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=X, pady=10, padx=20)

        ttk.Label(header_frame, text="DHD FILE INSPECTOR v1.0 VIRUSTOTAL API", font=(FONT_NAME, 16, 'bold'),
                foreground=ACCENT_COLOR).pack(side=LEFT)

        # Status da API
        self.lbl_api_status = ttk.Label(header_frame, text="● API: Não configurada",
                                      foreground="#ff3333", font=(FONT_NAME, 10))
        self.lbl_api_status.pack(side=RIGHT, padx=10)
        self.atualizar_status_api()

        # Controles principais
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=20, padx=20, fill=X)

        botoes = [
            ("🗂️ Selecionar Pasta", lambda: self.selecionar_pasta(True)),
            ("📄 Verificar Arquivo", self.selecionar_arquivo),
            ("🔑 Configurar API", self.janela_api_key),
            ("ℹ️ Sobre", self.mostrar_sobre)
        ]

        self.btn_pasta = None
        self.btn_arquivo = None

        for texto, comando in botoes:
            btn = ttk.Button(control_frame, text=texto, command=comando)
            btn.pack(side=LEFT, padx=5)
            if texto == "🗂️ Selecionar Pasta":
                self.btn_pasta = btn
            elif texto == "📄 Verificar Arquivo":
                self.btn_arquivo = btn

        # Progresso
        self.progress = ttk.Progressbar(self.root, style="Horizontal.TProgressbar")
        self.progress.pack(fill=X, padx=20, pady=10)

        # Corpo principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

        # Painel de resultados
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(side=LEFT, fill=BOTH, expand=True)

        # Lista de ameaças
        threat_frame = ttk.Frame(results_frame)
        threat_frame.pack(fill=BOTH, expand=True)

        ttk.Label(threat_frame, text="AMEAÇAS DETECTADAS", font=(FONT_NAME, 12, 'bold')).pack(anchor=W)
        self.lista_maliciosos = Listbox(threat_frame, bg=MEDIUM_BG, fg=TEXT_COLOR, selectbackground=ACCENT_COLOR,
                                      font=(FONT_NAME, 10), relief=FLAT, highlightthickness=0)
        self.lista_maliciosos.pack(fill=BOTH, expand=True, pady=5)
        self.lista_maliciosos.bind('<<ListboxSelect>>', self.mostrar_detalhes)

        # Lista segura
        safe_frame = ttk.Frame(results_frame)
        safe_frame.pack(fill=BOTH, expand=True)

        ttk.Label(safe_frame, text="ARQUIVOS SEGUROS", font=(FONT_NAME, 12, 'bold')).pack(anchor=W)
        self.lista_seguros = Listbox(safe_frame, bg=MEDIUM_BG, fg="#00cc66", selectbackground=ACCENT_COLOR,
                                   font=(FONT_NAME, 10), relief=FLAT, highlightthickness=0)
        self.lista_seguros.pack(fill=BOTH, expand=True, pady=5)
        self.lista_seguros.bind('<<ListboxSelect>>', self.mostrar_detalhes)

        # Histórico
        history_frame = ttk.Frame(main_frame, width=300)
        history_frame.pack(side=RIGHT, fill=Y, padx=10)

        ttk.Label(history_frame, text="HISTÓRICO", font=(FONT_NAME, 12, 'bold')).pack(anchor=W)
        self.lista_historico = Listbox(history_frame, bg=MEDIUM_BG, fg=TEXT_COLOR, selectbackground=ACCENT_COLOR,
                                     font=(FONT_NAME, 10), relief=FLAT, highlightthickness=0)
        self.lista_historico.pack(fill=BOTH, expand=True, pady=5)
        self.lista_historico.bind('<<ListboxSelect>>', self.carregar_historico)

        # Status bar
        self.status = ttk.Label(self.root, text="Pronto", relief=SUNKEN, anchor=W,
                              font=(FONT_NAME, 9), background=LIGHT_BG, foreground=TEXT_COLOR)
        self.status.pack(side=BOTTOM, fill=X)

    def janela_api_key(self):
        janela = Toplevel(self.root)
        janela.title("Configuração de API Key")
        janela.configure(bg=DARK_BG)
        janela.resizable(False, False)
        self.center_popup_relative_to_main(janela)

        main_frame = ttk.Frame(janela)
        main_frame.pack(padx=20, pady=20)

        ttk.Label(main_frame, text="Insira sua VirusTotal API Key:").grid(row=0, column=0, sticky=W)
        entry_api_key = ttk.Entry(main_frame, width=40)
        entry_api_key.grid(row=1, column=0, pady=5)

        if self.scanner.API_KEY:
            entry_api_key.insert(0, self.scanner.API_KEY)


        ttk.Button(main_frame, text="Salvar", command=lambda: self.salvar_api_key( # Keep the "Salvar" Button
            entry_api_key.get(),
            janela
        )).grid(row=3, column=0, pady=10)


    def mostrar_sobre(self):
        sobre = """
**DHD File Inspector v1.0**

**Análise de Arquivos e Pastas com VirusTotal**

Desenvolvido por [Luis Felipe]

**Recursos:**

* Varredura de arquivos e pastas em busca de ameaças.
* Integração total com a API VirusTotal para detecção avançada.
* Histórico de análises para acompanhamento e segurança.
* Interface moderna, intuitiva e segura.
* Verificação recursiva de pastas para análise completa.

**Limitações da Versão Gratuita (API VirusTotal FREE):**

* Limite de 4 requisições por minuto.
* Suporte a arquivos de até 32MB.
* Até 500 verificações diárias.

**Para remover as limitações e obter o máximo do DHD File Inspector, considere uma API Pro do VirusTotal.**
        """
        janela = Toplevel(self.root)
        janela.title("Sobre")
        janela.configure(bg=DARK_BG)
        janela.resizable(False, False)
        self.center_popup_relative_to_main(janela)

        ttk.Label(janela, text=sobre, justify=LEFT, font=(FONT_NAME, 10)).pack(padx=20, pady=10)
        ttk.Button(janela, text="Fechar", command=janela.destroy).pack(pady=10)

    def center_popup_relative_to_main(self, janela_popup):
        janela_popup.update_idletasks()
        width = janela_popup.winfo_width()
        height = janela_popup.winfo_height()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()

        x = main_x + (main_width / 2) - (width / 2)
        y = main_y + (main_height / 2) - (height / 2)
        janela_popup.geometry('+%d+%d' % (int(x), int(y)))


    def salvar_api_key(self, key, janela): # Removed 'salvar' parameter
        if len(key) != 64 and len(key) != 0:
            messagebox.showerror("Erro", "API Key inválida! Deve ter 64 caracteres.")
            return

        self.scanner.set_api_key(key if len(key) == 64 else None)
        try:
            if len(key) == 64: # Always save if valid key provided
                with open(self.config_file, 'w') as f:
                    json.dump({'api_key': key}, f)
            elif os.path.exists(self.config_file):
                os.remove(self.config_file) # Remove config file if key is cleared

        except Exception as e:
            messagebox.showerror("Erro ao Salvar", f"Ocorreu um erro ao salvar a API Key: {str(e)}")
            return

        self.atualizar_status_api()
        janela.destroy()
        messagebox.showinfo("Sucesso", "Configurações da API Key salvas!")

    def carregar_config(self):
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.scanner.set_api_key(config['api_key'])
        except FileNotFoundError:
            pass
        except json.JSONDecodeError as e:
            messagebox.showerror("Erro", f"Arquivo de configuração corrompido. A API Key não pôde ser carregada.\nErro: {str(e)}")
            pass


    def atualizar_status_api(self):
        if self.scanner.API_KEY:
            self.lbl_api_status.config(text="● API: Configurada", foreground="#00cc66")
        else:
            self.lbl_api_status.config(text="● API: Não configurada", foreground="#ff3333")

    def selecionar_arquivo(self):
        if self.scanning:
            messagebox.showinfo("Aviso", "Verificação já em operação. Aguarde a conclusão.")
            return

        arquivo_path = filedialog.askopenfilename()
        if arquivo_path:
            self.limpar_resultados()
            self.scanning = True
            if self.btn_arquivo:
                self.btn_arquivo.config(state=DISABLED)

            timestamp = datetime.now().strftime("%H:%M:%S")
            scan_id = f"{timestamp} - {os.path.basename(arquivo_path)}"
            self.historico.append({
                'id': scan_id,
                'arquivo': arquivo_path,
                'resultados': {},
                'timestamp': timestamp
            })
            self.lista_historico.insert(END, scan_id)

            self.progress_max = 1
            self.progress['maximum'] = self.progress_max
            self.progress['value'] = 0

            threading.Thread(target=self.verificar_arquivo_unico, args=(arquivo_path,)).start()

    def verificar_arquivo_unico(self, arquivo):
        try:
            file_hash = self.scanner.calcular_hash(arquivo)
            resultado = self.scanner.verificar_por_hash(file_hash)

            if resultado.get('response_code') == 0:
                resultado_upload = self.scanner.enviar_arquivo(arquivo)
                resultado_scan = resultado_upload
                if resultado_upload.get('response_code') == 1:
                    for _ in range(5):
                        time.sleep(15)
                        resultado = self.scanner.verificar_por_hash(file_path) # Corrected variable name here
                        if resultado.get('response_code') == 1:
                            break

            nome_arquivo = os.path.basename(arquivo)
            if resultado and resultado.get('response_code') == 1:
                self.historico[-1]['resultados'][nome_arquivo] = resultado
                self.resultados[arquivo] = resultado
                self.root.after(0, self.processar_resultado, nome_arquivo, resultado)
            elif resultado and resultado.get('response_code') == 0 and "error" in resultado:
                self.root.after(0, self.adicionar_erro, nome_arquivo, resultado["error"])
            elif resultado_scan and resultado_scan.get('response_code') == 0 and "error" in resultado_scan:
                self.root.after(0, self.adicionar_erro, nome_arquivo, resultado_scan["error"])
            else:
                self.root.after(0, self.adicionar_erro, nome_arquivo, "Falha na verificação (resposta inesperada da API)")

        except Exception as e:
            self.root.after(0, self.adicionar_erro, os.path.basename(arquivo), str(e))
        finally:
            self.root.after(0, self.atualizar_progresso, 1)

        self.scanning = False
        self.root.after(0, self.finalizar_verificacao)


    def selecionar_pasta(self, recursivo=False):
        if self.scanning:
            messagebox.showinfo("Aviso", "Verificação já em operação. Aguarde a conclusão.")
            return

        pasta = filedialog.askdirectory()
        if pasta:
            self.limpar_resultados()
            self.scanning = True
            if self.btn_pasta:
                self.btn_pasta.config(state=DISABLED)

            files = []
            for dirpath, _, filenames in os.walk(pasta):
                for f in filenames:
                    files.append(os.path.join(dirpath, f))

            self.progress_max = len(files)
            self.progress['maximum'] = self.progress_max
            self.progress['value'] = 0

            timestamp = datetime.now().strftime("%H:%M:%S")
            scan_id = f"{timestamp} - {os.path.basename(pasta)}"
            self.historico.append({
                'id': scan_id,
                'pasta': pasta,
                'resultados': {},
                'timestamp': timestamp
            })
            self.lista_historico.insert(END, scan_id)

            threading.Thread(target=self.verificar_pasta, args=(files,)).start()

    def verificar_pasta(self, files):
        current_scan = self.historico[-1]

        for i, caminho_completo in enumerate(files):
            if not self.scanning:
                break

            try:
                arquivo = os.path.basename(caminho_completo)
                self.atualizar_status(f"Verificando: {arquivo}...")

                file_hash = self.scanner.calcular_hash(caminho_completo)
                resultado = self.scanner.verificar_por_hash(file_hash)

                if resultado.get('response_code') == 0:
                    resultado_upload = self.scanner.enviar_arquivo(caminho_completo)
                    resultado_scan = resultado_upload
                    if resultado_upload.get('response_code') == 1:
                        for _ in range(5):
                            time.sleep(15)
                            resultado = self.scanner.verificar_por_hash(file_path) # Corrected variable name here
                            if resultado.get('response_code') == 1:
                                break

                if resultado and resultado.get('response_code') == 1:
                    current_scan['resultados'][arquivo] = resultado
                    self.resultados[arquivo] = resultado
                    self.root.after(0, self.processar_resultado, arquivo, resultado)
                elif resultado and resultado.get('response_code') == 0 and "error" in resultado:
                    self.root.after(0, self.adicionar_erro, arquivo, resultado["error"])
                elif resultado_scan and resultado_scan.get('response_code') == 0 and "error" in resultado_scan:
                    self.root.after(0, self.adicionar_erro, arquivo, resultado_scan["error"])
                else:
                    self.root.after(0, self.adicionar_erro, arquivo, "Falha na verificação (resposta inesperada da API)")


                self.root.after(0, self.atualizar_progresso, i + 1)
                time.sleep(15)

            except Exception as e:
                self.root.after(0, self.adicionar_erro, arquivo, str(e))

        self.scanning = False
        self.root.after(0, self.finalizar_verificacao)

    def processar_resultado(self, arquivo, resultado):
        if resultado['positives'] > 0:
            self.lista_maliciosos.insert(END, f"{arquivo} ({resultado['positives']}/{resultado['total']})")
        else:
            self.lista_seguros.insert(END, f"{arquivo} (0/{resultado['total']})")

        self.atualizar_contadores()

    def mostrar_detalhes(self, event):
        widget = event.widget
        if widget.curselection():
            index = widget.curselection()[0]
            item = widget.get(index)
            arquivo = item.split(' (')[0]

            resultado = self.resultados.get(arquivo)
            if resultado:
                detalhes = f"Arquivo: {arquivo}\n"
                detalhes += f"Detecções: {resultado['positives']}/{resultado['total']}\n"
                detalhes += f"Data da análise: {resultado.get('scan_date', 'Desconhecida')}\n"
                detalhes += f"Hash SHA-256: {resultado.get('sha256', '')}\n\n"

                if resultado['positives'] > 0:
                    detalhes += "Antivírus que detectaram:\n"
                    for av, data in resultado['scans'].items():
                        if data['detected']:
                            detalhes += f"• {av}: {data['result']}\n"

                messagebox.showinfo("Detalhes da Análise", detalhes)

    def carregar_historico(self, event):
        widget = event.widget
        if widget.curselection():
            try:
                index = widget.curselection()[0]
                scan = self.historico[index]

                self.limpar_resultados()
                self.resultados = scan['resultados'].copy()

                for arquivo, resultado in scan['resultados'].items():
                    if resultado['positives'] > 0:
                        self.lista_maliciosos.insert(END, f"{arquivo} ({resultado['positives']}/{resultado['total']})")
                    else:
                        self.lista_seguros.insert(END, f"{arquivo} ({resultado['total']})")

                self.atualizar_contadores()
                self.status.config(text=f"Carregado: {scan['id']}")
            except IndexError:
                pass
            except Exception as e:
                messagebox.showerror("Erro ao Carregar Histórico", f"Ocorreu um erro ao carregar o histórico de escaneamento: {str(e)}")


    def limpar_resultados(self):
        self.lista_maliciosos.delete(0, END)
        self.lista_seguros.delete(0, END)
        self.resultados.clear()
        self.progress['value'] = 0

    def adicionar_erro(self, arquivo, mensagem):
        self.lista_maliciosos.insert(END, f"{arquivo} (Erro: {mensagem})")
        self.atualizar_contadores()

    def atualizar_progresso(self, valor):
        self.progress['value'] = valor
        self.root.update_idletasks()

    def atualizar_contadores(self):
        pass

    def atualizar_status(self, mensagem):
        self.status.config(text=mensagem)
        self.root.update_idletasks()

    def finalizar_verificacao(self):
        self.atualizar_status("Verificação concluída!")
        if self.btn_arquivo:
            self.btn_arquivo.config(state=NORMAL)
        if self.btn_pasta:
            self.btn_pasta.config(state=NORMAL)
        messagebox.showinfo("Concluído", f"Verificação finalizada!\n\n"
                          f"Arquivos seguros: {self.lista_seguros.size()}\n"
                          f"Arquivos suspeitos: {self.lista_maliciosos.size()}")

    def verificar_api_key(self):
        if not self.scanner.API_KEY:
            messagebox.showerror("Erro", "Configure a API Key primeiro!")
            return False
        return True

if __name__ == "__main__":
    root = Tk()
    app = App(root)
    root.mainloop()