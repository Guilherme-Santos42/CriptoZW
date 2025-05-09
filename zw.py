import os
import base64
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Configurações
senha_padrao = "ZWWorld"
salt = b'\x00' * 16  # SALT fixo
backend = default_backend()

# Funções de criptografia
def gerar_chave(senha_usuario):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(senha_usuario.encode()))

def criptografar_arquivo(caminho_arquivo, fernet):
    with open(caminho_arquivo, 'rb') as file:
        dados = file.read()
    dados_criptografados = fernet.encrypt(dados)
    with open(caminho_arquivo, 'wb') as file:
        file.write(dados_criptografados)

def descriptografar_arquivo(caminho_arquivo, fernet):
    with open(caminho_arquivo, 'rb') as file:
        dados_criptografados = file.read()
    dados = fernet.decrypt(dados_criptografados)
    with open(caminho_arquivo, 'wb') as file:
        file.write(dados)

def processar_pasta(caminho_base, fernet, modo="criptografar"):
    todos_arquivos = []
    for pasta, subpastas, arquivos in os.walk(caminho_base):
        for arquivo in arquivos:
            todos_arquivos.append(os.path.join(pasta, arquivo))

    total = len(todos_arquivos)
    progresso["maximum"] = total

    for i, caminho_arquivo in enumerate(todos_arquivos, start=1):
        try:
            if modo == "criptografar":
                criptografar_arquivo(caminho_arquivo, fernet)
            else:
                descriptografar_arquivo(caminho_arquivo, fernet)
        except Exception as e:
            print(f"Erro no arquivo {caminho_arquivo}: {e}")
        progresso["value"] = i
        janela.update_idletasks()

def iniciar_criptografia():
    senha_usuario = entrada_senha.get()
    if senha_usuario != senha_padrao:
        messagebox.showerror("Erro", "Senha incorreta!")
        return

    pasta = filedialog.askdirectory(title="Selecione a pasta para criptografar")
    if not pasta:
        return

    chave = gerar_chave(senha_usuario)
    fernet = Fernet(chave)
    progresso["value"] = 0
    processar_pasta(pasta, fernet, modo="criptografar")
    messagebox.showinfo("Sucesso", "Criptografia concluída!")

def iniciar_descriptografia():
    senha_usuario = entrada_senha.get()
    if senha_usuario != senha_padrao:
        messagebox.showerror("Erro", "Senha incorreta!")
        return

    pasta = filedialog.askdirectory(title="Selecione a pasta para descriptografar")
    if not pasta:
        return

    chave = gerar_chave(senha_usuario)
    fernet = Fernet(chave)
    progresso["value"] = 0
    processar_pasta(pasta, fernet, modo="descriptografar")
    messagebox.showinfo("Sucesso", "Descriptografia concluída!")

# Interface moderna
janela = ttk.Window(themename="darkly")  # temas: darkly, cyborg, superhero, etc
janela.title("ZWWorld Encryption")
janela.geometry("450x300")
janela.resizable(False, False)

# Layout
titulo = ttk.Label(janela, text="ZWWorld Encryption Tool", font=("Helvetica", 18, "bold"), bootstyle="primary")
titulo.pack(pady=15)

frame_principal = ttk.Frame(janela, padding=20)
frame_principal.pack(pady=10)

ttk.Label(frame_principal, text="Digite a senha:", font=("Helvetica", 12)).pack(pady=5)
entrada_senha = ttk.Entry(frame_principal, show="*", font=("Helvetica", 12), width=30)
entrada_senha.pack()

progresso = ttk.Progressbar(frame_principal, bootstyle="success-striped", length=250, mode="determinate")
progresso.pack(pady=20)

frame_botoes = ttk.Frame(frame_principal)
frame_botoes.pack(pady=10)

botao_criptografar = ttk.Button(frame_botoes, text="Criptografar", width=18, bootstyle="success", command=iniciar_criptografia)
botao_criptografar.grid(row=0, column=0, padx=10)

botao_descriptografar = ttk.Button(frame_botoes, text="Descriptografar", width=18, bootstyle="warning", command=iniciar_descriptografia)
botao_descriptografar.grid(row=0, column=1, padx=10)

janela.mainloop()
