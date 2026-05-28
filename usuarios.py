from flask_login import UserMixin

import sqlite3

# =====================================================
# CLASSE USUÁRIO
# =====================================================

class Usuario(UserMixin):

    def __init__(self, id, perfil, cras=None, nome=None):
        self.id = id
        self.perfil = perfil
        self.cras = cras  # CRAS de referência do técnico
        self.nome = nome if nome else id

# =====================================================
# CARREGAR USUÁRIO
# =====================================================

def carregar_usuario(usuario):

    conexao = sqlite3.connect("sistema.db")
    cursor = conexao.cursor()

    cursor.execute("""
        SELECT usuario, perfil, cras, nome
        FROM usuarios
        WHERE usuario = ?
    """, (usuario,))

    dados = cursor.fetchone()
    conexao.close()

    if dados:
        return Usuario(
            dados[0],  # id
            dados[1],  # perfil
            dados[2],  # cras
            dados[3] if len(dados) > 3 and dados[3] else dados[0]  # nome
        )

    return None