from flask_login import UserMixin
from banco import get_db_connection, _devolver_conexao

class Usuario(UserMixin):
    def __init__(self, id, perfil, cras=None, nome=None, acesso_atividades=False, unidade_id=None):
        self.id = id
        self.perfil = perfil
        self.cras = cras
        self.nome = nome
        self.acesso_atividades = acesso_atividades
        self.unidade_id = unidade_id

def carregar_usuario(user_id):
    """Carrega usuário do banco Supabase"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT usuario, perfil, cras, nome, acesso_atividades, unidade_id
            FROM usuarios
            WHERE usuario = %s
        """, (user_id,))
        dados = cursor.fetchone()
        cursor.close()
    finally:
        _devolver_conexao(conn)  # sempre devolve ao pool, nunca fecha

    if dados:
        return Usuario(dados[0], dados[1], dados[2], dados[3], dados[4], dados[5])
    return None
