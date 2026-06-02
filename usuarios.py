import os
from flask_login import UserMixin
from banco import get_db_connection

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
# CARREGAR USUÁRIO - FUNCIONA COM SQLITE E POSTGRESQL
# =====================================================

def carregar_usuario(usuario):
    """
    Carrega usuário do banco de dados.
    Funciona tanto com SQLite (local) quanto com PostgreSQL (Supabase/Render)
    
    Args:
        usuario (str): Nome de usuário/login
    
    Returns:
        Usuario: Objeto Usuario se encontrado, None caso contrário
    """
    try:
        # Usa a mesma conexão do banco.py (resolve o tipo automaticamente)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Identifica se é PostgreSQL ou SQLite para usar o marcador correto
        database_url = os.environ.get('DATABASE_URL')
        marcador = "%s" if database_url else "?"
        
        # Busca o usuário no banco
        cursor.execute(f"""
            SELECT usuario, perfil, cras, nome
            FROM usuarios
            WHERE usuario = {marcador}
        """, (usuario,))
        
        dados = cursor.fetchone()
        
        # Fecha cursor e conexão
        cursor.close()
        conn.close()
        
        # Se encontrou o usuário, cria e retorna o objeto
        if dados:
            # Converte para os tipos corretos
            return Usuario(
                str(dados[0]),  # id (garante que é string para o Flask-Login)
                dados[1],       # perfil
                dados[2],       # cras (pode ser None)
                dados[3] if len(dados) > 3 and dados[3] else dados[0]  # nome
            )
        
        return None
        
    except Exception as e:
        print(f"⚠️ Erro ao carregar usuário {usuario}: {e}")
        return None


# =====================================================
# FUNÇÃO AUXILIAR - LISTAR TODOS OS USUÁRIOS
# =====================================================

def listar_usuarios():
    """
    Retorna lista de todos os usuários do sistema.
    Útil para relatórios e administração.
    
    Returns:
        list: Lista de tuplas com dados dos usuários
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Identifica o marcador
        database_url = os.environ.get('DATABASE_URL')
        marcador = "%s" if database_url else "?"
        
        cursor.execute(f"""
            SELECT id, usuario, nome, perfil, cras, primeiro_acesso
            FROM usuarios
            ORDER BY id
        """)
        
        usuarios = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return usuarios
        
    except Exception as e:
        print(f"⚠️ Erro ao listar usuários: {e}")
        return []


# =====================================================
# FUNÇÃO AUXILIAR - BUSCAR USUÁRIO POR ID
# =====================================================

def buscar_usuario_por_id(user_id):
    """
    Busca um usuário pelo ID numérico
    
    Args:
        user_id (int): ID do usuário
    
    Returns:
        tuple: Dados do usuário ou None
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Identifica o marcador
        database_url = os.environ.get('DATABASE_URL')
        marcador = "%s" if database_url else "?"
        
        cursor.execute(f"""
            SELECT id, usuario, nome, perfil, cras, primeiro_acesso
            FROM usuarios
            WHERE id = {marcador}
        """, (user_id,))
        
        usuario = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return usuario
        
    except Exception as e:
        print(f"⚠️ Erro ao buscar usuário por ID {user_id}: {e}")
        return None


# =====================================================
# FUNÇÃO AUXILIAR - VERIFICAR SE USUÁRIO EXISTE
# =====================================================

def usuario_existe(usuario):
    """
    Verifica se um nome de usuário já existe no banco
    
    Args:
        usuario (str): Nome de usuário
    
    Returns:
        bool: True se existe, False caso contrário
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Identifica o marcador
        database_url = os.environ.get('DATABASE_URL')
        marcador = "%s" if database_url else "?"
        
        cursor.execute(f"""
            SELECT COUNT(*) FROM usuarios
            WHERE usuario = {marcador}
        """, (usuario,))
        
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        
        return count > 0
        
    except Exception as e:
        print(f"⚠️ Erro ao verificar existência do usuário {usuario}: {e}")
        return False
