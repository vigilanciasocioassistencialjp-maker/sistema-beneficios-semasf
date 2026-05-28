import os
import sqlite3

def criar_banco():
    # Determinar o caminho do banco
    if os.environ.get('PYTHONANYWHERE_DOMAIN'):
        # No PythonAnywhere, salvar na pasta home
        db_path = '/home/' + os.environ.get('USER', 'seu_usuario') + '/sistema.db'
    else:
        # Localmente
        db_path = "sistema.db"
    
    conexao = sqlite3.connect(db_path)
    cursor = conexao.cursor()
    
    # Tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            nome TEXT NOT NULL,
            senha TEXT NOT NULL,
            perfil TEXT NOT NULL,
            cras TEXT,
            primeiro_acesso INTEGER DEFAULT 1
        )
    """)
    
    # Tabela de solicitações
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS solicitacoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tecnico TEXT NOT NULL,
            cpf TEXT NOT NULL,
            nome TEXT NOT NULL,
            data_nascimento TEXT,
            telefone TEXT,
            email TEXT,
            endereco TEXT,
            numero TEXT,
            complemento TEXT,
            bairro TEXT,
            cep TEXT,
            referencia TEXT,
            cras TEXT NOT NULL,
            data_escuta TEXT,
            total_pessoas INTEGER,
            composicao_familiar TEXT,
            renda_bruta REAL,
            renda_per_capita REAL,
            beneficios TEXT,
            vulnerabilidade TEXT,
            servicos_suas TEXT,
            parecer TEXT,
            status TEXT DEFAULT 'Cadastrada',
            data_solicitacao TEXT,
            data_entrega TEXT,
            tecnico_entrega TEXT
        )
    """)
    
    # Verificar se existe usuário admin
    cursor.execute("SELECT * FROM usuarios WHERE usuario = 'admin'")
    if not cursor.fetchone():
        import bcrypt
        salt = bcrypt.gensalt()
        senha_hash = bcrypt.hashpw('admin123'.encode('utf-8'), salt).decode('utf-8')
        cursor.execute("""
            INSERT INTO usuarios (usuario, nome, senha, perfil, cras, primeiro_acesso)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('admin', 'Administrador', senha_hash, 'gestor', None, 0))
    
    conexao.commit()
    conexao.close()
    print(f"✅ Banco criado em: {db_path}")