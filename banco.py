# banco.py - VERSÃO PYTHONANYWHERE (MYSQL)
import MySQLdb
import os

# =====================================================
# CONFIGURAÇÃO DO MYSQL NO PYTHONANYWHERE
# =====================================================

def get_db_connection():
    """Retorna conexão com MySQL do PythonAnywhere"""
    try:
        conn = MySQLdb.connect(
            host='SEU_USUARIO.mysql.pythonanywhere-services.com',
            user='SEU_USUARIO',
            passwd='SUA_SENHA_MYSQL',
            db='SEU_USUARIO$default',
            charset='utf8mb4',
            use_unicode=True
        )
        return conn
    except Exception as e:
        print(f"❌ Erro na conexão MySQL: {e}")
        raise e


def criar_banco():
    """Cria as tabelas se não existirem"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Tabela de usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                usuario VARCHAR(50) UNIQUE NOT NULL,
                nome VARCHAR(100) NOT NULL,
                senha VARCHAR(255) NOT NULL,
                perfil VARCHAR(20) NOT NULL,
                cras VARCHAR(50),
                primeiro_acesso TINYINT DEFAULT 1
            ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        ''')
        
        # Tabela de solicitações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS solicitacoes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                tecnico VARCHAR(50),
                cpf VARCHAR(20),
                nome VARCHAR(100),
                data_nascimento VARCHAR(20),
                telefone VARCHAR(20),
                email VARCHAR(100),
                endereco VARCHAR(200),
                numero VARCHAR(10),
                complemento VARCHAR(100),
                bairro VARCHAR(100),
                cep VARCHAR(20),
                referencia VARCHAR(200),
                cras VARCHAR(50),
                data_escuta VARCHAR(20),
                total_pessoas INT,
                composicao_familiar TEXT,
                renda_bruta DECIMAL(10,2),
                renda_per_capita DECIMAL(10,2),
                beneficios TEXT,
                vulnerabilidade TEXT,
                servicos_suas TEXT,
                parecer TEXT,
                status VARCHAR(20) DEFAULT 'Cadastrada',
                data_solicitacao VARCHAR(30),
                data_entrega VARCHAR(30),
                tecnico_entrega VARCHAR(50)
            ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        ''')
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Tabelas criadas/verificadas no MySQL (PythonAnywhere)")
        print("🎉 Banco de dados pronto para uso!")
        
    except Exception as e:
        print(f"❌ Erro ao criar tabelas: {e}")
        raise e
