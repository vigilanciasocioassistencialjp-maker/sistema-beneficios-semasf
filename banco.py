import os
import sqlite3
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# =====================================================
# CONFIGURAÇÃO DA STRING DE CONEXÃO (COM DEBUG E FALLBACK)
# =====================================================

def get_db_connection():
    """Retorna conexão com o banco (SQLite local ou PostgreSQL no Supabase)"""
    
    # Tenta pegar a variável de ambiente
    database_url = os.environ.get('DATABASE_URL')
    
    # LOG DE DIAGNÓSTICO (aparece nos logs do Render)
    if database_url:
        # Mostra apenas o início para não expor a senha, mas confirma que a variável EXISTE
        print(f"🔍 [DEBUG] DATABASE_URL encontrada! (início: {database_url[:40]}...)")
    else:
        print("❌ [DEBUG] Variável de ambiente 'DATABASE_URL' não encontrada!")
        print("📦 Usando SQLite como fallback.")
        conn = sqlite3.connect('sistema.db')
        conn.row_factory = sqlite3.Row
        return conn

    # Tenta conectar ao PostgreSQL (caso a variável exista)
    try:
        conn = psycopg2.connect(database_url)
        print("✅ [SUCESSO] Conectado ao Supabase com PostgreSQL!")
        return conn
    except Exception as e:
        print(f"❌ [ERRO] Falha na conexão com Supabase: {e}")
        print("📦 Usando SQLite como fallback.")
        conn = sqlite3.connect('sistema.db')
        conn.row_factory = sqlite3.Row
        return conn


# =====================================================
# CRIAÇÃO DAS TABELAS (FUNCIONA COM SQLITE E POSTGRESQL)
# =====================================================

def criar_banco():
    """Cria as tabelas se não existirem (funciona para SQLite e PostgreSQL)"""
    database_url = os.environ.get('DATABASE_URL')
    
    # Verifica se deve usar PostgreSQL ou SQLite
    usar_postgres = False
    
    if database_url:
        try:
            # Testa a conexão antes de prosseguir
            conn_test = psycopg2.connect(database_url)
            conn_test.close()
            usar_postgres = True
            print("🐘 Usando PostgreSQL para criar tabelas")
        except Exception as e:
            print(f"⚠️ PostgreSQL indisponível: {e}")
            print("📦 Usando SQLite como fallback")
            usar_postgres = False
    else:
        print("📦 DATABASE_URL não encontrada. Usando SQLite para criar tabelas")
    
    if usar_postgres:
        # =============================================
        # POSTGRESQL (SUPABASE)
        # =============================================
        conn = psycopg2.connect(database_url)
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Tabela de usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                usuario TEXT UNIQUE NOT NULL,
                nome TEXT NOT NULL,
                senha TEXT NOT NULL,
                perfil TEXT NOT NULL,
                cras TEXT,
                primeiro_acesso INTEGER DEFAULT 1
            )
        ''')
        
        # Tabela de solicitações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS solicitacoes (
                id SERIAL PRIMARY KEY,
                tecnico TEXT,
                cpf TEXT,
                nome TEXT,
                data_nascimento TEXT,
                telefone TEXT,
                email TEXT,
                endereco TEXT,
                numero TEXT,
                complemento TEXT,
                bairro TEXT,
                cep TEXT,
                referencia TEXT,
                cras TEXT,
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
        ''')
        
        cursor.close()
        conn.close()
        print("✅ Tabelas criadas/verificadas no PostgreSQL (Supabase)")
        
    else:
        # =============================================
        # SQLITE (LOCAL OU FALLBACK)
        # =============================================
        conn = sqlite3.connect('sistema.db')
        cursor = conn.cursor()
        
        # Tabela de usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT UNIQUE NOT NULL,
                nome TEXT NOT NULL,
                senha TEXT NOT NULL,
                perfil TEXT NOT NULL,
                cras TEXT,
                primeiro_acesso INTEGER DEFAULT 1
            )
        ''')
        
        # Tabela de solicitações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS solicitacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tecnico TEXT,
                cpf TEXT,
                nome TEXT,
                data_nascimento TEXT,
                telefone TEXT,
                email TEXT,
                endereco TEXT,
                numero TEXT,
                complemento TEXT,
                bairro TEXT,
                cep TEXT,
                referencia TEXT,
                cras TEXT,
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
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Tabelas criadas/verificadas no SQLite")
    
    print("🎉 Banco de dados pronto para uso!")
