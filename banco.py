import os
import sqlite3
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT


def get_db_connection():
    """Retorna conexão com o banco (SQLite local ou PostgreSQL no Render)"""
    database_url = os.environ.get('postgresql://sistema_user:rUL4zd6RfSOJ6YEV6tQx6P6kfnv141qe@dpg-d8a3ka3eo5us739d9o30-a.oregon-postgres.render.com/sistema_cestas')

    if database_url:
        # PostgreSQL no Render
        conn = psycopg2.connect(database_url)
        return conn
    else:
        # SQLite local
        return sqlite3.connect('sistema.db')


def criar_banco():
    """Cria as tabelas se não existirem (funciona para SQLite e PostgreSQL)"""
    database_url = os.environ.get('postgresql://sistema_user:rUL4zd6RfSOJ6YEV6tQx6P6kfnv141qe@dpg-d8a3ka3eo5us739d9o30-a.oregon-postgres.render.com/sistema_cestas')

    if database_url:
        # PostgreSQL
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

    else:
        # SQLite
        conn = sqlite3.connect('sistema.db')
        cursor = conn.cursor()

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

    print("✅ Banco de dados criado/verificado com sucesso!")