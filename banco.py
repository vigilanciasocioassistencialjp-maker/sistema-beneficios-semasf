import os
import psycopg2

# =====================================================
# CONEXÃO COM SUPABASE POSTGRESQL
# =====================================================

def get_db_connection():
    """Retorna conexão com o banco Supabase PostgreSQL"""
    
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        raise Exception("❌ Variável de ambiente 'DATABASE_URL' não encontrada!")
    
    try:
        conn = psycopg2.connect(
            database_url,
            connect_timeout=10,
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=5
        )
        print("✅ Conectado ao Supabase PostgreSQL!")
        return conn
        
    except Exception as e:
        print(f"❌ Erro fatal na conexão com Supabase: {e}")
        raise e


# =====================================================
# CRIAÇÃO DAS TABELAS
# =====================================================

def criar_banco():
    """Cria as tabelas se não existirem no Supabase"""
    
    try:
        conn = get_db_connection()
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
        
        # Tabela de solicitações (com cpf_hash desde o início)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS solicitacoes (
                id SERIAL PRIMARY KEY,
                tecnico TEXT,
                cpf TEXT,
                cpf_hash TEXT,
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
                tecnico_entrega TEXT,
                excecao_art64 BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # =====================================================
        # MIGRAÇÃO: Adiciona excecao_art64 se a tabela já existe
        # =====================================================
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'solicitacoes' AND column_name = 'excecao_art64'
        """)
        if not cursor.fetchone():
            print("⚠️  Coluna excecao_art64 não encontrada. Adicionando...")
            cursor.execute("ALTER TABLE solicitacoes ADD COLUMN excecao_art64 BOOLEAN DEFAULT FALSE")
            print("✅ Coluna excecao_art64 adicionada!")

        # =====================================================
        # MIGRAÇÃO: Adiciona cpf_hash se a tabela já existe
        # sem a coluna (bancos criados antes da criptografia)
        # =====================================================
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'solicitacoes' AND column_name = 'cpf_hash'
        """)
        if not cursor.fetchone():
            print("⚠️  Coluna cpf_hash não encontrada. Adicionando...")
            cursor.execute("ALTER TABLE solicitacoes ADD COLUMN cpf_hash TEXT")
            print("✅ Coluna cpf_hash adicionada!")

        # Tabela de configurações do sistema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuracoes (
                chave TEXT PRIMARY KEY,
                valor TEXT NOT NULL,
                descricao TEXT,
                atualizado_em TEXT
            )
        ''')

        # Inserir salário mínimo padrão se ainda não existir
        cursor.execute("""
            INSERT INTO configuracoes (chave, valor, descricao, atualizado_em)
            VALUES ('salario_minimo', '1621.00', 'Salário mínimo nacional vigente (R$)', NOW()::text)
            ON CONFLICT (chave) DO UPDATE
                SET valor = '1621.00', atualizado_em = NOW()::text
                WHERE configuracoes.valor = '1518.00'
        """)

        conn.commit()
        cursor.close()
        conn.close()
        
        print("✅ Tabelas criadas/verificadas no Supabase!")
        print("🎉 Banco de dados pronto para uso!")
        
    except Exception as e:
        print(f"❌ Erro ao criar tabelas: {e}")
        raise e
