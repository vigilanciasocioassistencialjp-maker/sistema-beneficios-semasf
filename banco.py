import os
import psycopg2
from psycopg2 import pool as pg_pool

# =====================================================
# POOL DE CONEXÕES COM SUPABASE POSTGRESQL
# =====================================================

_pool = None

def _criar_pool():
    """Cria o pool de conexões (chamado na inicialização)"""
    global _pool
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        raise Exception("❌ Variável de ambiente 'DATABASE_URL' não encontrada!")
    _pool = pg_pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=database_url,
        connect_timeout=10,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
    )
    print("✅ Pool de conexões criado (1–10 conexões)!")

def get_db_connection():
    """Retorna uma conexão do pool. Deve ser fechada com conn.close() após uso."""
    global _pool
    if _pool is None or _pool.closed:
        _criar_pool()
    try:
        conn = _pool.getconn()
        conn.autocommit = False
        return conn
    except Exception as e:
        print(f"❌ Erro ao obter conexão do pool: {e}")
        raise e

def _devolver_conexao(conn):
    """Devolve a conexão ao pool (uso interno)."""
    global _pool
    if _pool and not _pool.closed:
        try:
            _pool.putconn(conn)
        except Exception:
            pass


# =====================================================
# CRIAÇÃO DAS TABELAS
# =====================================================

def criar_banco():
    """Cria o pool e as tabelas se não existirem no Supabase"""

    # Garante que o pool existe antes de qualquer uso
    global _pool
    if _pool is None or _pool.closed:
        _criar_pool()

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

        # =====================================================
        # MIGRAÇÃO: Índice para busca rápida por cpf_hash
        # =====================================================
        cursor.execute("""
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'solicitacoes' AND indexname = 'idx_solicitacoes_cpf_hash'
        """)
        if not cursor.fetchone():
            print("⚠️  Índice idx_solicitacoes_cpf_hash não encontrado. Criando...")
            cursor.execute("CREATE INDEX idx_solicitacoes_cpf_hash ON solicitacoes (cpf_hash)")
            print("✅ Índice idx_solicitacoes_cpf_hash criado!")

        # =====================================================
        # MIGRAÇÃO: Adiciona observacoes_entrega
        # =====================================================
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'solicitacoes' AND column_name = 'observacoes_entrega'
        """)
        if not cursor.fetchone():
            print("⚠️  Coluna observacoes_entrega não encontrada. Adicionando...")
            cursor.execute("ALTER TABLE solicitacoes ADD COLUMN observacoes_entrega TEXT")
            print("✅ Coluna observacoes_entrega adicionada!")

        # Tabela de histórico de edições
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS historico_edicoes (
                id SERIAL PRIMARY KEY,
                solicitacao_id INTEGER NOT NULL,
                usuario TEXT NOT NULL,
                campo TEXT NOT NULL,
                valor_antes TEXT,
                valor_depois TEXT,
                data_hora TEXT NOT NULL
            )
        ''')

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
        _devolver_conexao(conn)

        print("✅ Tabelas criadas/verificadas no Supabase!")
        print("🎉 Banco de dados pronto para uso!")

    except Exception as e:
        print(f"❌ Erro ao criar tabelas: {e}")
        raise e
