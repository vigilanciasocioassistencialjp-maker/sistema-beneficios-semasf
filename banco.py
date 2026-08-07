import os
import psycopg2
import bcrypt
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
        
        # =====================================================
        # MIGRAÇÃO: Recuperação de senha por e-mail
        # =====================================================
        for col, tipo in [('email', 'TEXT'), ('reset_token', 'TEXT'), ('reset_token_expira', 'TIMESTAMPTZ')]:
            cursor.execute(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_name='usuarios' AND column_name='{col}'
            """)
            if not cursor.fetchone():
                cursor.execute(f"ALTER TABLE usuarios ADD COLUMN {col} {tipo}")
                print(f"✅ Coluna usuarios.{col} adicionada!")

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

        # =====================================================
        # MIGRAÇÃO: Adiciona num_tentativas
        # =====================================================
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'solicitacoes' AND column_name = 'num_tentativas'
        """)
        if not cursor.fetchone():
            print("⚠️  Coluna num_tentativas não encontrada. Adicionando...")
            cursor.execute("ALTER TABLE solicitacoes ADD COLUMN num_tentativas INTEGER DEFAULT 1")
            print("✅ Coluna num_tentativas adicionada!")

        # =====================================================
        # MIGRAÇÃO: Adiciona valor_bolsa_familia
        # =====================================================
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'solicitacoes' AND column_name = 'valor_bolsa_familia'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE solicitacoes ADD COLUMN valor_bolsa_familia REAL DEFAULT 0")
            print("✅ Coluna valor_bolsa_familia adicionada!")

        # =====================================================
        # MIGRAÇÃO: Adiciona visita_domiciliar
        # =====================================================
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'solicitacoes' AND column_name = 'visita_domiciliar'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE solicitacoes ADD COLUMN visita_domiciliar BOOLEAN DEFAULT FALSE")
            print("✅ Coluna visita_domiciliar adicionada!")

        # =====================================================
        # MIGRAÇÃO: Campos de cancelamento
        # =====================================================
        for col, tipo in [('cancelado_por','TEXT'),('cancelado_em','TEXT'),('motivo_cancelamento','TEXT')]:
            cursor.execute(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_name='solicitacoes' AND column_name='{col}'
            """)
            if not cursor.fetchone():
                cursor.execute(f"ALTER TABLE solicitacoes ADD COLUMN {col} {tipo}")
                print(f"✅ Coluna {col} adicionada!")

        # Tabela de notificações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notificacoes (
                id SERIAL PRIMARY KEY,
                destinatario TEXT NOT NULL,
                remetente TEXT NOT NULL,
                mensagem TEXT NOT NULL,
                tipo TEXT DEFAULT 'geral',
                lida BOOLEAN DEFAULT FALSE,
                criada_em TEXT NOT NULL,
                solicitacao_id INTEGER
            )
        ''')

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

        # Tabela de mapeamento CRAS → Bairros (editável pelo admin/gestor)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cras_bairros (
                id SERIAL PRIMARY KEY,
                cras TEXT NOT NULL,
                bairro TEXT NOT NULL UNIQUE
            )
        ''')

        # Popula cras_bairros com dados iniciais se estiver vazia
        cursor.execute("SELECT COUNT(*) FROM cras_bairros")
        if cursor.fetchone()[0] == 0:
            print("⚠️  Tabela cras_bairros vazia. Populando com dados iniciais...")
            bairros_iniciais = [
                ('CRAS MORAR MELHOR','MORAR MELHOR'),('CRAS MORAR MELHOR','BELA VISTA'),
                ('CRAS MORAR MELHOR','CONDOMÍNIO JI-PARANÁ'),('CRAS MORAR MELHOR','CASA PRETA'),
                ('CRAS MORAR MELHOR','DOM BOSCO'),('CRAS MORAR MELHOR','DISTRITO INDUSTRIAL'),
                ('CRAS MORAR MELHOR','JARDIM AURÉLIO BERNARDES'),('CRAS MORAR MELHOR','NOVO HORIZONTE'),
                ('CRAS MORAR MELHOR','PARQUE SÃO PEDRO'),('CRAS MORAR MELHOR','PARK AMAZONAS'),
                ('CRAS MORAR MELHOR','RESIDENCIAL AÇAÍ'),('CRAS MORAR MELHOR','RESIDENCIAL ARAÇÁ'),
                ('CRAS MORAR MELHOR','RESIDENCIAL COLINA PARK'),('CRAS MORAR MELHOR','RESIDENCIAL JATOBÁ'),
                ('CRAS MORAR MELHOR','SÃO BERNARDO'),('CRAS MORAR MELHOR','VILA OPERÁRIOS'),
                ('CRAS MORAR MELHOR','ÁREA RURAL DO 1º DISTRITO'),
                ('CRAS JARDIM DOS MIGRANTES','BOSQUE DOS IPÊS'),('CRAS JARDIM DOS MIGRANTES','CENTRO'),
                ('CRAS JARDIM DOS MIGRANTES','CIDADE JARDIM'),('CRAS JARDIM DOS MIGRANTES','DOIS DE ABRIL'),
                ('CRAS JARDIM DOS MIGRANTES','JARDIM DOS MIGRANTES'),('CRAS JARDIM DOS MIGRANTES','JARDIM PRESIDENCIAL I'),
                ('CRAS JARDIM DOS MIGRANTES','JARDIM PRESIDENCIAL II'),('CRAS JARDIM DOS MIGRANTES','JARDIM PRESIDENCIAL III'),
                ('CRAS JARDIM DOS MIGRANTES','NOVO URUPÁ'),('CRAS JARDIM DOS MIGRANTES','NOVO JI-PARANÁ'),
                ('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL ALDEIA DO LAGO'),('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL COPAS VERDES'),
                ('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL GREEN PARK'),('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL MILÃO'),
                ('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL PLANALTO I'),('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL PLANALTO II'),
                ('CRAS JARDIM DOS MIGRANTES','RESIDENCIAL VENEZA'),("CRAS JARDIM DOS MIGRANTES","RESIDENCIAL ESPELHO D'ÁGUA"),
                ('CRAS JARDIM DOS MIGRANTES','ESPELHO ECOVILLE'),('CRAS JARDIM DOS MIGRANTES','SANTIAGO'),
                ('CRAS JARDIM DOS MIGRANTES','SETOR CHACAREIRO'),('CRAS JARDIM DOS MIGRANTES','VAL PARAÍSO'),
                ('CRAS JARDIM DOS MIGRANTES','UNIÃO'),('CRAS JARDIM DOS MIGRANTES','URUPÁ'),
                ('CRAS JARDIM DOS MIGRANTES','VILA DE RONDÔNIA'),('CRAS JARDIM DOS MIGRANTES','GLEBA G'),
                ('CRAS JARDIM DOS MIGRANTES','NOVA LONDRINA'),
                ('CRAS SÃO FRANCISCO','RESIDENCIAL RONDON'),('CRAS SÃO FRANCISCO','DUQUE DE CAXIAS'),
                ('CRAS SÃO FRANCISCO','JARDIM DAS SERINGUEIRAS'),('CRAS SÃO FRANCISCO','JARDIM SÃO CRISTÓVÃO'),
                ('CRAS SÃO FRANCISCO','JARDIM FLÓRIDA'),('CRAS SÃO FRANCISCO','LOTEAMENTO RONDON I'),
                ('CRAS SÃO FRANCISCO','NOVA BRASÍLIA'),('CRAS SÃO FRANCISCO','PRIMAVERA'),
                ('CRAS SÃO FRANCISCO','RIACHUELO'),('CRAS SÃO FRANCISCO','SÃO FRANCISCO'),
                ('CRAS SÃO FRANCISCO','SÃO PEDRO'),('CRAS SÃO FRANCISCO','VILA JOTÃO'),
                ('CRAS SÃO FRANCISCO','ÁREA RURAL DO 2° DISTRITO'),('CRAS SÃO FRANCISCO','LINHA PIRINEUS'),
                ('CRAS SÃO FRANCISCO','TALISMÃ'),
                ('CRAS RODA MOINHO','CAPELASSO'),('CRAS RODA MOINHO','ALTO ALEGRE'),
                ('CRAS RODA MOINHO','BOA ESPERANÇA'),('CRAS RODA MOINHO','CONJUNTO HABITACIONAL PARECIS'),
                ('CRAS RODA MOINHO','CAFEZINHO'),('CRAS RODA MOINHO','GREENVILLE'),
                ('CRAS RODA MOINHO','HABITAR BRASIL'),('CRAS RODA MOINHO','JORGE TEIXEIRA'),
                ('CRAS RODA MOINHO','JK'),('CRAS RODA MOINHO','MÁRIO ANDREAZZA/BNH'),
                ('CRAS RODA MOINHO','NOSSA SENHORA DE FÁTIMA'),('CRAS RODA MOINHO','PARQUE DOS PIONEIROS'),
                ('CRAS RODA MOINHO','PARK BRASIL'),('CRAS RODA MOINHO','RESIDENCIAL CARNEIRO'),
                ('CRAS RODA MOINHO','RESIDENCIAL TERRA NOVA'),('CRAS RODA MOINHO','RESIDENCIAL ORLEANS I'),
                ('CRAS RODA MOINHO','RESIDENCIAL ORLEANS II'),('CRAS RODA MOINHO','UNIÃO II'),
                ('CRAS RODA MOINHO','DISTRITO NOVA COLINA'),('CRAS RODA MOINHO','ALDEIAS INDÍGENAS'),
            ]
            cursor.executemany(
                "INSERT INTO cras_bairros (cras, bairro) VALUES (%s,%s) ON CONFLICT (bairro) DO NOTHING",
                bairros_iniciais
            )
            print("✅ Bairros iniciais inseridos!")

        # =====================================================
        # MIGRAÇÃO: flag de entrega pela Equipe Volante
        # (bairros de área rural: escuta é feita no CRAS, mas a
        # entrega da cesta é responsabilidade da Equipe Volante)
        # =====================================================
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'cras_bairros' AND column_name = 'entrega_volante'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE cras_bairros ADD COLUMN entrega_volante BOOLEAN DEFAULT FALSE")
            # Pré-marca os bairros claramente rurais; o gestor pode ajustar
            # os demais na tela de Configurações
            cursor.execute("""
                UPDATE cras_bairros SET entrega_volante = TRUE
                WHERE bairro LIKE '%RURAL%'
                   OR bairro LIKE 'LINHA %'
                   OR bairro LIKE '%ALDEIAS%'
                   OR bairro = 'DISTRITO NOVA COLINA'
                   OR bairro = 'SETOR CHACAREIRO'
            """)
            print(f"✅ Coluna entrega_volante adicionada ({cursor.rowcount} bairro(s) rural(is) pré-marcado(s))!")

        # MIGRAÇÃO: renomear perfil 'tecnico' → 'cras'
        cursor.execute("UPDATE usuarios SET perfil = 'cras' WHERE perfil = 'tecnico'")
        if cursor.rowcount > 0:
            print(f"✅ {cursor.rowcount} usuário(s) migrado(s): perfil 'tecnico' → 'cras'")

        # =====================================================
        # MIGRAÇÃO: acesso à página de Fotos das Atividades — permissão
        # extra que se soma ao perfil já existente do usuário (cras/creas/
        # cras_volante/gestor/admin mantêm exatamente o acesso que já têm)
        # =====================================================
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'usuarios' AND column_name = 'acesso_atividades'
        """)
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE usuarios ADD COLUMN acesso_atividades BOOLEAN DEFAULT FALSE")
            print("✅ Coluna usuarios.acesso_atividades adicionada!")

        # Tabela de atividades/ações registradas para o Quadrimestral
        # (fotos de atendimentos/grupos com legenda, enviadas por coordenadoras)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS atividades_fotos (
                id SERIAL PRIMARY KEY,
                titulo TEXT NOT NULL,
                data_atividade TEXT NOT NULL,
                servico TEXT,
                descricao TEXT,
                criado_por TEXT NOT NULL,
                criado_em TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fotos_atividade (
                id SERIAL PRIMARY KEY,
                atividade_id INTEGER NOT NULL REFERENCES atividades_fotos(id) ON DELETE CASCADE,
                storage_path TEXT NOT NULL,
                legenda TEXT,
                ordem INTEGER DEFAULT 0,
                criado_em TEXT NOT NULL
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

        # Cria admin padrão via variável de ambiente se não houver nenhum usuário
        cursor2 = conn.cursor()
        cursor2.execute("SELECT COUNT(*) FROM usuarios")
        if cursor2.fetchone()[0] == 0:
            admin_user  = os.environ.get('ADMIN_USER',  'admin')
            admin_senha = os.environ.get('ADMIN_SENHA', '')
            admin_nome  = os.environ.get('ADMIN_NOME',  'Administrador')
            if admin_senha:
                senha_hash = bcrypt.hashpw(admin_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor2.execute(
                    "INSERT INTO usuarios (usuario, nome, senha, perfil, primeiro_acesso) VALUES (%s, %s, %s, 'admin', 1)",
                    (admin_user, admin_nome, senha_hash)
                )
                conn.commit()
                print(f"✅ Admin padrão criado: usuário '{admin_user}' (troque a senha no primeiro acesso)")
            else:
                print("⚠️  Banco vazio e ADMIN_SENHA não definida — nenhum admin criado.")
        cursor2.close()

        conn.commit()
        cursor.close()
        _devolver_conexao(conn)

        print("✅ Tabelas criadas/verificadas no Supabase!")
        print("🎉 Banco de dados pronto para uso!")

    except Exception as e:
        print(f"❌ Erro ao criar tabelas: {e}")
        raise e
