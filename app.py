from flask import Flask, render_template, request, redirect, url_for, send_file, flash, get_flashed_messages, session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from usuarios import Usuario, carregar_usuario
from banco import criar_banco, get_db_connection
import os
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import bcrypt
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
import io
import qrcode
import secrets
import logging
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet

# =====================================================
# CONFIGURAÇÃO DO APP
# =====================================================

app = Flask(__name__)

# 🔒 Secret key SEGURA (gerada automaticamente ou via variável de ambiente)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# 🕐 Fuso horário de Rondônia (UTC-4)
FUSO_RONDONIA = timezone(timedelta(hours=-4))

# 🔐 Configurar criptografia para CPF
CHAVE_CRIPTO = os.environ.get('CHAVE_CRIPTO')
if not CHAVE_CRIPTO:
    CHAVE_CRIPTO = Fernet.generate_key().decode()
    print("=" * 60)
    print("⚠️  CHAVE DE CRIPTOGRAFIA GERADA!")
    print(f"🔑 Chave: {CHAVE_CRIPTO}")
    print("⚠️  ADICIONE ESTA CHAVE COMO VARIÁVEL DE AMBIENTE NO RENDER!")
    print("⚠️  Nome da variável: CHAVE_CRIPTO")
    print("=" * 60)

fernet = Fernet(CHAVE_CRIPTO.encode() if isinstance(CHAVE_CRIPTO, str) else CHAVE_CRIPTO)

def criptografar_cpf(cpf):
    """Criptografa o CPF para salvar no banco"""
    if not cpf:
        return cpf
    cpf_limpo = str(cpf).replace('.', '').replace('-', '').strip()
    if len(cpf_limpo) == 11:
        return fernet.encrypt(cpf_limpo.encode()).decode()
    return cpf

def descriptografar_cpf(cpf_cripto):
    """Descriptografa o CPF para mostrar na tela"""
    if not cpf_cripto:
        return cpf_cripto
    try:
        return fernet.decrypt(cpf_cripto.encode()).decode()
    except:
        return cpf_cripto

def formatar_cpf(cpf):
    """Formata CPF: 12345678901 → 123.456.789-01"""
    cpf = str(cpf).replace('.', '').replace('-', '').strip()
    if len(cpf) == 11:
        return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"
    return cpf

def validar_cpf(cpf):
    """
    Valida CPF verificando os dígitos verificadores.
    Retorna True se for válido, False se for inválido.
    """
    # Limpar CPF
    cpf = str(cpf).replace('.', '').replace('-', '').replace(' ', '').strip()
    
    # Verificar se tem 11 dígitos
    if len(cpf) != 11:
        return False
    
    # Verificar se todos os dígitos são iguais (inválido)
    if cpf == cpf[0] * 11:
        return False
    
    # Cálculo do primeiro dígito verificador
    soma = 0
    for i in range(9):
        soma += int(cpf[i]) * (10 - i)
    
    resto = (soma * 10) % 11
    if resto == 10:
        resto = 0
    
    if resto != int(cpf[9]):
        return False
    
    # Cálculo do segundo dígito verificador
    soma = 0
    for i in range(10):
        soma += int(cpf[i]) * (11 - i)
    
    resto = (soma * 10) % 11
    if resto == 10:
        resto = 0
    
    if resto != int(cpf[10]):
        return False
    
    return True

# 🛡️ Configurar logs de segurança
if not os.path.exists('logs'):
    os.makedirs('logs')

handler = RotatingFileHandler('logs/auditoria.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%d/%m/%Y %H:%M:%S'
))
logger = logging.getLogger('auditoria')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# 🛡️ Dicionário para controle de tentativas de login
tentativas_login = defaultdict(list)
MAX_TENTATIVAS = 5
BLOQUEIO_MINUTOS = 15

# 🔧 CRIAR BANCO DE DADOS SE NÃO EXISTIR
criar_banco()

# =====================================================
# FORÇAR HTTPS (quando no Render)
# =====================================================

@app.before_request
def before_request():
    """Força HTTPS e registra acessos"""
    if os.environ.get('RENDER') and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, 301)
    
    if request.endpoint and request.endpoint != 'static':
        usuario = current_user.id if current_user.is_authenticated else 'não autenticado'
        logger.info(f"Acesso: {request.method} {request.path} | IP: {request.remote_addr} | Usuário: {usuario}")

# =====================================================
# CRIAR USUÁRIO ADMIN AUTOMATICAMENTE
# =====================================================

def criar_admin_automatico():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM usuarios")
        
        resultado = cursor.fetchone()
        count = resultado[0] if resultado else 0

        if count == 0:
            senha_temporaria = secrets.token_urlsafe(8)
            senha_hash = bcrypt.hashpw(senha_temporaria.encode('utf-8'), bcrypt.gensalt())
            
            sql = """
                INSERT INTO usuarios (usuario, nome, senha, perfil, primeiro_acesso)
                VALUES (%s, %s, %s, %s, %s)
            """
            
            cursor.execute(sql, ('admin', 'Administrador', senha_hash.decode('utf-8'), 'admin', 1))
            conn.commit()
                
            print("=" * 60)
            print("✅ Usuário admin criado automaticamente!")
            print(f"🔑 Usuário: admin")
            print(f"🔑 Senha temporária: {senha_temporaria}")
            print("⚠️  GUARDE ESTA SENHA!")
            print("=" * 60)
            
            logger.warning(f"Admin criado com senha temporária. Usuário: admin")
        else:
            print(f"✅ Banco já possui {count} usuário(s)")

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"⚠️ Erro ao criar admin automático: {e}")
        logger.error(f"Erro ao criar admin: {e}")

criar_admin_automatico()

def get_db():
    return get_db_connection()

# =====================================================
# LOGIN MANAGER
# =====================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "🔒 Faça login para acessar o sistema."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return carregar_usuario(user_id)

# =====================================================
# FILTROS
# =====================================================

@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value) if value else []
    except:
        return []

@app.template_filter('formatar_data')
def formatar_data(data):
    if not data:
        return ''
    try:
        if isinstance(data, str) and '-' in data:
            partes = data.split('-')
            if len(partes) == 3:
                return f"{partes[2]}/{partes[1]}/{partes[0]}"
        if isinstance(data, str):
            dt = datetime.strptime(data, '%Y-%m-%d')
            return dt.strftime('%d/%m/%Y')
    except:
        pass
    return data

# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    ip = request.remote_addr
    agora = datetime.now(FUSO_RONDONIA)
    
    tentativas_login[ip] = [t for t in tentativas_login[ip] if t > agora - timedelta(minutes=BLOQUEIO_MINUTOS)]
    
    if len(tentativas_login[ip]) >= MAX_TENTATIVAS:
        minutos_restantes = BLOQUEIO_MINUTOS - int((agora - tentativas_login[ip][0]).total_seconds() / 60)
        logger.warning(f"IP bloqueado: {ip}")
        return render_template("login.html", 
                             erro=f"⛔ Muitas tentativas! Aguarde {minutos_restantes} minutos.",
                             bloqueado=True)
    
    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = request.form["senha"]

        conexao = get_db()
        cursor = conexao.cursor()

        cursor.execute("""
            SELECT usuario, senha, perfil, primeiro_acesso, cras, nome
            FROM usuarios WHERE usuario = %s
        """, (usuario,))

        dados = cursor.fetchone()
        cursor.close()
        conexao.close()

        if dados:
            usuario_banco = dados[0]
            senha_hash = dados[1]
            perfil_banco = dados[2]
            primeiro_acesso = dados[3] if len(dados) > 3 else 0
            cras_banco = dados[4] if len(dados) > 4 else None
            nome_usuario = dados[5] if len(dados) > 5 and dados[5] else usuario_banco

            try:
                if bcrypt.checkpw(senha.encode('utf-8'), senha_hash.encode('utf-8')):
                    user = Usuario(usuario_banco, perfil_banco, cras_banco, nome_usuario)
                    login_user(user)
                    
                    if ip in tentativas_login:
                        del tentativas_login[ip]
                    
                    logger.info(f"Login bem-sucedido: {usuario_banco} | IP: {ip}")
                    
                    if primeiro_acesso == 1:
                        get_flashed_messages()
                        return redirect(url_for("trocar_senha", primeiro_acesso=True))
                    
                    if perfil_banco in ['admin', 'gestor']:
                        return redirect(url_for("dashboard"))
                    else:
                        return redirect(url_for("solicitacoes"))
                else:
                    tentativas_login[ip].append(agora)
                    tentativas_restantes = MAX_TENTATIVAS - len(tentativas_login[ip])
                    logger.warning(f"Senha incorreta: {usuario} | IP: {ip}")
                    
                    if tentativas_restantes > 0:
                        erro = f"❌ Senha incorreta! Tentativas restantes: {tentativas_restantes}"
                    else:
                        erro = f"⛔ Conta bloqueada por 15 minutos."
            except Exception as e:
                logger.error(f"Erro na autenticação: {e}")
                erro = "❌ Erro na autenticação."
        else:
            tentativas_login[ip].append(agora)
            tentativas_restantes = MAX_TENTATIVAS - len(tentativas_login[ip])
            logger.warning(f"Usuário não encontrado: {usuario} | IP: {ip}")
            
            if tentativas_restantes > 0:
                erro = f"❌ Usuário não encontrado! Tentativas restantes: {tentativas_restantes}"
            else:
                erro = f"⛔ Conta bloqueada por 15 minutos."
    
    return render_template("login.html", erro=erro, bloqueado=False)

# =====================================================
# TROCAR SENHA
# =====================================================

@app.route("/trocar_senha", methods=["GET", "POST"])
@login_required
def trocar_senha():
    primeiro_acesso = request.args.get('primeiro_acesso', False)
    erro = None
    sucesso = None
    
    if request.method == "POST":
        senha_atual = request.form.get("senha_atual", "")
        nova_senha = request.form.get("nova_senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")
        
        if not nova_senha or not confirmar_senha:
            erro = "Preencha todos os campos!"
        elif len(nova_senha) < 6:
            erro = "A nova senha deve ter no mínimo 6 caracteres!"
        elif nova_senha != confirmar_senha:
            erro = "A confirmação da senha não corresponde!"
        elif not any(c.isupper() for c in nova_senha):
            erro = "A senha deve conter pelo menos uma letra maiúscula!"
        elif not any(c.isdigit() for c in nova_senha):
            erro = "A senha deve conter pelo menos um número!"
        else:
            if not primeiro_acesso:
                conexao = get_db()
                cursor = conexao.cursor()
                cursor.execute("SELECT senha FROM usuarios WHERE usuario = %s", (current_user.id,))
                resultado = cursor.fetchone()
                if resultado:
                    senha_hash = resultado[0]
                    cursor.close()
                    conexao.close()
                    
                    if not bcrypt.checkpw(senha_atual.encode('utf-8'), senha_hash.encode('utf-8')):
                        erro = "Senha atual incorreta!"
                else:
                    cursor.close()
                    conexao.close()
                    erro = "Usuário não encontrado!"
            
            if not erro:
                salt = bcrypt.gensalt()
                nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), salt).decode('utf-8')
                
                conexao = get_db()
                cursor = conexao.cursor()
                cursor.execute("""
                    UPDATE usuarios 
                    SET senha = %s, primeiro_acesso = 0 
                    WHERE usuario = %s
                """, (nova_senha_hash, current_user.id))
                conexao.commit()
                cursor.close()
                conexao.close()
                
                logger.info(f"Senha alterada: {current_user.id}")
                sucesso = "✅ Senha alterada com sucesso!"
                
            if primeiro_acesso:
                if current_user.perfil in ['admin', 'gestor']:
                    return redirect(url_for("dashboard"))
                else:
                    return redirect(url_for("solicitacoes"))
    
    return render_template("trocar_senha.html", 
                         erro=erro, sucesso=sucesso, 
                         primeiro_acesso=primeiro_acesso)

# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
@login_required
def logout():
    logger.info(f"Logout: {current_user.id}")
    logout_user()
    return redirect(url_for("login"))

# =====================================================
# API - VERIFICAR CPF (Histórico + Validação)
# =====================================================

@app.route("/api/verificar_cpf/<cpf>")
@login_required
def verificar_cpf(cpf):
    """Verifica validade e histórico de cestas do CPF"""
    try:
        # Validar CPF primeiro
        cpf_limpo = str(cpf).replace('.', '').replace('-', '').replace(' ', '').strip()
        
        if len(cpf_limpo) != 11:
            return jsonify({'valido': False, 'erro': 'CPF deve ter 11 dígitos'})
        
        if not validar_cpf(cpf_limpo):
            return jsonify({'valido': False, 'erro': 'CPF inválido'})
        
        # Criptografar para buscar no banco
        cpf_cripto = criptografar_cpf(cpf_limpo)
        
        conexao = get_db()
        cursor = conexao.cursor()
        
        # Contar total de cestas entregues
        cursor.execute("""
            SELECT COUNT(*), MAX(data_entrega)
            FROM solicitacoes 
            WHERE cpf = %s AND status = 'Entregue'
        """, (cpf_cripto,))
        
        resultado = cursor.fetchone()
        total_recebido = resultado[0] if resultado else 0
        ultima_entrega = resultado[1] if resultado and resultado[1] else None
        
        # Verificar se tem solicitação pendente
        cursor.execute("""
            SELECT COUNT(*)
            FROM solicitacoes 
            WHERE cpf = %s AND status = 'Cadastrada'
        """, (cpf_cripto,))
        
        pendente = cursor.fetchone()[0] > 0
        
        # Buscar nome do último cadastro
        cursor.execute("""
            SELECT nome FROM solicitacoes 
            WHERE cpf = %s 
            ORDER BY id DESC LIMIT 1
        """, (cpf_cripto,))
        
        nome_row = cursor.fetchone()
        nome = nome_row[0] if nome_row else None
        
        conexao.close()
        
        # Calcular dias desde a última entrega
        dias_desde_ultima = None
        if ultima_entrega:
            try:
                if '-' in str(ultima_entrega):
                    data_ultima = datetime.strptime(str(ultima_entrega)[:10], '%Y-%m-%d')
                else:
                    data_ultima = datetime.strptime(str(ultima_entrega)[:10], '%d/%m/%Y')
                dias_desde_ultima = (datetime.now(FUSO_RONDONIA) - data_ultima.replace(tzinfo=None)).days
            except:
                pass
        
        # Definir tipo de alerta
        if dias_desde_ultima and dias_desde_ultima < 90:
            alerta = 'vermelho'
        elif total_recebido > 0:
            alerta = 'amarelo'
        else:
            alerta = 'verde'
        
        return jsonify({
            'valido': True,
            'total_recebido': total_recebido,
            'ultima_entrega': str(ultima_entrega) if ultima_entrega else None,
            'dias_desde_ultima': dias_desde_ultima,
            'pendente': pendente,
            'alerta': alerta,
            'nome': nome
        })
        
    except Exception as e:
        logger.error(f"Erro ao verificar CPF: {e}")
        return jsonify({'erro': str(e)}), 500

# =====================================================
# PÁGINA PRINCIPAL (Nova Solicitação)
# =====================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def inicio():
    if request.method == "POST":
        bairro = request.form["bairro"]
        cras_solicitacao = request.form["cras"]
        
        if current_user.perfil not in ['admin', 'gestor']:
            if current_user.cras != cras_solicitacao:
                logger.warning(f"Tentativa de acesso não autorizado: {current_user.id}")
                return "Você não tem permissão!", 403
        
        cpf = request.form["cpf"]
        
        # 🔐 Validar CPF
        cpf_limpo = cpf.replace('.', '').replace('-', '').strip()
        if not validar_cpf(cpf_limpo):
            flash('❌ CPF inválido! Verifique o número digitado.', 'danger')
            return render_template("index.html", sucesso=False)
        
        nome = request.form["nome"]
        data_nascimento = request.form.get("data_nascimento", "")
        telefone = request.form.get("telefone", "")
        rg = request.form.get("rg", "")
        email = request.form.get("email", "")
        
        endereco = request.form.get("endereco", "")
        numero = request.form.get("numero", "")
        complemento = request.form.get("complemento", "")
        bairro = request.form["bairro"]
        cep = request.form.get("cep", "")
        referencia = request.form.get("referencia", "")
        
        cras = request.form["cras"]
        data_escuta = request.form.get("data_escuta", "")
        
        membros_nomes = request.form.getlist("membro_nome[]")
        membros_idades = request.form.getlist("membro_idade[]")
        membros_vinculos = request.form.getlist("membro_vinculo[]")
        
        composicao_familiar = []
        for i in range(len(membros_nomes)):
            if membros_nomes[i].strip():
                composicao_familiar.append({
                    'nome': membros_nomes[i],
                    'idade': membros_idades[i] if i < len(membros_idades) else '',
                    'vinculo': membros_vinculos[i] if i < len(membros_vinculos) else ''
                })
        
        composicao_json = json.dumps(composicao_familiar, ensure_ascii=False)
        total_pessoas = len(composicao_familiar)
        
        renda_bruta = float(request.form.get("renda_bruta", 0)) if request.form.get("renda_bruta") else 0
        renda_per_capita = float(request.form.get("renda_per_capita", 0)) if request.form.get("renda_per_capita") else 0
        beneficios = request.form.get("beneficios", "")
        
        vulnerabilidades = request.form.getlist("vulnerabilidade")
        vulnerabilidade_text = ", ".join(vulnerabilidades) if vulnerabilidades else ""

        servicos_suas = request.form.getlist("servicos_suas")
        servicos_suas_text = ", ".join(servicos_suas) if servicos_suas else ""
        
        parecer = request.form.get("parecer", "")
        
        tecnico = current_user.id
        data_solicitacao = datetime.now(FUSO_RONDONIA).strftime("%d/%m/%Y %H:%M:%S")
        
        # 🔐 Criptografar CPF antes de salvar
        cpf_criptografado = criptografar_cpf(cpf_limpo)
        
        conexao = get_db()
        cursor = conexao.cursor()
        
        cursor.execute("""
            INSERT INTO solicitacoes (
                tecnico, cpf, nome, data_nascimento, telefone, email,
                endereco, numero, complemento, bairro, cep, referencia,
                cras, data_escuta, total_pessoas, composicao_familiar,
                renda_bruta, renda_per_capita, beneficios, vulnerabilidade,
                servicos_suas, parecer, status, data_solicitacao
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            tecnico, cpf_criptografado, nome, data_nascimento, telefone, email,
            endereco, numero, complemento, bairro, cep, referencia,
            cras, data_escuta, total_pessoas, composicao_json,
            renda_bruta, renda_per_capita, beneficios, vulnerabilidade_text,
            servicos_suas_text, parecer, 'Cadastrada', data_solicitacao
        ))
        
        conexao.commit()
        conexao.close()
        
        logger.info(f"Solicitação cadastrada: Técnico={tecnico}, Beneficiário={nome}, CRAS={cras}")
        flash('Solicitação cadastrada com sucesso!', 'success')
        return redirect(url_for("solicitacoes"))
    
    return render_template("index.html", sucesso=False)

# =====================================================
# LISTAR SOLICITAÇÕES
# =====================================================

@app.route("/solicitacoes")
@app.route("/solicitacoes/<int:pagina>")
@login_required
def solicitacoes(pagina=1):
    registros_por_pagina = 20
    offset = (pagina - 1) * registros_por_pagina
    
    conexao = get_db()
    cursor = conexao.cursor()
    
    if current_user.perfil in ['admin', 'gestor']:
        cursor.execute("SELECT COUNT(*) FROM solicitacoes")
        total_registros = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT id, tecnico, nome, cpf, bairro, cras, data_solicitacao, status
            FROM solicitacoes
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, (registros_por_pagina, offset))
    else:
        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE cras = %s", (current_user.cras,))
        total_registros = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT id, tecnico, nome, cpf, bairro, cras, data_solicitacao, status
            FROM solicitacoes
            WHERE cras = %s
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, (current_user.cras, registros_por_pagina, offset))
    
    total_paginas = (total_registros + registros_por_pagina - 1) // registros_por_pagina
    dados = cursor.fetchall()
    conexao.close()
    
    # Descriptografar CPF
    dados_descripto = []
    for row in dados:
        row = list(row)
        if row[3]:
            row[3] = formatar_cpf(descriptografar_cpf(row[3]))
        dados_descripto.append(tuple(row))
    
    return render_template(
        "solicitacoes.html",
        solicitacoes=dados_descripto,
        user_perfil=current_user.perfil,
        datetime=datetime,
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_registros=total_registros,
        current_user=current_user
    )

# =====================================================
# DETALHES DA SOLICITAÇÃO
# =====================================================

@app.route("/ver_solicitacao/<int:id>")
@login_required
def ver_solicitacao(id):
    conexao = get_db()
    cursor = conexao.cursor()
    
    cursor.execute("""
        SELECT 
            s.id, s.nome, s.cpf, s.data_nascimento, s.telefone, s.data_solicitacao, s.email,
            s.endereco, s.numero, s.complemento, s.bairro, s.cep, s.referencia,
            s.cras, s.renda_bruta, s.renda_per_capita, s.beneficios, s.vulnerabilidade,
            s.data_entrega, s.tecnico_entrega, s.parecer, s.status, s.tecnico,
            s.composicao_familiar, s.servicos_suas,
            u_tecnico.nome as nome_tecnico_escuta,
            u_entrega.nome as nome_tecnico_entrega
        FROM solicitacoes s
        LEFT JOIN usuarios u_tecnico ON s.tecnico = u_tecnico.usuario
        LEFT JOIN usuarios u_entrega ON s.tecnico_entrega = u_entrega.usuario
        WHERE s.id = %s
    """, (id,))
    
    solicitacao = cursor.fetchone()
    conexao.close()
    
    if not solicitacao:
        return "Solicitação não encontrada", 404
    
    solicitacao = list(solicitacao)
    
    # Descriptografar CPF
    if solicitacao[2]:
        solicitacao[2] = formatar_cpf(descriptografar_cpf(solicitacao[2]))
    
    # Formatar data de nascimento
    if solicitacao[3]:
        try:
            if '-' in str(solicitacao[3]):
                partes = str(solicitacao[3]).split('-')
                if len(partes) == 3:
                    solicitacao[3] = f"{partes[2]}/{partes[1]}/{partes[0]}"
        except:
            pass
    
    logger.info(f"Visualização de solicitação ID={id} por {current_user.id}")
    
    return render_template("ver_solicitacao.html", 
                         solicitacao=solicitacao, 
                         json=json, datetime=datetime,
                         current_user=current_user)

# =====================================================
# GERAR PDF
# =====================================================

@app.route("/gerar_pdf/<int:id>")
@login_required
def gerar_pdf_assinatura(id):
    conexao = get_db()
    cursor = conexao.cursor()
    
    cursor.execute("""
        SELECT 
            s.id, s.tecnico, s.nome, s.cpf, s.data_nascimento, s.telefone,
            s.endereco, s.numero, s.bairro, s.cras, s.renda_bruta,
            s.renda_per_capita, s.parecer, s.status, s.data_escuta,
            s.data_solicitacao, u.nome as tecnico_nome,
            s.data_entrega, s.tecnico_entrega, u_entrega.nome as tecnico_entrega_nome
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico = u.usuario
        LEFT JOIN usuarios u_entrega ON s.tecnico_entrega = u_entrega.usuario
        WHERE s.id = %s
    """, (id,))
   
    solicitacao = cursor.fetchone()
    conexao.close()
    
    if not solicitacao:
        return "Solicitação não encontrada", 404
    
    solicitacao = list(solicitacao)
    
    # Descriptografar CPF para o PDF
    cpf_pdf = formatar_cpf(descriptografar_cpf(solicitacao[3])) if solicitacao[3] else 'Não informado'
    solicitacao[3] = cpf_pdf
    
    logger.info(f"PDF gerado para solicitação ID={id} por {current_user.id}")
    
    numero_controle = f"CB-{datetime.now(FUSO_RONDONIA).strftime('%Y%m%d')}-{solicitacao[0]:04d}"
    
    qr_data = f"""Solicitação: {numero_controle}
Beneficiário: {solicitacao[2]}
CPF: {solicitacao[3]}
CRAS: {solicitacao[9]}
Técnico Escuta: {solicitacao[16] if solicitacao[16] else solicitacao[1]}
Data Escuta: {solicitacao[14] if solicitacao[14] else 'Não informada'}"""
    
    if solicitacao[13] in ['Entregue', 'Ausente'] and solicitacao[17]:
        qr_data += f"""
Status: {solicitacao[13]}
Data Entrega: {solicitacao[17]}
Técnico Entrega: {solicitacao[19] if solicitacao[19] else solicitacao[18]}"""
    
    qr = qrcode.QRCode(box_size=2, border=1)
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y_position = height - 2*cm
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2*cm, y_position, "PREFEITURA MUNICIPAL DE JI-PARANÁ")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y_position - 0.5*cm, "Secretaria Municipal de Assistência Social e Família - SEMASF")
    
    c.line(2*cm, y_position - 0.8*cm, width - 2*cm, y_position - 0.8*cm)
    
    c.setFont("Helvetica", 9)
    c.drawString(2*cm, y_position - 1.3*cm, f"Nº de Controle: {numero_controle}")
    c.drawString(2*cm, y_position - 1.8*cm, f"Data de Emissão: {datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M')}")
    
    qr_path = io.BytesIO()
    qr_img.save(qr_path, 'PNG')
    qr_path.seek(0)
    qr_reader = ImageReader(qr_path)
    c.drawImage(qr_reader, width - 3.5*cm, y_position - 2.2*cm, width=1.5*cm, height=1.5*cm)
    
    y_position = y_position - 4*cm
    
    c.setFont("Helvetica-Bold", 12)
    c.setFillColorRGB(0, 0.5, 0)
    c.drawString(2*cm, y_position, "1. DADOS DO BENEFICIÁRIO")
    c.setFillColorRGB(0, 0, 0)
    
    c.setFont("Helvetica", 10)
    y_position -= 0.6*cm
    c.drawString(2*cm, y_position, f"Nome: {solicitacao[2]}")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"CPF: {solicitacao[3]}")
    y_position -= 0.5*cm
    
    data_nascimento_pdf = solicitacao[4] if solicitacao[4] else 'Não informado'
    if data_nascimento_pdf != 'Não informado' and '-' in str(data_nascimento_pdf):
        try:
            partes = str(data_nascimento_pdf).split('-')
            if len(partes) == 3:
                data_nascimento_pdf = f"{partes[2]}/{partes[1]}/{partes[0]}"
        except:
            pass
    c.drawString(2*cm, y_position, f"Data Nascimento: {data_nascimento_pdf}")
    
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"Telefone: {solicitacao[5] if solicitacao[5] else 'Não informado'}")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"Endereço: {solicitacao[6] if solicitacao[6] else 'Não informado'}, {solicitacao[7] if solicitacao[7] else 'S/N'}")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"Bairro: {solicitacao[8]}")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"CRAS de Referência: {solicitacao[9]}")
    y_position -= 1*cm
    
    c.setFont("Helvetica-Bold", 12)
    c.setFillColorRGB(0, 0.5, 0)
    c.drawString(2*cm, y_position, "2. REGISTRO DE ATENDIMENTO")
    c.setFillColorRGB(0, 0, 0)
    
    c.setFont("Helvetica", 10)
    y_position -= 0.6*cm
    tecnico_nome = solicitacao[16] if solicitacao[16] else solicitacao[1]
    c.drawString(2*cm, y_position, f"Técnico/a que realizou a Escuta: {tecnico_nome}")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"Data da Escuta Técnica: {solicitacao[14] if solicitacao[14] else 'Não informada'}")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"Renda Bruta Familiar: R$ {solicitacao[10]:.2f}" if solicitacao[10] else "Renda Bruta: Não informada")
    y_position -= 0.5*cm
    c.drawString(2*cm, y_position, f"Renda Per Capita: R$ {solicitacao[11]:.2f}" if solicitacao[11] else "Renda Per Capita: Não informada")
    y_position -= 1*cm
    
    if solicitacao[13] in ['Entregue', 'Ausente']:
        c.setFont("Helvetica-Bold", 12)
        c.setFillColorRGB(0, 0.5, 0.8)
        c.drawString(2*cm, y_position, "3. INFORMAÇÕES DA ENTREGA")
        c.setFillColorRGB(0, 0, 0)
        
        c.setFont("Helvetica", 10)
        y_position -= 0.6*cm
        
        if solicitacao[13] == 'Entregue':
            c.setFillColorRGB(0, 0.5, 0)
            c.drawString(2*cm, y_position, f"Status: ✅ ENTREGUE")
        else:
            c.setFillColorRGB(0.8, 0, 0)
            c.drawString(2*cm, y_position, f"Status: ❌ AUSENTE")
        c.setFillColorRGB(0, 0, 0)
        
        y_position -= 0.5*cm
        
        if solicitacao[17]:
            data_entrega = solicitacao[17]
            if isinstance(data_entrega, str) and '-' in data_entrega:
                partes = data_entrega.split('-')
                if len(partes) == 3:
                    data_entrega = f"{partes[2]}/{partes[1]}/{partes[0]}"
            c.drawString(2*cm, y_position, f"Data da Entrega: {data_entrega}")
        else:
            c.drawString(2*cm, y_position, "Data da Entrega: Não registrada")
        
        y_position -= 0.5*cm
        
        if solicitacao[19]:
            c.drawString(2*cm, y_position, f"Técnico que entregou: {solicitacao[19]}")
        elif solicitacao[18]:
            c.drawString(2*cm, y_position, f"Técnico que entregou: {solicitacao[18]}")
        else:
            c.drawString(2*cm, y_position, "Técnico que entregou: Não registrado")
        
        y_position -= 1*cm
        secao_numero = "4"
        secao_assinaturas = "5"
    else:
        secao_numero = "3"
        secao_assinaturas = "4"
    
    if y_position < 10*cm:
        c.showPage()
        y_position = height - 2*cm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2*cm, y_position, f"PREFEITURA MUNICIPAL DE JI-PARANÁ - SEMASF (Continuação)")
        c.setFont("Helvetica", 9)
        c.drawString(2*cm, y_position - 0.5*cm, f"Nº Controle: {numero_controle}")
        c.line(2*cm, y_position - 0.7*cm, width - 2*cm, y_position - 0.7*cm)
        y_position = y_position - 1.5*cm
    
    c.setFont("Helvetica-Bold", 12)
    c.setFillColorRGB(0, 0.5, 0)
    c.drawString(2*cm, y_position, f"{secao_numero}. PARECER TÉCNICO / HISTÓRICO FAMILIAR")
    c.setFillColorRGB(0, 0, 0)
    
    parecer_texto = solicitacao[12] if solicitacao[12] else "Sem parecer técnico registrado"
    y_position -= 0.5*cm
    
    text_object = c.beginText(2.2*cm, y_position - 0.2*cm)
    text_object.setFont("Helvetica", 10)
    text_object.setTextOrigin(2.2*cm, y_position - 0.2*cm)
    
    max_width = width - 5*cm
    palavras = parecer_texto.split()
    linha = ""

    for palavra in palavras:
        linha_teste = linha + " " + palavra if linha else palavra
        if c.stringWidth(linha_teste, "Helvetica", 10) <= max_width:
            linha = linha_teste
        else:
            if linha:
                text_object.textLine(linha)
            linha = palavra
    if linha:
        text_object.textLine(linha)
    
    c.drawText(text_object)
    y_position = text_object.getY() - 1*cm
    
    if y_position < 8*cm:
        c.showPage()
        y_position = height - 2*cm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2*cm, y_position, f"PREFEITURA MUNICIPAL DE JI-PARANÁ - SEMASF (Continuação)")
        c.setFont("Helvetica", 9)
        c.drawString(2*cm, y_position - 0.5*cm, f"Nº Controle: {numero_controle}")
        c.line(2*cm, y_position - 0.7*cm, width - 2*cm, y_position - 0.7*cm)
        y_position = y_position - 1.5*cm
    
    c.setFont("Helvetica-Bold", 12)
    c.setFillColorRGB(0, 0.5, 0)
    c.drawString(2*cm, y_position, f"{secao_assinaturas}. ASSINATURAS")
    c.setFillColorRGB(0, 0, 0)
    
    y_position -= 1*cm
    
    if solicitacao[13] in ['Entregue', 'Ausente'] and solicitacao[17]:
        data_entrega = solicitacao[17]
        if isinstance(data_entrega, str) and '-' in data_entrega:
            partes = data_entrega.split('-')
            if len(partes) == 3:
                data_entrega = f"{partes[2]}/{partes[1]}/{partes[0]}"
        c.setFont("Helvetica", 9)
        c.drawString(2*cm, y_position + 0.3*cm, f"Data da Entrega: {data_entrega}")
    else:
        c.setFont("Helvetica", 9)
        c.drawString(2*cm, y_position + 0.3*cm, "Data da Entrega: ______/________/_________________")
    
    c.line(2*cm, y_position - 0.5*cm, width/2 - 1*cm, y_position - 0.5*cm)
    c.drawString(2*cm, y_position - 1*cm, "Assinatura do Beneficiário")
    
    c.line(width/2 + 1*cm, y_position - 0.5*cm, width - 2*cm, y_position - 0.5*cm)
    c.drawString(width/2 + 1*cm, y_position - 1*cm, "Técnico Responsável pela Entrega")
    
    y_position -= 3*cm
    
    c.rect(2*cm, y_position, 5*cm, 1.5*cm)
    c.setFont("Helvetica", 8)
    c.drawString(2.3*cm, y_position + 0.8*cm, "CARIMBO DO CRAS")
    c.drawString(2.3*cm, y_position + 0.3*cm, f"{solicitacao[9]}")
    
    c.setFont("Helvetica", 8)
    c.setFillColorRGB(0.5, 0.5, 0.5)
    c.drawString(2*cm, 1*cm, f"Documento gerado em {datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y às %H:%M:%S')}")
    c.drawString(2*cm, 0.5*cm, "Este documento deve ser assinado pelo beneficiário e pelo técnico responsável pela entrega.")
    
    c.save()
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"termo_entrega_{numero_controle}.pdf",
        mimetype='application/pdf'
    )

# =====================================================
# REGISTRAR ENTREGA
# =====================================================

@app.route("/registrar_entrega/<int:id>", methods=["POST"])
@login_required
def registrar_entrega(id):
    status_entrega = request.form.get("status_entrega", "")
    data_entrega = request.form.get("data_entrega", "")
    observacoes = request.form.get("observacoes", "")

    if not status_entrega or status_entrega not in ['Entregue', 'Ausente']:
        flash("Status de entrega inválido!", "danger")
        return redirect(url_for("solicitacoes"))

    if not data_entrega:
        flash("Data de entrega é obrigatória!", "danger")
        return redirect(url_for("solicitacoes"))

    conexao = get_db()
    cursor = conexao.cursor()

    cursor.execute("SELECT status FROM solicitacoes WHERE id = %s", (id,))
    resultado = cursor.fetchone()

    if not resultado:
        conexao.close()
        flash("Solicitação não encontrada!", "danger")
        return redirect(url_for("solicitacoes"))

    status_atual = resultado[0]

    if status_atual in ['Entregue', 'Ausente']:
        conexao.close()
        flash(f"Esta solicitação já está com status '{status_atual}' e não pode ser alterada!", "warning")
        return redirect(url_for("solicitacoes"))

    if current_user.perfil not in ['admin', 'gestor']:
        cursor.execute("SELECT cras FROM solicitacoes WHERE id = %s", (id,))
        result = cursor.fetchone()
        if not result or result[0] != current_user.cras:
            conexao.close()
            flash("Você não tem permissão para registrar entrega desta solicitação!", "danger")
            return redirect(url_for("solicitacoes"))

    cursor.execute("""
        UPDATE solicitacoes 
        SET status = %s, data_entrega = %s, tecnico_entrega = %s
        WHERE id = %s
    """, (status_entrega, data_entrega, current_user.id, id))

    if observacoes:
        cursor.execute("""
            UPDATE solicitacoes 
            SET parecer = parecer || '\n\n--- OBSERVAÇÕES DA ENTREGA ---\n' || %s
            WHERE id = %s
        """, (observacoes, id))

    conexao.commit()
    conexao.close()

    logger.info(f"Entrega registrada: ID={id}, Status={status_entrega}, Técnico={current_user.id}")

    if status_entrega == 'Entregue':
        flash('✅ Entrega registrada com sucesso! Cesta entregue para a família.', 'success')
    else:
        flash('❌ Ausência registrada.', 'warning')

    return redirect(url_for("solicitacoes"))

# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for("solicitacoes"))
    
    conexao = get_db()
    cursor = conexao.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM solicitacoes")
    total_solicitacoes = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Entregue'")
    total_entregues = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Ausente'")
    total_ausentes = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Cadastrada'")
    total_pendentes = cursor.fetchone()[0]
    
    conexao.close()
    
    return render_template(
        "dashboard.html",
        total_solicitacoes=total_solicitacoes,
        total_entregues=total_entregues,
        total_ausentes=total_ausentes,
        total_pendentes=total_pendentes,
        datetime=datetime,
        current_user=current_user
    )

# =====================================================
# RELATÓRIO MENSAL
# =====================================================

@app.route("/relatorio")
@login_required
def relatorio():
    mes = request.args.get('mes', datetime.now(FUSO_RONDONIA).strftime('%Y-%m'))
    ano = mes[:4]
    mes_num = mes[5:7]

    meses = {
        '01': 'Janeiro', '02': 'Fevereiro', '03': 'Março', '04': 'Abril',
        '05': 'Maio', '06': 'Junho', '07': 'Julho', '08': 'Agosto',
        '09': 'Setembro', '10': 'Outubro', '11': 'Novembro', '12': 'Dezembro'
    }
    nome_mes = meses.get(mes_num, mes_num)

    conexao = get_db()
    cursor = conexao.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes 
        WHERE data_solicitacao IS NOT NULL
        AND SUBSTR(data_solicitacao, 7, 4) = %s
        AND SUBSTR(data_solicitacao, 4, 2) = %s
    """, (ano, mes_num))
    total_solicitacoes = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes 
        WHERE status = 'Entregue' 
        AND data_entrega IS NOT NULL
        AND (
            (SUBSTR(data_entrega, 7, 4) = %s AND SUBSTR(data_entrega, 4, 2) = %s)
            OR (SUBSTR(data_entrega, 1, 4) = %s AND SUBSTR(data_entrega, 6, 2) = %s)
        )
    """, (ano, mes_num, ano, mes_num))
    total_entregues = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes 
        WHERE status = 'Ausente' 
        AND data_entrega IS NOT NULL
        AND (
            (SUBSTR(data_entrega, 7, 4) = %s AND SUBSTR(data_entrega, 4, 2) = %s)
            OR (SUBSTR(data_entrega, 1, 4) = %s AND SUBSTR(data_entrega, 6, 2) = %s)
        )
    """, (ano, mes_num, ano, mes_num))
    total_ausentes = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes 
        WHERE status = 'Cadastrada'
        AND data_solicitacao IS NOT NULL
        AND SUBSTR(data_solicitacao, 7, 4) = %s
        AND SUBSTR(data_solicitacao, 4, 2) = %s
    """, (ano, mes_num))
    total_pendentes = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT cras, COUNT(*) as total,
            SUM(CASE WHEN status = 'Entregue' THEN 1 ELSE 0 END) as entregues,
            SUM(CASE WHEN status = 'Ausente' THEN 1 ELSE 0 END) as ausentes
        FROM solicitacoes 
        WHERE data_solicitacao IS NOT NULL
        AND SUBSTR(data_solicitacao, 7, 4) = %s
        AND SUBSTR(data_solicitacao, 4, 2) = %s
        GROUP BY cras
    """, (ano, mes_num))
    por_cras = cursor.fetchall()

    cursor.execute("""
        SELECT 
            COALESCE(u.nome, 'Técnico não identificado') as nome_tecnico,
            COUNT(*) as total,
            SUM(CASE WHEN s.status = 'Entregue' THEN 1 ELSE 0 END) as entregues,
            SUM(CASE WHEN s.status = 'Ausente' THEN 1 ELSE 0 END) as ausentes
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico_entrega = u.usuario
        WHERE s.status IN ('Entregue', 'Ausente')
        AND s.data_entrega IS NOT NULL
        AND (
            (SUBSTR(s.data_entrega, 7, 4) = %s AND SUBSTR(s.data_entrega, 4, 2) = %s)
            OR (SUBSTR(s.data_entrega, 1, 4) = %s AND SUBSTR(s.data_entrega, 6, 2) = %s)
        )
        GROUP BY s.tecnico_entrega, u.nome
    """, (ano, mes_num, ano, mes_num))
    por_tecnico = cursor.fetchall()

    cursor.execute("""
        SELECT s.nome, s.cpf, s.bairro, s.cras, s.status, s.data_entrega,
            COALESCE(u.nome, 'Não informado') as tecnico_nome
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico_entrega = u.usuario
        WHERE s.status IN ('Entregue', 'Ausente') 
        AND s.data_entrega IS NOT NULL
        AND (
            (SUBSTR(s.data_entrega, 7, 4) = %s AND SUBSTR(s.data_entrega, 4, 2) = %s)
            OR (SUBSTR(s.data_entrega, 1, 4) = %s AND SUBSTR(s.data_entrega, 6, 2) = %s)
        )
        ORDER BY s.data_entrega DESC
        LIMIT 20
    """, (ano, mes_num, ano, mes_num))
    ultimas_entregas = cursor.fetchall()

    lista_meses = []
    for i in range(12):
        data = datetime.now(FUSO_RONDONIA).replace(day=1)
        if i > 0:
            if data.month > 1:
                data = data.replace(month=data.month - 1)
            else:
                data = data.replace(year=data.year - 1, month=12)
        valor = data.strftime('%Y-%m')
        nome_mes_calc = meses.get(data.strftime('%m'), data.strftime('%m'))
        lista_meses.append({
            'valor': valor,
            'nome': f"{nome_mes_calc} de {data.strftime('%Y')}"
        })

    conexao.close()

    return render_template(
        "relatorio.html",
        mes=mes, nome_mes=nome_mes, ano=ano,
        total_solicitacoes=total_solicitacoes,
        total_entregues=total_entregues,
        total_ausentes=total_ausentes,
        total_pendentes=total_pendentes,
        por_cras=por_cras,
        ultimas_entregas=ultimas_entregas,
        por_tecnico=por_tecnico,
        lista_meses=lista_meses,
        datetime=datetime,
        current_user=current_user
    )

# =====================================================
# GERENCIAR USUÁRIOS
# =====================================================

@app.route("/usuario/novo", methods=["GET", "POST"])
@login_required
def novo_usuario():
    if current_user.perfil != 'admin':
        logger.warning(f"Tentativa de acesso não autorizado: {current_user.id} tentou criar usuário")
        flash("Acesso negado! Apenas administradores podem criar usuários.", "danger")
        return redirect(url_for("listar_usuarios"))
    
    erro = None
    sucesso = None
    
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        nome = request.form.get("nome", "").strip()
        perfil = request.form.get("perfil", "")
        senha = request.form.get("senha", "")
        cras = request.form.get("cras", "")
        
        if not usuario or not nome or not perfil or not senha:
            erro = "Todos os campos são obrigatórios!"
        elif len(senha) < 6:
            erro = "A senha deve ter no mínimo 6 caracteres!"
        elif perfil not in ['tecnico', 'gestor', 'admin']:
            erro = "Perfil inválido!"
        elif perfil == 'tecnico' and not cras:
            erro = "Técnico deve ter um CRAS de referência!"
        elif not any(c.isupper() for c in senha):
            erro = "A senha deve conter pelo menos uma letra maiúscula!"
        elif not any(c.isdigit() for c in senha):
            erro = "A senha deve conter pelo menos um número!"
        else:
            salt = bcrypt.gensalt()
            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), salt).decode('utf-8')
            
            conexao = get_db()
            cursor = conexao.cursor()
            
            try:
                cursor.execute("""
                    INSERT INTO usuarios (usuario, nome, senha, perfil, cras, primeiro_acesso)
                    VALUES (%s, %s, %s, %s, %s, 1)
                """, (usuario, nome, senha_hash, perfil, cras if perfil == 'tecnico' else None))
                conexao.commit()
                logger.info(f"Usuário criado: {usuario} por {current_user.id}")
                sucesso = f"Usuário {usuario} criado com sucesso!"
            except Exception as e:
                if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                    erro = f"Usuário {usuario} já existe!"
                else:
                    logger.error(f"Erro ao criar usuário: {e}")
                    erro = f"Erro ao criar usuário: {e}"
            finally:
                conexao.close()
    
    return render_template("novo_usuario.html", erro=erro, sucesso=sucesso)


@app.route("/usuarios")
@login_required
def listar_usuarios():
    if current_user.perfil != 'admin':
        flash("Acesso negado! Apenas administradores podem acessar esta página.", "danger")
        return redirect(url_for("dashboard"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT id, usuario, nome, perfil, cras FROM usuarios ORDER BY id")
    usuarios = cursor.fetchall()
    conexao.close()
    
    return render_template("usuarios.html", usuarios=usuarios, current_user=current_user)


@app.route("/usuario/excluir/<int:id>")
@login_required
def excluir_usuario(id):
    if current_user.perfil != 'admin':
        logger.warning(f"Tentativa de exclusão não autorizada por {current_user.id}")
        flash("Acesso negado! Apenas administradores podem excluir usuários.", "danger")
        return redirect(url_for("listar_usuarios"))
    
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT usuario, perfil FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    
    if not usuario:
        conexao.close()
        return redirect(url_for("listar_usuarios"))
    
    if usuario[0] == current_user.id:
        conexao.close()
        flash("Você não pode excluir seu próprio usuário!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    if usuario[1] == 'admin':
        conexao.close()
        flash("Não é possível excluir outro administrador!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conexao.commit()
    conexao.close()
    
    logger.warning(f"Usuário excluído: {usuario[0]} por {current_user.id}")
    flash(f"Usuário {usuario[0]} excluído com sucesso!", "success")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuario/editar/<int:id>", methods=["POST"])
@login_required
def editar_usuario(id):
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for("solicitacoes"))
    
    novo_nome = request.form.get("nome", "").strip()
    
    if not novo_nome:
        return redirect(url_for("listar_usuarios"))
    
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET nome = %s WHERE id = %s", (novo_nome, id))
    conexao.commit()
    conexao.close()
    
    logger.info(f"Usuário ID={id} atualizado por {current_user.id}")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuario/editar_cras/<int:id>", methods=["POST"])
@login_required
def editar_cras_usuario(id):
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for("solicitacoes"))
    
    novo_cras = request.form.get("cras", "").strip()
    
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET cras = %s WHERE id = %s", (novo_cras, id))
    conexao.commit()
    conexao.close()
    
    return redirect(url_for("listar_usuarios"))


@app.route("/usuario/editar_perfil/<int:id>", methods=["POST"])
@login_required
def editar_perfil_usuario(id):
    if current_user.perfil != 'admin':
        flash("Acesso negado! Apenas administradores podem alterar perfis.", "danger")
        return redirect(url_for("listar_usuarios"))
    
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT usuario FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    
    if usuario and usuario[0] == current_user.id:
        conexao.close()
        flash("Você não pode alterar seu próprio perfil!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    novo_perfil = request.form.get("perfil", "").strip()
    
    if novo_perfil not in ['tecnico', 'gestor', 'admin']:
        conexao.close()
        return redirect(url_for("listar_usuarios"))
    
    cursor.execute("UPDATE usuarios SET perfil = %s WHERE id = %s", (novo_perfil, id))
    conexao.commit()
    conexao.close()
    
    logger.warning(f"Perfil do usuário ID={id} alterado para {novo_perfil} por {current_user.id}")
    flash(f"Perfil do usuário alterado para {novo_perfil}!", "success")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuario/alterar_senha/<int:id>", methods=["POST"])
@login_required
def alterar_senha_usuario(id):
    conexao = get_db()
    cursor = conexao.cursor()
    
    cursor.execute("SELECT usuario FROM usuarios WHERE id = %s", (id,))
    usuario_logado = cursor.fetchone()
    
    if not usuario_logado:
        conexao.close()
        flash("Usuário não encontrado!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    if current_user.id != usuario_logado[0]:
        conexao.close()
        flash("Você só pode alterar sua própria senha!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    senha_atual = request.form.get("senha_atual", "")
    nova_senha = request.form.get("nova_senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")
    
    if not nova_senha or len(nova_senha) < 6:
        conexao.close()
        flash("A nova senha deve ter no mínimo 6 caracteres!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    if nova_senha != confirmar_senha:
        conexao.close()
        flash("As senhas não coincidem!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    cursor.execute("SELECT senha FROM usuarios WHERE id = %s", (id,))
    result = cursor.fetchone()
    if not result:
        conexao.close()
        flash("Usuário não encontrado!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    senha_hash_atual = result[0]
    
    if not bcrypt.checkpw(senha_atual.encode('utf-8'), senha_hash_atual.encode('utf-8')):
        conexao.close()
        flash("Senha atual incorreta!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    salt = bcrypt.gensalt()
    nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), salt).decode('utf-8')
    
    cursor.execute("UPDATE usuarios SET senha = %s, primeiro_acesso = 0 WHERE id = %s", (nova_senha_hash, id))
    conexao.commit()
    conexao.close()
    
    logger.info(f"Senha alterada para usuário ID={id}")
    flash("✅ Senha alterada com sucesso!", "success")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuario/resetar_senha/<int:id>", methods=["POST"])
@login_required
def resetar_senha_usuario(id):
    if current_user.perfil != 'admin':
        flash("Acesso negado! Apenas administradores podem resetar senhas.", "danger")
        return redirect(url_for("listar_usuarios"))
    
    if current_user.id == id:
        flash("Use a opção 'Alterar Senha' para modificar sua própria senha.", "warning")
        return redirect(url_for("listar_usuarios"))
    
    nova_senha = secrets.token_urlsafe(8)
    salt = bcrypt.gensalt()
    nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), salt).decode('utf-8')
    
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET senha = %s, primeiro_acesso = 1 WHERE id = %s", (nova_senha_hash, id))
    conexao.commit()
    conexao.close()
    
    logger.warning(f"Senha resetada para usuário ID={id} por {current_user.id}")
    flash(f"✅ Senha resetada! Nova senha temporária: {nova_senha}", "success")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuario/alterar_senha", methods=["POST"])
@login_required
def alterar_senha_simples():
    conexao = get_db()
    cursor = conexao.cursor()
    
    cursor.execute("SELECT id, senha FROM usuarios WHERE usuario = %s", (current_user.id,))
    result = cursor.fetchone()
    
    if not result:
        conexao.close()
        flash("Usuário não encontrado!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    user_id = result[0]
    senha_hash_atual = result[1]
    
    senha_atual = request.form.get("senha_atual", "")
    nova_senha = request.form.get("nova_senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")
    
    if not nova_senha or len(nova_senha) < 6:
        conexao.close()
        flash("A nova senha deve ter no mínimo 6 caracteres!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    if nova_senha != confirmar_senha:
        conexao.close()
        flash("As senhas não coincidem!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    if not bcrypt.checkpw(senha_atual.encode('utf-8'), senha_hash_atual.encode('utf-8')):
        conexao.close()
        flash("Senha atual incorreta!", "danger")
        return redirect(url_for("listar_usuarios"))
    
    salt = bcrypt.gensalt()
    nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), salt).decode('utf-8')
    
    cursor.execute("UPDATE usuarios SET senha = %s, primeiro_acesso = 0 WHERE id = %s", (nova_senha_hash, user_id))
    conexao.commit()
    conexao.close()
    
    logger.info(f"Senha alterada pelo próprio usuário {current_user.id}")
    flash("✅ Senha alterada com sucesso!", "success")
    return redirect(url_for("listar_usuarios"))

# =====================================================
# ROTA DE BACKUP
# =====================================================

@app.route("/api/backup")
@app.route("/api/backup/download")
@login_required
def backup_automatico():
    if 'download' in request.path and current_user.perfil != 'admin':
        return "Acesso negado", 403
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, usuario, nome, perfil, cras, primeiro_acesso FROM usuarios")
        usuarios_raw = cursor.fetchall()
        
        cursor.execute("SELECT * FROM solicitacoes")
        solicitacoes_raw = cursor.fetchall()
        
        conn.close()
        
        usuarios = []
        for u in usuarios_raw:
            usuarios.append({
                'id': u[0], 'usuario': u[1], 'nome': u[2],
                'perfil': u[3], 'cras': u[4], 'primeiro_acesso': u[5]
            })
        
        colunas = ['id', 'tecnico', 'cpf', 'nome', 'data_nascimento', 'telefone', 
                   'email', 'endereco', 'numero', 'complemento', 'bairro', 'cep', 
                   'referencia', 'cras', 'data_escuta', 'total_pessoas', 
                   'composicao_familiar', 'renda_bruta', 'renda_per_capita', 
                   'beneficios', 'vulnerabilidade', 'servicos_suas', 'parecer', 
                   'status', 'data_solicitacao', 'data_entrega', 'tecnico_entrega']
        
        solicitacoes = []
        for s in solicitacoes_raw:
            item = {}
            for i, coluna in enumerate(colunas):
                item[coluna] = s[i] if i < len(s) else None
            solicitacoes.append(item)
        
        backup = {
            'data': datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M:%S'),
            'total_usuarios': len(usuarios),
            'total_solicitacoes': len(solicitacoes),
            'usuarios': usuarios,
            'solicitacoes': solicitacoes
        }
        
        backup_dir = '/opt/render/.data/backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        nome_arquivo = f"backup_{datetime.now(FUSO_RONDONIA).strftime('%Y%m%d_%H%M%S')}.json"
        caminho_completo = os.path.join(backup_dir, nome_arquivo)
        
        with open(caminho_completo, 'w', encoding='utf-8') as f:
            json.dump(backup, f, ensure_ascii=False, indent=2)
        
        arquivos = sorted([f for f in os.listdir(backup_dir) if f.endswith('.json')], reverse=True)
        for arquivo_antigo in arquivos[7:]:
            os.remove(os.path.join(backup_dir, arquivo_antigo))
        
        logger.info(f"✅ Backup gerado: {nome_arquivo}")
        
        if 'download' in request.path:
            return send_file(
                caminho_completo,
                as_attachment=True,
                download_name=nome_arquivo,
                mimetype='application/json'
            )
        
        return f"✅ Backup gerado com sucesso: {nome_arquivo}", 200
        
    except Exception as e:
        logger.error(f"❌ Erro no backup: {e}")
        return f"❌ Erro no backup: {e}", 500


if __name__ == "__main__":
    criar_banco()
    app.run(debug=True)
