from flask import Flask, render_template, request, redirect, url_for, send_file, flash, get_flashed_messages, session, jsonify
import re as _re

def _strip_html(text):
    """Remove tags HTML e converte entidades básicas para texto puro (para o PDF)."""
    if not text:
        return ''
    text = _re.sub(r'<br\s*/?>', '\n', text, flags=_re.IGNORECASE)
    text = _re.sub(r'</p>', '\n', text, flags=_re.IGNORECASE)
    text = _re.sub(r'<[^>]+>', '', text)
    text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
    return _re.sub(r'\n{3,}', '\n\n', text).strip()
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from usuarios import Usuario, carregar_usuario
from banco import criar_banco, get_db_connection, _devolver_conexao
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
import hashlib
import gzip
import base64
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit

# =====================================================
# CONFIGURAÇÃO DO APP
# =====================================================

app = Flask(__name__)

# 🔒 Secret key
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# 🛡️ Proteção CSRF global
csrf = CSRFProtect(app)

# ⏱️ Sessão expira após 8 horas de inatividade
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# 🕐 Fuso horário de Rondônia (UTC-4)
FUSO_RONDONIA = timezone(timedelta(hours=-4))

#===============================================
# 🔐 CHAVE DE CRIPTOGRAFIA - FIXA NO RENDER
#===============================================

CHAVE_CRIPTO = os.environ.get('CHAVE_CRIPTO')

# DEBUG: Mostrar se a chave foi encontrada
if CHAVE_CRIPTO:
    print(f"✅ Chave ENCONTRADA no ambiente: {CHAVE_CRIPTO[:20]}...")
else:
    CHAVE_CRIPTO = Fernet.generate_key().decode()
    print("=" * 60)
    print("❌ Chave NÃO encontrada no ambiente!")
    print(f"🔑 Nova chave gerada: {CHAVE_CRIPTO}")
    print("⚠️  ADICIONE NO RENDER: CHAVE_CRIPTO = " + CHAVE_CRIPTO)
    print("=" * 60)

# Criar o Fernet
fernet = Fernet(CHAVE_CRIPTO.encode())

# =====================================================
# FUNÇÕES DE CPF
# =====================================================

def hash_cpf(cpf):
    """Gera hash SHA256 para buscas (sempre igual para o mesmo CPF)"""
    cpf_limpo = ''.join(filter(str.isdigit, str(cpf)))
    return hashlib.sha256(cpf_limpo.encode()).hexdigest()

def criptografar_cpf(cpf_limpo):
    """Criptografa o CPF para salvar no banco"""
    if not cpf_limpo:
        return ''
    cpf_limpo = ''.join(filter(str.isdigit, str(cpf_limpo)))
    if len(cpf_limpo) == 11:
        return fernet.encrypt(cpf_limpo.encode()).decode()
    return cpf_limpo

def descriptografar_cpf(cpf_cripto):
    """Descriptografa o CPF para mostrar na tela"""
    if not cpf_cripto:
        return ''
    
    cpf_str = str(cpf_cripto)
    
    # Se já for um CPF em texto plano (11 dígitos), retorna ele
    cpf_limpo = ''.join(filter(str.isdigit, cpf_str))
    if len(cpf_limpo) == 11:
        return cpf_limpo
    
    # Tenta descriptografar
    try:
        valor = fernet.decrypt(cpf_str.encode()).decode()
        if len(valor) == 11 and valor.isdigit():
            return valor
        return cpf_str
    except Exception as e:
        print(f"⚠️ Erro ao descriptografar CPF: {e}")
        return cpf_str

def formatar_cpf(cpf):
    """Formata CPF: 12345678901 → 123.456.789-01"""
    if not cpf:
        return ''
    cpf_limpo = ''.join(filter(str.isdigit, str(cpf)))
    if len(cpf_limpo) == 11:
        return f"{cpf_limpo[:3]}.{cpf_limpo[3:6]}.{cpf_limpo[6:9]}-{cpf_limpo[9:]}"
    return str(cpf)

def validar_cpf(cpf):
    """Valida CPF pelos dígitos verificadores"""
    cpf = ''.join(filter(str.isdigit, str(cpf)))
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    
    # Primeiro dígito
    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    resto = (soma * 10) % 11
    if resto == 10:
        resto = 0
    if resto != int(cpf[9]):
        return False
    
    # Segundo dígito
    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    resto = (soma * 10) % 11
    if resto == 10:
        resto = 0
    if resto != int(cpf[10]):
        return False
    
    return True

# 🛡️ Logs
if not os.path.exists('logs'):
    os.makedirs('logs')

handler = RotatingFileHandler('logs/auditoria.log', maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%d/%m/%Y %H:%M:%S'))
logger = logging.getLogger('auditoria')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# 🛡️ Força bruta
tentativas_login = defaultdict(list)
MAX_TENTATIVAS = 5
BLOQUEIO_MINUTOS = 15

# 🔧 Criar banco
criar_banco()

# =====================================================
# BACKUP AUTOMATICO POR E-MAIL
# =====================================================

EMAIL_REMETENTE    = os.environ.get('EMAIL_REMETENTE', 'sistema.cestas.semasf@gmail.com')
EMAIL_DESTINATARIO = os.environ.get('EMAIL_DESTINATARIO', 'sistema.cestas.semasf@gmail.com')
SENDGRID_API_KEY   = os.environ.get('SENDGRID_API_KEY', '')

def gerar_backup_json():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM solicitacoes")
    cols_sol = [d[0] for d in cursor.description]
    solicitacoes = [dict(zip(cols_sol, row)) for row in cursor.fetchall()]
    cursor.execute("SELECT id, usuario, nome, perfil, cras FROM usuarios")
    cols_usu = [d[0] for d in cursor.description]
    usuarios = [dict(zip(cols_usu, row)) for row in cursor.fetchall()]
    conn.close()
    return {
        'gerado_em': datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M:%S'),
        'total_solicitacoes': len(solicitacoes),
        'total_usuarios': len(usuarios),
        'solicitacoes': solicitacoes,
        'usuarios': usuarios
    }

def enviar_backup_email():
    if not SENDGRID_API_KEY:
        print("Backup ignorado: SENDGRID_API_KEY nao configurada no Render.")
        return False
    try:
        agora = datetime.now(FUSO_RONDONIA)
        nome_arquivo = f"backup_semasf_{agora.strftime('%Y%m%d_%H%M%S')}.json.gz"

        # Gerar e compactar backup
        dados = gerar_backup_json()
        conteudo = json.dumps(dados, ensure_ascii=False, indent=2, default=str).encode('utf-8')
        buffer_gz = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer_gz, mode='wb') as gz:
            gz.write(conteudo)
        buffer_gz.seek(0)
        tamanho_kb = round(buffer_gz.getbuffer().nbytes / 1024, 1)

        corpo = (
            f"Backup automatico do Sistema de Cestas Basicas - SEMASF Ji-Parana\n\n"
            f"Data/Hora: {agora.strftime('%d/%m/%Y as %H:%M:%S')} (horario de Rondonia)\n"
            f"Solicitacoes: {dados['total_solicitacoes']}\n"
            f"Usuarios: {dados['total_usuarios']}\n"
            f"Tamanho: {tamanho_kb} KB (compactado)\n\n"
            f"Este e-mail e gerado automaticamente todo dia a meia-noite.\n"
            f"Guarde os ultimos 30 e-mails para manter 30 dias de historico.\n\n"
            f"-- Sistema SEMASF"
        )

        # Montar e-mail via SendGrid
        mensagem = Mail(
            from_email=EMAIL_REMETENTE,
            to_emails=EMAIL_DESTINATARIO,
            subject=f"[SEMASF] Backup automatico - {agora.strftime('%d/%m/%Y')}",
            plain_text_content=corpo
        )

        # Anexar arquivo compactado
        anexo = Attachment(
            FileContent(base64.b64encode(buffer_gz.read()).decode()),
            FileName(nome_arquivo),
            FileType('application/gzip'),
            Disposition('attachment')
        )
        mensagem.attachment = anexo

        # Enviar via API HTTP (sem bloqueio de porta)
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(mensagem)

        print(f"Backup enviado via SendGrid: {nome_arquivo} ({tamanho_kb} KB) — status {response.status_code}")
        logger.info(f"Backup automatico enviado: {nome_arquivo} ({tamanho_kb} KB, {dados['total_solicitacoes']} solicitacoes)")

    except Exception as e:
        print(f"Erro no backup automatico: {e}")
        logger.error(f"Erro no backup automatico: {e}")
        raise

scheduler = BackgroundScheduler(timezone='America/Porto_Velho')
scheduler.add_job(
    func=enviar_backup_email,
    trigger=CronTrigger(hour=8, minute=0),
    id='backup_diario',
    name='Backup diario por e-mail',
    replace_existing=True,
    misfire_grace_time=3600  # se perder as 8h, executa em até 1h depois
)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())
print("Agendador de backup iniciado (todo dia às 8h, horario de Rondonia)")

# =====================================================
# HTTPS
# ===================================================

@app.before_request
def before_request():
    if os.environ.get('RENDER') and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, 301)
    if request.endpoint and request.endpoint != 'static':
        usuario = current_user.id if current_user.is_authenticated else 'não autenticado'
        logger.info(f"Acesso: {request.method} {request.path} | IP: {request.remote_addr} | Usuário: {usuario}")

@app.after_request
def adicionar_headers_no_cache(response):
    """Impede o navegador de cachear páginas HTML, garantindo que os
    técnicos sempre recebam a versão mais recente após atualizações."""
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

class _PooledConn:
    """Wrapper que devolve a conexão ao pool quando .close() é chamado."""
    def __init__(self, conn):
        self._conn = conn

    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.rollback()
        except Exception:
            pass
        _devolver_conexao(self._conn)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def get_db():
    return _PooledConn(get_db_connection())

# =====================================================
# LOGIN
# =====================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = None

@login_manager.user_loader
def load_user(user_id):
    return carregar_usuario(user_id)

@app.context_processor
def inject_notificacoes_count():
    if current_user.is_authenticated:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM notificacoes WHERE destinatario=%s AND lida=FALSE", (current_user.id,))
            count = cur.fetchone()[0]
            conn.close()
            return {'notificacoes_nao_lidas': count}
        except:
            return {'notificacoes_nao_lidas': 0}
    return {'notificacoes_nao_lidas': 0}

@app.template_filter('fromjson')
def fromjson_filter(value):
    try: return json.loads(value) if value else []
    except: return []

@app.template_filter('formatar_data')
def formatar_data(data):
    if not data: return ''
    try:
        if isinstance(data, str) and '-' in data:
            partes = data.split('-')
            if len(partes) == 3: return f"{partes[2]}/{partes[1]}/{partes[0]}"
    except: pass
    return data

@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    ip = request.remote_addr
    agora = datetime.now(FUSO_RONDONIA)
    tentativas_login[ip] = [t for t in tentativas_login[ip] if t > agora - timedelta(minutes=BLOQUEIO_MINUTOS)]
    
    if len(tentativas_login[ip]) >= MAX_TENTATIVAS:
        minutos = BLOQUEIO_MINUTOS - int((agora - tentativas_login[ip][0]).total_seconds() / 60)
        return render_template("login.html", erro=f"⛔ Bloqueado! Aguarde {minutos} min.", bloqueado=True)
    
    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = request.form["senha"]
        conexao = get_db()
        cursor = conexao.cursor()
        cursor.execute("SELECT usuario, senha, perfil, primeiro_acesso, cras, nome FROM usuarios WHERE usuario = %s", (usuario,))
        dados = cursor.fetchone()
        cursor.close()
        conexao.close()
        
        if dados and bcrypt.checkpw(senha.encode('utf-8'), dados[1].encode('utf-8')):
            user = Usuario(dados[0], dados[2], dados[4] if len(dados) > 4 else None, dados[5] if len(dados) > 5 else dados[0])
            login_user(user, remember=False)
            session.permanent = True
            if ip in tentativas_login: del tentativas_login[ip]
            logger.info(f"Login: {dados[0]}")
            if dados[3] == 1:
                return redirect(url_for("trocar_senha", primeiro_acesso=True))
            return redirect(url_for("dashboard") if dados[2] in ['admin', 'gestor'] else url_for("solicitacoes"))
        else:
            tentativas_login[ip].append(agora)
            erro = "❌ Usuário ou senha incorretos!"
    
    return render_template("login.html", erro=erro, bloqueado=False)

# =====================================================
# TROCAR SENHA
# =====================================================

@app.route("/trocar_senha", methods=["GET", "POST"])
@login_required
def trocar_senha():
    erro = sucesso = None
    if request.method == "POST":
        nova = request.form.get("nova_senha", "")
        confirma = request.form.get("confirmar_senha", "")
        if len(nova) < 6: erro = "Mínimo 6 caracteres!"
        elif nova != confirma: erro = "Senhas não conferem!"
        elif not any(c.isupper() for c in nova): erro = "Precisa de maiúscula!"
        elif not any(c.isdigit() for c in nova): erro = "Precisa de número!"
        else:
            hash_nova = bcrypt.hashpw(nova.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conexao = get_db()
            cursor = conexao.cursor()
            cursor.execute("UPDATE usuarios SET senha = %s, primeiro_acesso = 0 WHERE usuario = %s", (hash_nova, current_user.id))
            conexao.commit()
            conexao.close()
            logger.info(f"Senha alterada: {current_user.id}")
            sucesso = "✅ Senha alterada!"
            if request.args.get('primeiro_acesso'):
                return redirect(url_for("dashboard") if current_user.perfil in ['admin', 'gestor'] else url_for("solicitacoes"))
    return render_template("trocar_senha.html", erro=erro, sucesso=sucesso)

# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# =====================================================
# API VERIFICAR CPF (COM HASH)
# =====================================================

@app.route("/api/verificar_cpf/<cpf>")
@login_required
def verificar_cpf(cpf):
    """Verifica validade e histórico de cestas do CPF"""
    try:
        cpf_limpo = ''.join(filter(str.isdigit, str(cpf)))
        if len(cpf_limpo) != 11 or not validar_cpf(cpf_limpo):
            return jsonify({'valido': False, 'erro': 'CPF inválido'})
        
        hash_busca = hash_cpf(cpf_limpo)
        conexao = get_db()
        cursor = conexao.cursor()
        
        # Total de cestas entregues
        cursor.execute("SELECT COUNT(*), MAX(data_entrega) FROM solicitacoes WHERE cpf_hash = %s AND status = 'Entregue'", (hash_busca,))
        r = cursor.fetchone()
        total_recebido = r[0] or 0
        ultima_entrega = r[1]
        
        # Pendente
        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE cpf_hash = %s AND status = 'Cadastrada'", (hash_busca,))
        pendente = cursor.fetchone()[0] > 0
        
        # Nome
        cursor.execute("SELECT nome FROM solicitacoes WHERE cpf_hash = %s ORDER BY id DESC LIMIT 1", (hash_busca,))
        nome_row = cursor.fetchone()
        nome = nome_row[0] if nome_row else None
        
        conexao.close()
        
        # Dias desde última entrega
        dias = None
        if ultima_entrega:
            try:
                data_ultima = datetime.strptime(str(ultima_entrega)[:10], '%Y-%m-%d' if '-' in str(ultima_entrega) else '%d/%m/%Y')
                dias = (datetime.now() - data_ultima).days
            except: pass
        
        # Alerta
        if dias and dias < 90:
            alerta = 'vermelho'
        elif total_recebido > 0:
            alerta = 'amarelo'
        else:
            alerta = 'verde'
        
        return jsonify({
            'valido': True,
            'total_recebido': total_recebido,
            'dias_desde_ultima': dias,
            'pendente': pendente,
            'alerta': alerta,
            'nome': nome
        })
    except Exception as e:
        logger.error(f"Erro verificar CPF: {e}")
        return jsonify({'erro': str(e)}), 500

# =====================================================
# HELPERS - BAIRROS/CRAS (lidos do banco)
# =====================================================

def get_bairros_por_cras():
    """Retorna dict {cras: [bairros]} ordenado, lido da tabela cras_bairros."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT cras, bairro FROM cras_bairros ORDER BY cras, bairro")
        rows = cursor.fetchall()
    finally:
        conn.close()
    resultado = {}
    for cras, bairro in rows:
        resultado.setdefault(cras, []).append(bairro)
    return resultado

def get_lista_cras():
    """Retorna lista de CRAS distintos, ordenados."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT cras FROM cras_bairros ORDER BY cras")
        rows = cursor.fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows]

# =====================================================
# PÁGINA PRINCIPAL - NOVA SOLICITAÇÃO
# =====================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def inicio():
    if request.method == "POST":
        cpf = request.form["cpf"]
        cpf_limpo = ''.join(filter(str.isdigit, cpf))
        
        if not validar_cpf(cpf_limpo):
            flash('❌ CPF inválido!', 'danger')
            return render_template("index.html", sucesso=False)
        
        cpf_cripto = criptografar_cpf(cpf_limpo)
        cpf_hash = hash_cpf(cpf_limpo)
        
        # Dados do formulário
        nome = request.form.get("nome", "")
        data_nasc = request.form.get("data_nascimento", "")
        telefone = request.form.get("telefone", "")
        email = request.form.get("email", "")
        endereco = request.form.get("endereco", "")
        numero = request.form.get("numero", "")
        complemento = request.form.get("complemento", "")
        bairro = request.form.get("bairro", "")
        cep = request.form.get("cep", "")
        referencia = request.form.get("referencia", "")
        cras = request.form.get("cras", "")
        data_escuta = request.form.get("data_escuta", "")
        
        # Membros da família
        membros_nomes = request.form.getlist("membro_nome[]")
        membros_idades = request.form.getlist("membro_idade[]")
        membros_vinculos = request.form.getlist("membro_vinculo[]")
        composicao = []
        for i in range(len(membros_nomes)):
            if membros_nomes[i].strip():
                composicao.append({
                    'nome': membros_nomes[i],
                    'idade': membros_idades[i] if i < len(membros_idades) else '',
                    'vinculo': membros_vinculos[i] if i < len(membros_vinculos) else ''
                })
        composicao_json = json.dumps(composicao, ensure_ascii=False)
        total_pessoas = len(composicao)
        
        # Renda
        renda_bruta = float(request.form.get("renda_bruta", 0) or 0)
        renda_per_capita = float(request.form.get("renda_per_capita", 0) or 0)
        beneficios = request.form.get("beneficios", "")
        
        # Vulnerabilidades
        vulnerabilidades = request.form.getlist("vulnerabilidade")
        vulnerabilidade_text = ", ".join(vulnerabilidades) if vulnerabilidades else ""
        
        # Serviços SUAS
        servicos = request.form.getlist("servicos_suas")
        servicos_text = ", ".join(servicos) if servicos else ""
        
        # Parecer
        parecer = request.form.get("parecer", "")
        
        # Exceção Art. 64 - concessão fora dos critérios ordinários
        excecao_art64 = request.form.get("excecao_art64") == "1"

        # Novos campos
        valor_bolsa_familia = 0.0
        if beneficios == "Bolsa Família":
            try:
                vbf = request.form.get("valor_bolsa_familia", "0").replace('.','').replace(',','.')
                valor_bolsa_familia = float(vbf or 0)
            except: pass
        visita_domiciliar = request.form.get("visita_domiciliar") == "1"

        # Validação server-side: renda per capita vs critério legal
        salario_minimo = get_salario_minimo()
        limite_rpc = salario_minimo / 4
        if renda_per_capita > limite_rpc and not excecao_art64:
            flash(f'❌ Renda per capita (R$ {renda_per_capita:.2f}) ultrapassa o limite legal de R$ {limite_rpc:.2f} (1/4 do salário mínimo). Marque a exceção do Art. 64 para prosseguir.', 'danger')
            return render_template("index.html", sucesso=False)
        
        tecnico = current_user.id
        data_solic = datetime.now(FUSO_RONDONIA).strftime("%d/%m/%Y %H:%M:%S")
        
        conexao = get_db()
        cursor = conexao.cursor()
        cursor.execute("""
            INSERT INTO solicitacoes (tecnico, cpf, cpf_hash, nome, data_nascimento, telefone, email, endereco, numero, complemento, bairro, cep, referencia, cras, data_escuta, total_pessoas, composicao_familiar, renda_bruta, renda_per_capita, beneficios, vulnerabilidade, servicos_suas, parecer, status, data_solicitacao, excecao_art64, valor_bolsa_familia, visita_domiciliar)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (tecnico, cpf_cripto, cpf_hash, nome, data_nasc, telefone, email, endereco, numero, complemento, bairro, cep, referencia, cras, data_escuta, total_pessoas, composicao_json, renda_bruta, renda_per_capita, beneficios, vulnerabilidade_text, servicos_text, parecer, 'Cadastrada', data_solic, excecao_art64, valor_bolsa_familia, visita_domiciliar))
        conexao.commit()
        conexao.close()
        
        logger.info(f"Solicitação cadastrada: {nome}")
        flash('✅ Solicitação cadastrada!', 'success')
        return redirect(url_for("solicitacoes"))
    bairros_por_cras = get_bairros_por_cras()
    return render_template("index.html", sucesso=False,
                           bairros_por_cras=bairros_por_cras)

# =====================================================
# LISTAR SOLICITAÇÕES (CPF DESCRIPTOGRAFADO)
# =====================================================

@app.route("/solicitacoes")
@app.route("/solicitacoes/<int:pagina>")
@login_required
def solicitacoes(pagina=1):
    registros_por_pagina = 20
    offset = (pagina - 1) * registros_por_pagina

    busca_nome              = request.args.get('busca_nome', '').strip()
    busca_status            = request.args.get('busca_status', '').strip()
    busca_cpf               = request.args.get('busca_cpf', '').strip()
    busca_unidade           = request.args.get('busca_unidade', '').strip()
    busca_tecnico_escuta    = request.args.get('busca_tecnico_escuta', '').strip()
    busca_tecnico_entrega   = request.args.get('busca_tecnico_entrega', '').strip()
    busca_tecnico_qualquer  = request.args.get('busca_tecnico_qualquer', '').strip()
    periodo_inicio          = request.args.get('periodo_inicio', '').strip()
    periodo_fim             = request.args.get('periodo_fim', '').strip()

    filtros = []
    params  = []
    join_usuario = ""

    if current_user.perfil not in ['admin', 'gestor', 'creas', 'cras_volante']:
        filtros.append("s.cras = %s")
        params.append(current_user.cras)

    if busca_nome:
        filtros.append("s.nome ILIKE %s")
        params.append(f"%{busca_nome}%")

    if busca_status == 'Visita':
        filtros.append("s.visita_domiciliar = TRUE")
    elif busca_status:
        filtros.append("s.status = %s")
        params.append(busca_status)

    if busca_tecnico_escuta:
        filtros.append("s.tecnico = %s")
        params.append(busca_tecnico_escuta)

    if busca_tecnico_entrega:
        filtros.append("s.tecnico_entrega = %s")
        params.append(busca_tecnico_entrega)

    if busca_tecnico_qualquer:
        filtros.append("(s.tecnico = %s OR s.tecnico_entrega = %s)")
        params.extend([busca_tecnico_qualquer, busca_tecnico_qualquer])

    if busca_unidade:
        join_usuario = "LEFT JOIN usuarios u ON s.tecnico = u.usuario"
        if busca_unidade == 'CREAS':
            filtros.append("u.perfil = 'creas'")
        elif busca_unidade == 'EQUIPE VOLANTE':
            filtros.append("u.perfil = 'cras_volante'")
        elif busca_unidade == 'ADMINISTRAÇÃO':
            filtros.append("u.perfil IN ('admin', 'gestor')")
        else:
            filtros.append("COALESCE(u.cras, s.cras) = %s")
            params.append(busca_unidade)

    cond_periodo, p_periodo = _periodo_sql(periodo_inicio, periodo_fim)
    if cond_periodo:
        filtros.append(cond_periodo)
        params.extend(p_periodo)

    where = ("WHERE " + " AND ".join(filtros)) if filtros else ""

    conexao = get_db()
    cursor  = conexao.cursor()

    # Listas para dropdowns
    cursor.execute("SELECT usuario, nome FROM usuarios ORDER BY nome")
    lista_tecnicos = cursor.fetchall()
    lista_unidades = get_lista_cras() + ['CREAS', 'EQUIPE VOLANTE']
    nomes_meses = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
                   'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro']
    lista_meses_sol = []
    agora = datetime.now(FUSO_RONDONIA)
    for i in range(24):
        d = agora - timedelta(days=30 * i)
        if d.year < 2026:
            break
        lista_meses_sol.append({'valor': d.strftime('%Y-%m'), 'nome': f"{nomes_meses[d.month-1]}/{d.year}"})

    base_query = f"FROM solicitacoes s {join_usuario} {where}"

    # Busca por CPF: descriptografa em Python
    if busca_cpf:
        cpf_limpo_busca = _re.sub(r'\D', '', busca_cpf)
        cursor.execute(
            f"SELECT s.id, s.tecnico, s.nome, s.cpf, s.bairro, s.cras, s.data_solicitacao, s.status, s.visita_domiciliar "
            f"{base_query} ORDER BY s.id DESC",
            params
        )
        todos = cursor.fetchall()
        dados_filtrados = []
        for row in todos:
            row = list(row)
            cpf_desc = descriptografar_cpf(row[3]) if row[3] else ''
            if cpf_limpo_busca in cpf_desc:
                row[3] = formatar_cpf(cpf_desc)
                dados_filtrados.append(tuple(row))
        total_registros = len(dados_filtrados)
        dados = dados_filtrados[(pagina - 1) * registros_por_pagina: pagina * registros_por_pagina]
    else:
        cursor.execute(f"SELECT COUNT(*) {base_query}", params)
        total_registros = cursor.fetchone()[0]
        cursor.execute(
            f"SELECT s.id, s.tecnico, s.nome, s.cpf, s.bairro, s.cras, s.data_solicitacao, s.status, s.visita_domiciliar "
            f"{base_query} ORDER BY s.id DESC LIMIT %s OFFSET %s",
            params + [registros_por_pagina, offset]
        )
        dados_raw = cursor.fetchall()
        dados = []
        for row in dados_raw:
            row = list(row)
            if row[3]:
                row[3] = formatar_cpf(descriptografar_cpf(row[3]))
            dados.append(tuple(row))

    conexao.close()

    total_paginas = max(1, (total_registros + registros_por_pagina - 1) // registros_por_pagina)

    return render_template(
        "solicitacoes.html",
        solicitacoes=dados,
        user_perfil=current_user.perfil,
        datetime=datetime,
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_registros=total_registros,
        busca_nome=busca_nome,
        busca_status=busca_status,
        busca_cpf=busca_cpf,
        busca_unidade=busca_unidade,
        busca_tecnico_escuta=busca_tecnico_escuta,
        busca_tecnico_entrega=busca_tecnico_entrega,
        busca_tecnico_qualquer=busca_tecnico_qualquer,
        periodo_inicio=periodo_inicio,
        periodo_fim=periodo_fim,
        lista_tecnicos=lista_tecnicos,
        lista_unidades=lista_unidades,
        lista_meses=lista_meses_sol,
        current_user=current_user
    )

# =====================================================
# VER SOLICITAÇÕES
# =====================================================

@app.route("/ver_solicitacao/<int:id>")
@login_required
def ver_solicitacao(id):
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT 
            s.id, s.nome, s.cpf, s.data_nascimento, s.telefone, 
            s.data_solicitacao, s.email, s.endereco, s.numero, 
            s.complemento, s.bairro, s.cep, s.referencia, s.cras, 
            s.renda_bruta, s.renda_per_capita, s.beneficios, 
            s.vulnerabilidade, s.data_entrega, s.tecnico_entrega,
            s.parecer, s.status, s.tecnico, s.composicao_familiar,
            s.servicos_suas, u_escuta.nome as tecnico_escuta_nome,
            u_entrega.nome as tecnico_entrega_nome,
            s.num_tentativas,
            s.valor_bolsa_familia,
            s.visita_domiciliar
        FROM solicitacoes s
        LEFT JOIN usuarios u_escuta ON s.tecnico = u_escuta.usuario
        LEFT JOIN usuarios u_entrega ON s.tecnico_entrega = u_entrega.usuario
        WHERE s.id = %s
    """, (id,))
    s = cursor.fetchone()
    if not s:
        conexao.close()
        return "Não encontrada", 404

    s = list(s)
    if s[2]:
        s[2] = formatar_cpf(descriptografar_cpf(s[2]))
    if s[3]:
        try:
            if '-' in str(s[3]):
                partes = str(s[3]).split('-')
                if len(partes) == 3:
                    s[3] = f"{partes[2]}/{partes[1]}/{partes[0]}"
        except:
            pass

    # Histórico de edições
    cursor.execute("""
        SELECT campo, valor_antes, valor_depois, usuario, data_hora
        FROM historico_edicoes
        WHERE solicitacao_id = %s
        ORDER BY data_hora DESC
        LIMIT 50
    """, (id,))
    historico = cursor.fetchall()
    conexao.close()

    return render_template(
        "ver_solicitacao.html",
        solicitacao=s,
        historico=historico,
        json=json,
        datetime=datetime,
        current_user=current_user
    )

# =====================================================
# EDITAR SOLICITAÇÃO
# =====================================================

@app.route("/editar_solicitacao/<int:id>", methods=["GET", "POST"])
@login_required
def editar_solicitacao(id):
    conexao = get_db()
    cursor = conexao.cursor()

    # Buscar solicitação
    cursor.execute("SELECT * FROM solicitacoes WHERE id = %s", (id,))
    row = cursor.fetchone()
    if not row:
        conexao.close()
        return "Solicitação não encontrada", 404

    cols = [d[0] for d in cursor.description]
    s = dict(zip(cols, row))

    # Descriptografar CPF para exibição
    s['cpf'] = formatar_cpf(descriptografar_cpf(s['cpf'])) if s['cpf'] else ''

    # Verificar permissão: só o autor (status Cadastrada) ou admin
    eh_admin   = current_user.perfil == 'admin'
    eh_autor   = current_user.id == s['tecnico']
    ja_entregue = s.get('status') in ('Entregue', 'Ausente')

    pode_editar = eh_admin or (eh_autor and not ja_entregue)

    if not pode_editar:
        conexao.close()
        if ja_entregue:
            flash('❌ Esta solicitação já teve a entrega registrada e não pode mais ser editada.', 'danger')
        else:
            flash('❌ Você não tem permissão para editar esta solicitação.', 'danger')
        return redirect(url_for('ver_solicitacao', id=id))

    if request.method == "POST":
        nome         = request.form.get("nome", "")
        data_nasc    = request.form.get("data_nascimento", "")
        telefone     = request.form.get("telefone", "")
        email        = request.form.get("email", "")
        endereco     = request.form.get("endereco", "")
        numero       = request.form.get("numero", "")
        complemento  = request.form.get("complemento", "")
        bairro       = request.form.get("bairro", "")
        cep          = request.form.get("cep", "")
        referencia   = request.form.get("referencia", "")
        cras         = request.form.get("cras", "")
        data_escuta  = request.form.get("data_escuta", "")
        renda_bruta  = float(request.form.get("renda_bruta", 0) or 0)
        renda_rpc    = float(request.form.get("renda_per_capita", 0) or 0)
        beneficios   = request.form.get("beneficios", "")
        vuls         = request.form.getlist("vulnerabilidade")
        servicos     = request.form.getlist("servicos_suas")
        parecer      = request.form.get("parecer", "")
        excecao      = request.form.get("excecao_art64") == "1"
        visita_dom   = request.form.get("visita_domiciliar") == "1"
        valor_bf     = 0.0
        if beneficios == "Bolsa Família":
            try:
                vbf = request.form.get("valor_bolsa_familia", "0").replace('.','').replace(',','.')
                valor_bf = float(vbf or 0)
            except: pass

        membros_nomes    = request.form.getlist("membro_nome[]")
        membros_idades   = request.form.getlist("membro_idade[]")
        membros_vinculos = request.form.getlist("membro_vinculo[]")
        composicao = []
        for i in range(len(membros_nomes)):
            if membros_nomes[i].strip():
                composicao.append({
                    'nome': membros_nomes[i],
                    'idade': membros_idades[i] if i < len(membros_idades) else '',
                    'vinculo': membros_vinculos[i] if i < len(membros_vinculos) else ''
                })

        novos = {
            'nome': nome, 'data_nascimento': data_nasc,
            'telefone': telefone, 'email': email,
            'endereco': endereco, 'numero': numero,
            'complemento': complemento, 'bairro': bairro,
            'cep': cep, 'referencia': referencia, 'cras': cras,
            'data_escuta': data_escuta,
            'renda_bruta': str(renda_bruta), 'renda_per_capita': str(renda_rpc),
            'beneficios': beneficios,
            'vulnerabilidade': ", ".join(vuls),
            'servicos_suas': ", ".join(servicos),
            'parecer': parecer,
            'excecao_art64': str(excecao),
        }

        cursor.execute("""
            UPDATE solicitacoes SET
                nome=%s, data_nascimento=%s, telefone=%s, email=%s,
                endereco=%s, numero=%s, complemento=%s, bairro=%s,
                cep=%s, referencia=%s, cras=%s, data_escuta=%s,
                total_pessoas=%s, composicao_familiar=%s,
                renda_bruta=%s, renda_per_capita=%s, beneficios=%s,
                vulnerabilidade=%s, servicos_suas=%s, parecer=%s,
                excecao_art64=%s, visita_domiciliar=%s, valor_bolsa_familia=%s
            WHERE id=%s
        """, (
            nome, data_nasc, telefone, email,
            endereco, numero, complemento, bairro,
            cep, referencia, cras, data_escuta,
            len(composicao), json.dumps(composicao, ensure_ascii=False),
            renda_bruta, renda_rpc, beneficios,
            ", ".join(vuls), ", ".join(servicos), parecer,
            excecao, visita_dom, valor_bf, id
        ))

        # ── Registrar histórico de alterações ──
        agora = datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M:%S')
        labels = {
            'nome': 'Nome', 'data_nascimento': 'Data de nascimento',
            'telefone': 'Telefone', 'email': 'E-mail',
            'endereco': 'Endereço', 'numero': 'Número',
            'complemento': 'Complemento', 'bairro': 'Bairro',
            'cep': 'CEP', 'referencia': 'Referência', 'cras': 'CRAS',
            'data_escuta': 'Data da escuta', 'renda_bruta': 'Renda bruta',
            'renda_per_capita': 'Renda per capita', 'beneficios': 'Benefícios',
            'vulnerabilidade': 'Vulnerabilidade', 'servicos_suas': 'Serviços SUAS',
            'parecer': 'Parecer técnico', 'excecao_art64': 'Exceção Art.64',
        }
        for campo, novo_val in novos.items():
            antigo = str(s.get(campo, '') or '')
            if antigo != str(novo_val or ''):
                cursor.execute("""
                    INSERT INTO historico_edicoes
                        (solicitacao_id, usuario, campo, valor_antes, valor_depois, data_hora)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (id, current_user.id, labels.get(campo, campo), antigo, str(novo_val), agora))

        conexao.commit()
        conexao.close()
        logger.info(f"Solicitação {id} editada por {current_user.id}")
        flash('✅ Solicitação atualizada com sucesso!', 'success')
        return redirect(url_for('ver_solicitacao', id=id))

    conexao.close()
    bairros_por_cras = get_bairros_por_cras()
    return render_template("editar_solicitacao.html", s=s, current_user=current_user,
                           bairros_por_cras=bairros_por_cras)



@app.route("/gerar_pdf/<int:id>")
@login_required
def gerar_pdf_assinatura(id):
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT 
            s.id,                       
            s.tecnico,                  
            s.nome,                     
            s.cpf,                      
            s.data_nascimento,          
            s.telefone,                 
            s.endereco,                 
            s.numero,                   
            s.bairro,                   
            s.cras,                     
            s.renda_bruta,              
            s.renda_per_capita,         
            s.parecer,                  
            s.status,                   
            s.data_escuta,              
            s.data_solicitacao,         
            u_escuta.nome as tecnico_nome,          
            s.data_entrega,             
            s.tecnico_entrega,          
            u_entrega.nome as tecnico_entrega_nome,
            s.composicao_familiar,      
            s.beneficios,               
            s.vulnerabilidade,          
            s.servicos_suas,            
            s.total_pessoas,            
            s.cep,                      -- ÍNDICE 25
            s.referencia,               -- ÍNDICE 26
            s.complemento,              -- ÍNDICE 27
            s.email,                    -- ÍNDICE 28
            s.excecao_art64,            -- ÍNDICE 29
            s.valor_bolsa_familia,      -- ÍNDICE 30
            s.visita_domiciliar         -- ÍNDICE 31
        FROM solicitacoes s
        LEFT JOIN usuarios u_escuta ON s.tecnico = u_escuta.usuario
        LEFT JOIN usuarios u_entrega ON s.tecnico_entrega = u_entrega.usuario
        WHERE s.id = %s
    """, (id,))
   
    s = cursor.fetchone()
    conexao.close()
    
    if not s:
        return "Solicitação não encontrada", 404
    
    # Mapeamento claro dos índices (DOCUMENTAÇÃO)
    ID = 0
    TECNICO = 1
    NOME = 2
    CPF = 3
    DATA_NASC = 4
    TELEFONE = 5
    ENDERECO = 6
    NUMERO = 7
    BAIRRO = 8
    CRAS = 9
    RENDA_BRUTA = 10
    RENDA_PER_CAPITA = 11
    PARECER = 12
    STATUS = 13
    DATA_ESCUTA = 14
    DATA_SOLICITACAO = 15
    TECNICO_NOME = 16
    DATA_ENTREGA = 17
    TECNICO_ENTREGA = 18
    TECNICO_ENTREGA_NOME = 19
    COMPOSICAO_FAMILIAR = 20
    BENEFICIOS = 21
    VULNERABILIDADE = 22
    SERVICOS_SUAS = 23
    TOTAL_PESSOAS = 24
    CEP = 25
    REFERENCIA = 26
    COMPLEMENTO = 27
    EMAIL = 28
    EXCECAO_ART64 = 29
    VALOR_BOLSA_FAMILIA = 30
    VISITA_DOMICILIAR = 31
    
    # Descriptografar CPF
    cpf_pdf = formatar_cpf(descriptografar_cpf(s[CPF])) if s[CPF] else 'N/A'
    
    # Formatar data de nascimento
    data_nasc = s[DATA_NASC] if s[DATA_NASC] else 'N/A'
    if data_nasc != 'N/A' and '-' in str(data_nasc):
        try:
            partes = str(data_nasc).split('-')
            if len(partes) == 3:
                data_nasc = f"{partes[2]}/{partes[1]}/{partes[0]}"
        except:
            pass
    
    # Formatar data da escuta
    data_escuta = s[DATA_ESCUTA] if s[DATA_ESCUTA] else 'N/A'
    if data_escuta != 'N/A' and '-' in str(data_escuta):
        try:
            partes = str(data_escuta).split('-')
            if len(partes) == 3:
                data_escuta = f"{partes[2]}/{partes[1]}/{partes[0]}"
        except:
            pass
    
    # Formatar data da entrega
    data_entrega_pdf = '___/___/_______'
    if s[DATA_ENTREGA]:
        data_entrega_pdf = str(s[DATA_ENTREGA])
        if '-' in data_entrega_pdf:
            try:
                partes = data_entrega_pdf.split('-')
                if len(partes) == 3:
                    data_entrega_pdf = f"{partes[2]}/{partes[1]}/{partes[0]}"
            except:
                pass
    
    # Formatar CEP
    cep_valor = ''.join(filter(str.isdigit, str(s[CEP]))) if s[CEP] else ''
    if len(cep_valor) == 8:
        cep_formatado = f"{cep_valor[:5]}-{cep_valor[5:]}"
    elif cep_valor:
        cep_formatado = cep_valor
    else:
        cep_formatado = 'N/A'
    
    numero_controle = f"CB-{datetime.now(FUSO_RONDONIA).strftime('%Y%m%d')}-{s[ID]:04d}"
    data_geracao = datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y às %H:%M:%S')
    tecnico_escuta = s[TECNICO_NOME] if s[TECNICO_NOME] else s[TECNICO]

    # ─── Gerar QR Code ────────────────────────────────────────────
    base_url = os.environ.get('BASE_URL', request.host_url.rstrip('/'))
    qr_conteudo = (
        f"Sistema SEMASF - Ji-Paraná\n"
        f"Controle: {numero_controle}\n"
        f"Técnico: {tecnico_escuta}\n"
        f"Gerado em: {data_geracao}\n"
        f"URL: {base_url}/ver_solicitacao/{s[ID]}"
    )
    qr_img = qrcode.make(qr_conteudo)
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    qr_reader = ImageReader(qr_buffer)

    # ─── Estrutura de duas passagens para "Página X de Y" ─────────
    # Passagem 1: contar páginas
    # Passagem 2: desenhar com total de páginas conhecido
    # Usamos uma classe auxiliar que desenha o rodapé no onPage

    MARGEM_RODAPE = 3.8*cm   # altura reservada para rodapé (QR + textos)
    MARGEM_TOP    = 2*cm
    LIMITE_Y      = MARGEM_RODAPE  # conteúdo não desce abaixo disso

    def desenhar_rodape(canvas_obj, pagina_atual, total_paginas):
        """Desenha rodapé padronizado em qualquer página."""
        canvas_obj.saveState()
        w, h = A4

        # Linha separadora
        canvas_obj.setStrokeColorRGB(0.5, 0.5, 0.5)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(2*cm, MARGEM_RODAPE - 0.1*cm, w - 2*cm, MARGEM_RODAPE - 0.1*cm)

        # QR Code (canto direito do rodapé)
        qr_size = 3.0*cm
        qr_x = w - 2*cm - qr_size
        qr_y = 0.5*cm
        canvas_obj.drawImage(qr_reader, qr_x, qr_y, width=qr_size, height=qr_size)
        canvas_obj.setFont("Helvetica", 5.5)
        canvas_obj.setFillColorRGB(0.4, 0.4, 0.4)
        canvas_obj.drawCentredString(qr_x + qr_size/2, qr_y - 0.3*cm, "Assinatura Digital")

        # Textos do rodapé (à esquerda do QR)
        tx = 2*cm
        canvas_obj.setFont("Helvetica-Bold", 7.5)
        canvas_obj.setFillColorRGB(0.15, 0.15, 0.15)
        canvas_obj.drawString(tx, MARGEM_RODAPE - 0.55*cm,
            "⚠  Este documento deve ser assinado pelo beneficiário e pelo técnico responsável pela entrega.")

        canvas_obj.setFont("Helvetica", 7.5)
        canvas_obj.setFillColorRGB(0.2, 0.2, 0.2)
        canvas_obj.drawString(tx, MARGEM_RODAPE - 1.0*cm,
            "A escuta, entrega e critérios de concessão obedeceram à Lei Municipal do SUAS nº 3.603 de 01/12/2022.")
        canvas_obj.drawString(tx, MARGEM_RODAPE - 1.4*cm,
            f"Documento gerado em {data_geracao}  |  Nº de Controle: {numero_controle}")

        # Numeração de páginas
        canvas_obj.setFont("Helvetica-Bold", 8)
        canvas_obj.setFillColorRGB(0.2, 0.2, 0.2)
        canvas_obj.drawString(tx, MARGEM_RODAPE - 1.85*cm,
            f"Página {pagina_atual} de {total_paginas}")

        canvas_obj.restoreState()

    def gerar_conteudo(canvas_obj, total_paginas_conhecido=None):
        """
        Desenha todo o conteúdo do PDF.
        Se total_paginas_conhecido for None, apenas conta as páginas (passagem 1).
        Caso contrário, desenha de verdade (passagem 2).
        """
        w, h = A4
        pagina_atual = 1
        desenhar = total_paginas_conhecido is not None

        def nova_pagina():
            nonlocal pagina_atual
            if desenhar:
                desenhar_rodape(canvas_obj, pagina_atual, total_paginas_conhecido)
            canvas_obj.showPage()
            pagina_atual += 1
            return h - MARGEM_TOP

        def check_space(needed, current_y):
            if current_y - needed < LIMITE_Y:
                return nova_pagina()
            return current_y

        y = h - MARGEM_TOP

        if desenhar:
            # ── CABEÇALHO ──────────────────────────────────────────
            logo_path = os.path.join(os.path.dirname(__file__), 'static', 'img', 'logo_prefeitura.png')
            # Logo no canto DIREITO — largura fixa 5.5cm para não sobrepor o texto
            logo_largura = 5.5*cm
            logo_altura  = 1.8*cm   # bounding box; aspect real ~4.17:1 → exibe ~5.5×1.32cm
            if os.path.exists(logo_path):
                try:
                    logo_reader = ImageReader(logo_path)
                    logo_x = w - 2*cm - logo_largura
                    canvas_obj.drawImage(logo_reader, logo_x, y - logo_altura + 0.4*cm,
                                         height=logo_altura, width=logo_largura,
                                         preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass
            canvas_obj.setFont("Helvetica-Bold", 14)
            canvas_obj.drawString(2*cm, y, "PREFEITURA MUNICIPAL DE JI-PARANÁ")
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica-Bold", 10)
            canvas_obj.drawString(2*cm, y, "Secretaria Municipal de Assistência Social e Família - SEMASF")
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 9)
            canvas_obj.drawString(2*cm, y, "TERMO DE CONCESSÃO DE CESTA BÁSICA")
            y -= 0.4*cm
            canvas_obj.line(2*cm, y, w - 2*cm, y)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica-Bold", 10)
            canvas_obj.drawString(2*cm, y, f"Nº de Controle: {numero_controle}")
            canvas_obj.drawString(10*cm, y, f"Data de Emissão: {datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M')}")
            y -= 0.8*cm

            # ── 1. DADOS DO BENEFICIÁRIO ────────────────────────────
            y = check_space(5*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "1. DADOS DO BENEFICIÁRIO")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 10)
            for label, valor in [
                ("Nome:", s[NOME] if s[NOME] else 'N/A'),
                ("CPF:", cpf_pdf),
                ("Data de Nascimento:", data_nasc),
                ("Telefone:", s[TELEFONE] if s[TELEFONE] else 'N/A'),
                ("Email:", s[EMAIL] if s[EMAIL] else 'N/A'),
            ]:
                canvas_obj.drawString(2.5*cm, y, f"{label} {valor}")
                y -= 0.45*cm
            y -= 0.2*cm

            # ── 2. ENDEREÇO ─────────────────────────────────────────
            y = check_space(7*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "2. ENDEREÇO")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 10)
            end_val = s[ENDERECO] if s[ENDERECO] else ''
            num_val = s[NUMERO] if s[NUMERO] else 'S/N'
            comp_val = s[COMPLEMENTO] if s[COMPLEMENTO] else ''
            end_completo = f"{end_val}, {num_val}" + (f" - {comp_val}" if comp_val else "")
            for label, valor in [
                ("Endereço:", end_completo[:60]),
                ("Bairro:", s[BAIRRO] if s[BAIRRO] else 'N/A'),
                ("CEP:", cep_formatado),
                ("Referência:", s[REFERENCIA][:50] if s[REFERENCIA] else 'N/A'),
                ("CRAS:", s[CRAS] if s[CRAS] else 'N/A'),
            ]:
                canvas_obj.drawString(2.5*cm, y, f"{label} {valor}")
                y -= 0.45*cm
            y -= 0.2*cm

            # ── 3. INFORMAÇÕES SOCIOECONÔMICAS ──────────────────────
            y = check_space(6*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "3. INFORMAÇÕES SOCIOECONÔMICAS")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 10)
            rb_val = s[RENDA_BRUTA] if s[RENDA_BRUTA] and float(s[RENDA_BRUTA]) > 0 else 0
            rpc_val = s[RENDA_PER_CAPITA] if s[RENDA_PER_CAPITA] and float(s[RENDA_PER_CAPITA]) > 0 else 0
            for label, valor in [
                ("Renda Bruta Familiar:", f"R$ {float(rb_val):.2f}" if rb_val > 0 else 'N/A'),
                ("Renda Per Capita:", f"R$ {float(rpc_val):.2f}" if rpc_val > 0 else 'N/A'),
                ("Benefícios:", ((s[BENEFICIOS] if s[BENEFICIOS] else 'Nenhum') + (f" — R$ {float(s[VALOR_BOLSA_FAMILIA]):.2f}" if s[BENEFICIOS] == 'Bolsa Família' and s[VALOR_BOLSA_FAMILIA] else ''))[:60]),
                ("Vulnerabilidades:", (s[VULNERABILIDADE] if s[VULNERABILIDADE] else 'Não informado')[:50]),
                ("Serviços SUAS:", (s[SERVICOS_SUAS] if s[SERVICOS_SUAS] else 'Não informado')[:50]),
            ]:
                canvas_obj.drawString(2.5*cm, y, f"{label} {valor}")
                y -= 0.45*cm
            y -= 0.2*cm

            # ── 4. COMPOSIÇÃO FAMILIAR ──────────────────────────────
            y = check_space(8*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "4. COMPOSIÇÃO FAMILIAR")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 10)
            total_pess = s[TOTAL_PESSOAS] if s[TOTAL_PESSOAS] and s[TOTAL_PESSOAS] > 0 else 1
            canvas_obj.drawString(2.5*cm, y, f"Total de pessoas: {total_pess}")
            y -= 0.5*cm
            comp_familiar = s[COMPOSICAO_FAMILIAR] if s[COMPOSICAO_FAMILIAR] else '[]'
            try:
                membros = json.loads(comp_familiar)
                if membros:
                    canvas_obj.setFont("Helvetica-Bold", 9)
                    canvas_obj.drawString(3*cm, y, "Nome")
                    canvas_obj.drawString(9*cm, y, "Idade")
                    canvas_obj.drawString(13*cm, y, "Vínculo")
                    y -= 0.4*cm
                    canvas_obj.setFont("Helvetica", 9)
                    for membro in membros[:8]:
                        y = check_space(1*cm, y)
                        canvas_obj.drawString(3*cm, y, membro.get('nome', '')[:25])
                        canvas_obj.drawString(9*cm, y, str(membro.get('idade', '')))
                        canvas_obj.drawString(13*cm, y, membro.get('vinculo', '')[:15])
                        y -= 0.35*cm
                else:
                    canvas_obj.drawString(2.5*cm, y, "Família unipessoal")
                    y -= 0.35*cm
            except:
                canvas_obj.drawString(2.5*cm, y, "Não informado")
                y -= 0.35*cm
            y -= 0.2*cm

            # ── 5. REGISTRO DE ATENDIMENTO ──────────────────────────
            y = check_space(4*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "5. REGISTRO DE ATENDIMENTO")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 10)
            for label, valor in [
                ("Técnico que realizou a Escuta:", tecnico_escuta),
                ("Data da Escuta Técnica:", data_escuta),
                ("Status:", s[STATUS] if s[STATUS] else 'N/A'),
            ]:
                canvas_obj.drawString(2.5*cm, y, f"{label} {valor}")
                y -= 0.45*cm
            y -= 0.2*cm

            # ── 6. PARECER TÉCNICO ──────────────────────────────────
            y = check_space(5*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "6. PARECER TÉCNICO")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm

            # Aviso de exceção Art. 64
            if s[EXCECAO_ART64]:
                box_x = 2*cm
                box_largura = w - 4*cm  # mesma largura útil da página (margens de 2cm)
                box_altura = 1.15*cm
                box_topo = y
                # Moldura
                canvas_obj.setStrokeColorRGB(0.7, 0.1, 0.1)
                canvas_obj.setLineWidth(1)
                canvas_obj.rect(box_x, box_topo - box_altura, box_largura, box_altura, fill=0)
                # Texto dentro da moldura (com recuo interno)
                canvas_obj.setFillColorRGB(0.7, 0.1, 0.1)
                canvas_obj.setFont("Helvetica-Bold", 8)
                canvas_obj.drawString(box_x + 0.3*cm, box_topo - 0.4*cm,
                    "CONCESSÃO EXCEPCIONAL — Art. 64 da Lei Municipal nº 3.603/2022")
                canvas_obj.setFont("Helvetica", 7.5)
                canvas_obj.drawString(box_x + 0.3*cm, box_topo - 0.72*cm,
                    "Situação não contemplada nos critérios ordinários, autorizada mediante parecer técnico social")
                canvas_obj.drawString(box_x + 0.3*cm, box_topo - 1.0*cm,
                    "e autorização do gestor da SEMASF.")
                canvas_obj.setFillColorRGB(0, 0, 0)
                canvas_obj.setStrokeColorRGB(0, 0, 0)
                y -= (box_altura + 0.4*cm)

            # Aviso de visita domiciliar
            if s[VISITA_DOMICILIAR]:
                vd_x = 2*cm
                vd_largura = w - 4*cm
                vd_altura = 0.9*cm
                canvas_obj.setStrokeColorRGB(0.0, 0.45, 0.7)
                canvas_obj.setLineWidth(1)
                canvas_obj.rect(vd_x, y - vd_altura, vd_largura, vd_altura, fill=0)
                canvas_obj.setFillColorRGB(0.0, 0.45, 0.7)
                canvas_obj.setFont("Helvetica-Bold", 8)
                canvas_obj.drawString(vd_x + 0.3*cm, y - 0.38*cm,
                    "VISITA DOMICILIAR SOLICITADA — Averiguação das condições relatadas pelo beneficiário.")
                canvas_obj.setFont("Helvetica", 7.5)
                canvas_obj.drawString(vd_x + 0.3*cm, y - 0.68*cm,
                    "O técnico responsável identificou necessidade de verificação in loco antes da concessão.")
                canvas_obj.setFillColorRGB(0, 0, 0)
                canvas_obj.setStrokeColorRGB(0, 0, 0)
                y -= (vd_altura + 0.4*cm)

            parecer_txt = _strip_html(s[PARECER]) if s[PARECER] else 'Sem parecer técnico registrado.'
            text_object = canvas_obj.beginText(2.5*cm, y)
            text_object.setFont("Helvetica", 9)
            max_w = w - 5*cm

            for paragrafo in parecer_txt.split('\n'):
                paragrafo = paragrafo.strip()
                # Linha em branco entre parágrafos
                if not paragrafo:
                    text_object.textLine('')
                    continue
                linha = ""
                for palavra in paragrafo.split():
                    teste = linha + " " + palavra if linha else palavra
                    if canvas_obj.stringWidth(teste, "Helvetica", 9) <= max_w:
                        linha = teste
                    else:
                        text_object.textLine(linha)
                        linha = palavra
                        if text_object.getY() < LIMITE_Y:
                            canvas_obj.drawText(text_object)
                            y = nova_pagina()
                            text_object = canvas_obj.beginText(2.5*cm, y)
                            text_object.setFont("Helvetica", 9)
                if linha:
                    text_object.textLine(linha)
                # Espaço entre parágrafos
                text_object.textLine('')

            canvas_obj.drawText(text_object)
            y = text_object.getY() - 1*cm

            # ── 7. ASSINATURAS ──────────────────────────────────────
            if y < 8*cm + LIMITE_Y:
                y = nova_pagina()
            else:
                y -= 0.5*cm
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "7. ASSINATURAS")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.8*cm
            canvas_obj.setFont("Helvetica-Bold", 10)
            canvas_obj.drawString(2*cm, y, f"Data da Entrega: {data_entrega_pdf}")
            y -= 1.2*cm
            canvas_obj.setFont("Helvetica", 10)
            canvas_obj.line(2*cm, y, 9.5*cm, y)
            canvas_obj.drawString(2*cm, y - 0.4*cm, "Assinatura do Beneficiário")
            canvas_obj.line(10.5*cm, y, 19*cm, y)
            canvas_obj.drawString(10.5*cm, y - 0.4*cm, "Técnico Responsável pela Entrega")
            y -= 2.5*cm
            if y > LIMITE_Y + 3*cm:
                canvas_obj.rect(2*cm, y - 1.5*cm, 6*cm, 2*cm)
                canvas_obj.setFont("Helvetica", 8)
                canvas_obj.drawString(2.3*cm, y - 0.5*cm, "CARIMBO DO CRAS")
                canvas_obj.drawString(2.3*cm, y - 0.9*cm, s[CRAS] if s[CRAS] else '')

            # Rodapé da última página
            desenhar_rodape(canvas_obj, pagina_atual, total_paginas_conhecido)

        else:
            # ── Passagem 1: simulação apenas para contar páginas ────
            # Replica a mesma lógica de quebra de página sem desenhar
            y -= 3.5*cm  # cabeçalho
            y = check_space(5*cm, y)
            y -= 5 * 0.45*cm + 0.2*cm + 0.6*cm  # dados beneficiário

            y = check_space(7*cm, y)
            y -= 5 * 0.45*cm + 0.2*cm + 0.6*cm  # endereço

            y = check_space(6*cm, y)
            y -= 5 * 0.45*cm + 0.2*cm + 0.6*cm  # socioeconômico

            y = check_space(8*cm, y)
            y -= 0.6*cm + 0.5*cm  # composição - cabeçalho
            try:
                membros = json.loads(s[COMPOSICAO_FAMILIAR] if s[COMPOSICAO_FAMILIAR] else '[]')
                for membro in membros[:8]:
                    y = check_space(1*cm, y)
                    y -= 0.35*cm
            except:
                y -= 0.35*cm
            y -= 0.2*cm

            y = check_space(4*cm, y)
            y -= 3 * 0.45*cm + 0.2*cm + 0.6*cm  # atendimento

            y = check_space(5*cm, y)
            y -= 0.6*cm
            # simular quebra de página do parecer
            parecer_txt = _strip_html(s[PARECER]) if s[PARECER] else 'Sem parecer técnico registrado.'
            linhas_estimadas = max(1, len(parecer_txt) // 80)
            for _ in range(linhas_estimadas):
                if y - 0.4*cm < LIMITE_Y:
                    y = nova_pagina()
                y -= 0.4*cm
            y -= 1*cm

            if y < 8*cm + LIMITE_Y:
                y = nova_pagina()

        return pagina_atual

    # ── Passagem 1: contar páginas ─────────────────────────────────
    counter_buf = io.BytesIO()
    c_count = canvas.Canvas(counter_buf, pagesize=A4)
    total_paginas = gerar_conteudo(c_count, total_paginas_conhecido=None)

    # ── Passagem 2: gerar PDF real ─────────────────────────────────
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    gerar_conteudo(c, total_paginas_conhecido=total_paginas)
    c.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"termo_entrega_{numero_controle}.pdf", mimetype='application/pdf')

# =====================================================
# REGISTRAR ENTREGA
# =====================================================

@app.route("/registrar_entrega/<int:id>", methods=["POST"])
@login_required
def registrar_entrega(id):
    status = request.form.get("status_entrega")
    data = request.form.get("data_entrega")
    observacoes = request.form.get("observacoes", "").strip()
    if not status or not data:
        flash("Preencha todos os campos!", "danger")
        return redirect(url_for("solicitacoes"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute(
        "UPDATE solicitacoes SET status=%s, data_entrega=%s, tecnico_entrega=%s, observacoes_entrega=%s WHERE id=%s",
        (status, data, current_user.id, observacoes or None, id)
    )
    conexao.commit()
    conexao.close()
    logger.info(f"Entrega: ID={id}, Status={status}")
    flash('✅ Registrado!' if status == 'Entregue' else '❌ Ausência registrada.', 'success')
    return redirect(url_for("solicitacoes"))

# =====================================================
# NOVA TENTATIVA DE ENTREGA
# =====================================================

@app.route("/nova_tentativa/<int:id>", methods=["POST"])
@login_required
def nova_tentativa(id):
    """Reseta status para Cadastrada e incrementa contador de tentativas."""
    conexao = get_db()
    cursor  = conexao.cursor()
    cursor.execute("SELECT status, num_tentativas FROM solicitacoes WHERE id = %s", (id,))
    row = cursor.fetchone()
    if not row or row[0] != 'Ausente':
        conexao.close()
        flash("Solicitação não encontrada ou não está com status Ausente.", "danger")
        return redirect(url_for("solicitacoes"))

    tentativa_atual = (row[1] or 1) + 1
    data_hora = datetime.now(FUSO_RONDONIA).strftime("%d/%m/%Y %H:%M:%S")

    cursor.execute("""
        UPDATE solicitacoes
        SET status = 'Cadastrada',
            data_entrega = NULL,
            tecnico_entrega = NULL,
            observacoes_entrega = NULL,
            num_tentativas = %s
        WHERE id = %s
    """, (tentativa_atual, id))

    cursor.execute("""
        INSERT INTO historico_edicoes (solicitacao_id, usuario, campo, valor_antes, valor_depois, data_hora)
        VALUES (%s, %s, 'status', 'Ausente', %s, %s)
    """, (id, current_user.id, f'Cadastrada (tentativa {tentativa_atual})', data_hora))

    conexao.commit()
    conexao.close()

    logger.info(f"Nova tentativa: ID={id}, tentativa={tentativa_atual}, tecnico={current_user.id}")
    flash(f"✅ Solicitação #{id} reaberta para nova tentativa de entrega (tentativa {tentativa_atual}).", "success")
    return redirect(url_for("ver_solicitacao", id=id))


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for('solicitacoes'))

    conexao = get_db()
    cursor  = conexao.cursor()

    # Totais gerais
    cursor.execute("SELECT COUNT(*) FROM solicitacoes")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status='Entregue'")
    entregues = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status='Ausente'")
    ausentes = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status='Cadastrada'")
    pendentes = cursor.fetchone()[0]

    # Por equipe (CRAS/perfil do técnico que registrou — produção real da equipe)
    cursor.execute("""
        SELECT
            CASE
                WHEN u.perfil = 'creas'       THEN 'CREAS'
                WHEN u.perfil = 'cras_volante' THEN 'EQUIPE VOLANTE'
                WHEN u.perfil IN ('admin','gestor') THEN 'ADMINISTRAÇÃO'
                ELSE COALESCE(u.cras, s.cras, 'Não informado')
            END AS equipe,
            COUNT(*) AS total,
            SUM(CASE WHEN s.status='Entregue' THEN 1 ELSE 0 END) AS entregues,
            SUM(CASE WHEN s.status='Ausente'  THEN 1 ELSE 0 END) AS ausentes
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico = u.usuario
        GROUP BY equipe ORDER BY total DESC
    """)
    por_cras = cursor.fetchall()

    # Últimos 6 meses (para gráfico de linha)
    cursor.execute("""
        SELECT TO_CHAR(TO_DATE(SUBSTRING(data_solicitacao, 7, 4) || '-' ||
                                SUBSTRING(data_solicitacao, 4, 2) || '-01', 'YYYY-MM-DD'), 'YYYY-MM') AS mes,
               COUNT(*) AS total
        FROM solicitacoes
        WHERE data_solicitacao ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}'
        GROUP BY mes ORDER BY mes DESC LIMIT 6
    """)
    por_mes_raw = cursor.fetchall()
    por_mes = list(reversed(por_mes_raw))

    conexao.close()

    return render_template(
        "dashboard.html",
        total_solicitacoes=total,
        total_entregues=entregues,
        total_ausentes=ausentes,
        total_pendentes=pendentes,
        por_cras=por_cras,
        por_mes=por_mes,
        datetime=datetime,
        current_user=current_user
    )

# =====================================================
# RELATÓRIO
# =====================================================

def _periodo_sql(periodo_inicio, periodo_fim):
    """Retorna (condicao_sql, params) para filtro de período YYYY-MM.
    Se nenhum período for informado, retorna condição vazia (mostra tudo)."""
    if not periodo_inicio and not periodo_fim:
        return "", []
    inicio = periodo_inicio or '2000-01'
    fim    = periodo_fim    or '2099-12'
    cond = """(
        (data_solicitacao ~ '^[0-9]' AND
         (SUBSTRING(data_solicitacao, 7, 4) || '-' || SUBSTRING(data_solicitacao, 4, 2)) BETWEEN %s AND %s)
        OR (data_entrega IS NOT NULL AND data_entrega != '' AND SUBSTRING(data_entrega::text, 1, 7) BETWEEN %s AND %s)
    )"""
    return cond, [inicio, fim, inicio, fim]

def _label_periodo(periodo_inicio, periodo_fim):
    """Gera texto legível para o período selecionado."""
    nomes = ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez']
    def fmt(p):
        try:
            a, m = p.split('-')
            return f"{nomes[int(m)-1]}/{a}"
        except:
            return p
    if periodo_inicio and periodo_fim:
        if periodo_inicio == periodo_fim:
            return fmt(periodo_inicio)
        return f"{fmt(periodo_inicio)} a {fmt(periodo_fim)}"
    if periodo_inicio:
        return f"A partir de {fmt(periodo_inicio)}"
    if periodo_fim:
        return f"Até {fmt(periodo_fim)}"
    return "Todo o período"

@app.route("/relatorio")
@login_required
def relatorio():
    periodo_inicio = request.args.get('periodo_inicio', '').strip()
    periodo_fim    = request.args.get('periodo_fim', '').strip()

    nomes_meses = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
                   'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro']
    lista_meses = []
    agora = datetime.now(FUSO_RONDONIA)
    for i in range(24):
        data = agora - timedelta(days=30 * i)
        if data.year < 2026:
            break
        valor = data.strftime('%Y-%m')
        nome = f"{nomes_meses[data.month - 1]}/{data.year}"
        lista_meses.append({'valor': valor, 'nome': nome})

    cond_periodo, p_periodo = _periodo_sql(periodo_inicio, periodo_fim)
    w = f"WHERE {cond_periodo}" if cond_periodo else ""

    def _and(base):
        return (base + " AND ") if base else "WHERE "

    conexao = get_db()
    cursor = conexao.cursor()

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {_and(w)}status != 'Cancelada'", p_periodo)
    total_solicitacoes = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {_and(w)}status='Entregue'", p_periodo)
    total_entregues = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {_and(w)}status='Ausente'", p_periodo)
    total_ausentes = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {_and(w)}status='Cadastrada'", p_periodo)
    total_pendentes = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {_and(w)}excecao_art64=TRUE", p_periodo)
    total_excecoes = cursor.fetchone()[0]

    # Por Unidade
    cursor.execute(f"""
        SELECT
            CASE
                WHEN u.perfil = 'creas'             THEN 'CREAS'
                WHEN u.perfil = 'cras_volante'       THEN 'EQUIPE VOLANTE'
                WHEN u.perfil IN ('admin','gestor')  THEN 'ADMINISTRAÇÃO'
                ELSE COALESCE(u.cras, s.cras, 'Não informado')
            END AS unidade,
            COUNT(*) as total,
            SUM(CASE WHEN s.status='Entregue' THEN 1 ELSE 0 END) as entregues,
            SUM(CASE WHEN s.status='Ausente'  THEN 1 ELSE 0 END) as ausentes
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico = u.usuario
        {w}
        GROUP BY unidade ORDER BY total DESC
    """, p_periodo)
    por_cras = cursor.fetchall()

    # Por Técnico
    cursor.execute(f"""
        SELECT COALESCE(u.nome, s.tecnico) as nome_tecnico,
               COUNT(*) as total,
               SUM(CASE WHEN s.status='Entregue' THEN 1 ELSE 0 END) as entregues,
               SUM(CASE WHEN s.status='Ausente'  THEN 1 ELSE 0 END) as ausentes
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico = u.usuario
        {w}
        GROUP BY COALESCE(u.nome, s.tecnico) ORDER BY total DESC
    """, p_periodo)
    por_tecnico = cursor.fetchall()

    # Últimas entregas do período (máx 20)
    cursor.execute(f"""
        SELECT s.nome, s.cpf, s.bairro,
               CASE
                   WHEN u_esc.perfil = 'creas'             THEN 'CREAS'
                   WHEN u_esc.perfil = 'cras_volante'       THEN 'EQUIPE VOLANTE'
                   WHEN u_esc.perfil IN ('admin','gestor')  THEN 'ADMINISTRAÇÃO'
                   ELSE COALESCE(u_esc.cras, s.cras, 'Não informado')
               END AS unidade,
               s.status, s.data_entrega,
               COALESCE(u_ent.nome, s.tecnico_entrega) as tecnico
        FROM solicitacoes s
        LEFT JOIN usuarios u_esc ON s.tecnico = u_esc.usuario
        LEFT JOIN usuarios u_ent ON s.tecnico_entrega = u_ent.usuario
        {_and(w)}s.status IN ('Entregue', 'Ausente')
        ORDER BY s.id DESC LIMIT 20
    """, p_periodo)
    raw_entregas = cursor.fetchall()

    ultimas_entregas = []
    for row in raw_entregas:
        row = list(row)
        if row[1]:
            row[1] = formatar_cpf(descriptografar_cpf(row[1]))
        ultimas_entregas.append(tuple(row))

    # Recorrência: beneficiários com mais de 1 cesta entregue (sem filtro de período)
    cursor.execute("""
        SELECT cpf_hash, MAX(nome), MAX(cpf), COUNT(*), MAX(data_entrega)
        FROM solicitacoes
        WHERE status='Entregue' AND cpf_hash IS NOT NULL
        GROUP BY cpf_hash HAVING COUNT(*) > 1
        ORDER BY COUNT(*) DESC LIMIT 30
    """)
    raw_recorrencia = cursor.fetchall()
    conexao.close()

    recorrencia = []
    for row in raw_recorrencia:
        cpf_legivel = formatar_cpf(descriptografar_cpf(row[2])) if row[2] else 'N/A'
        recorrencia.append({
            'cpf': cpf_legivel, 'nome': row[1] or 'N/A',
            'total_recebido': row[3],
            'ultima_entrega': str(row[4]) if row[4] else 'N/A',
        })

    label_periodo = _label_periodo(periodo_inicio, periodo_fim)

    return render_template(
        "relatorio.html",
        lista_meses=lista_meses,
        periodo_inicio=periodo_inicio,
        periodo_fim=periodo_fim,
        label_periodo=label_periodo,
        total_solicitacoes=total_solicitacoes,
        total_entregues=total_entregues,
        total_ausentes=total_ausentes,
        total_pendentes=total_pendentes,
        total_excecoes=total_excecoes,
        por_cras=por_cras,
        por_tecnico=por_tecnico,
        ultimas_entregas=ultimas_entregas,
        recorrencia=recorrencia,
        datetime=datetime,
        current_user=current_user
    )

# =====================================================
# EXPORTAÇÃO PDF DO RELATÓRIO
# =====================================================

def _coletar_dados_relatorio(periodo_inicio, periodo_fim):
    """Coleta os totais e tabelas do relatório para um período. Retorna um dict."""
    cond_periodo, p_periodo = _periodo_sql(periodo_inicio, periodo_fim)
    where = f"WHERE {cond_periodo}" if cond_periodo else ""

    conexao = get_db()
    cursor = conexao.cursor()

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {where}", p_periodo)
    total = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {where + (' AND ' if where else 'WHERE ')}status='Entregue'", p_periodo)
    entregues = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {where + (' AND ' if where else 'WHERE ')}status='Ausente'", p_periodo)
    ausentes = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {where + (' AND ' if where else 'WHERE ')}status='Cadastrada'", p_periodo)
    pendentes = cursor.fetchone()[0]

    cursor.execute(f"SELECT COUNT(*) FROM solicitacoes {where + (' AND ' if where else 'WHERE ')}excecao_art64=TRUE", p_periodo)
    excecoes = cursor.fetchone()[0]

    cursor.execute(f"""
        SELECT
            CASE
                WHEN u.perfil = 'creas'        THEN 'CREAS'
                WHEN u.perfil = 'cras_volante'  THEN 'EQUIPE VOLANTE'
                WHEN u.perfil IN ('admin','gestor') THEN 'ADMINISTRAÇÃO'
                ELSE COALESCE(u.cras, s.cras, 'Não informado')
            END AS equipe,
            COUNT(*),
            SUM(CASE WHEN s.status='Entregue' THEN 1 ELSE 0 END),
            SUM(CASE WHEN s.status='Ausente'  THEN 1 ELSE 0 END)
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico = u.usuario
        {'WHERE ' + cond_periodo if cond_periodo else ''}
        GROUP BY equipe ORDER BY COUNT(*) DESC""", p_periodo)
    por_cras = cursor.fetchall()

    cursor.execute(f"""
        SELECT COALESCE(u.nome, s.tecnico), COUNT(*),
            SUM(CASE WHEN s.status='Entregue' THEN 1 ELSE 0 END),
            SUM(CASE WHEN s.status='Ausente' THEN 1 ELSE 0 END)
        FROM solicitacoes s LEFT JOIN usuarios u ON s.tecnico=u.usuario
        {'WHERE ' + cond_periodo if cond_periodo else ''}
        GROUP BY COALESCE(u.nome, s.tecnico) ORDER BY COUNT(*) DESC""", p_periodo)
    por_tecnico = cursor.fetchall()

    conexao.close()
    return {
        'total': total, 'entregues': entregues, 'ausentes': ausentes,
        'pendentes': pendentes, 'excecoes': excecoes,
        'por_cras': por_cras, 'por_tecnico': por_tecnico
    }

def _nome_mes_extenso(mes):
    nomes = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
             'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro']
    try:
        ano, num = mes.split('-')
        return f"{nomes[int(num)-1]}/{ano}"
    except:
        return mes

def _desenhar_cabecalho_relatorio(c, w, h, mes, subtitulo):
    logo_path = os.path.join(os.path.dirname(__file__), 'static', 'img', 'logo_prefeitura.png')
    logo_h = 1.8*cm
    if os.path.exists(logo_path):
        try:
            c.drawImage(ImageReader(logo_path), 2*cm, h - 2*cm - logo_h + 0.2*cm,
                        height=logo_h, width=logo_h,
                        preserveAspectRatio=True, mask='auto')
        except Exception:
            pass
    c.setFont("Helvetica-Bold", 14)
    c.setFillColorRGB(0.12, 0.24, 0.45)
    c.drawCentredString(w/2, h - 2*cm, "PREFEITURA MUNICIPAL DE JI-PARANÁ")
    c.setFont("Helvetica", 10)
    c.setFillColorRGB(0, 0, 0)
    c.drawCentredString(w/2, h - 2.6*cm, "Secretaria Municipal de Assistência Social e Família - SEMASF")
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(w/2, h - 3.4*cm, subtitulo)
    c.setFont("Helvetica", 10)
    c.drawCentredString(w/2, h - 3.9*cm, f"Mês de referência: {_nome_mes_extenso(mes)}")
    c.setLineWidth(1)
    c.setStrokeColorRGB(0.12, 0.24, 0.45)
    c.line(2*cm, h - 4.2*cm, w - 2*cm, h - 4.2*cm)

def _desenhar_totais(c, w, y, dados):
    cards = [
        ("Total de Solicitações", dados['total'], (0.12, 0.24, 0.45)),
        ("Entregues", dados['entregues'], (0.15, 0.55, 0.25)),
        ("Ausentes", dados['ausentes'], (0.70, 0.15, 0.15)),
        ("Pendentes", dados['pendentes'], (0.80, 0.55, 0.10)),
        ("Exceções Art. 64", dados['excecoes'], (0.55, 0.15, 0.55)),
    ]
    card_w = (w - 4*cm) / len(cards)
    for i, (label, valor, cor) in enumerate(cards):
        x = 2*cm + i * card_w
        c.setStrokeColorRGB(*cor)
        c.setLineWidth(1)
        c.rect(x + 0.1*cm, y - 1.6*cm, card_w - 0.2*cm, 1.5*cm, fill=0)
        c.setFillColorRGB(*cor)
        c.setFont("Helvetica-Bold", 20)
        c.drawCentredString(x + card_w/2, y - 0.85*cm, str(valor))
        c.setFillColorRGB(0.2, 0.2, 0.2)
        c.setFont("Helvetica", 7)
        c.drawCentredString(x + card_w/2, y - 1.35*cm, label)
    return y - 2.2*cm

def _rodape_relatorio(c, w, mes):
    agora = datetime.now(FUSO_RONDONIA)
    c.setFont("Helvetica", 7)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(2*cm, 1*cm, f"Relatório gerado em {agora.strftime('%d/%m/%Y às %H:%M:%S')} (horário de Rondônia)")
    c.drawRightString(w - 2*cm, 1*cm, "SEMASF Ji-Paraná - Sistema de Cestas Básicas")

# =====================================================
# EXPORTAÇÃO EXCEL
# =====================================================

@app.route("/relatorio/excel")
@login_required
def exportar_excel():
    if current_user.perfil not in ['admin', 'gestor', 'creas', 'cras_volante', 'cras']:
        return "Acesso negado", 403

    periodo_inicio = request.args.get('periodo_inicio', '').strip()
    periodo_fim    = request.args.get('periodo_fim', '').strip()
    cond_periodo, p_periodo = _periodo_sql(periodo_inicio, periodo_fim)
    where_excel = f"WHERE {cond_periodo}" if cond_periodo else ""

    conexao = get_db()
    cursor  = conexao.cursor()
    cursor.execute(f"""
        SELECT id, nome, cpf, bairro, cras, tecnico, status,
               data_solicitacao, data_entrega, tecnico_entrega,
               renda_per_capita, total_pessoas, excecao_art64, observacoes_entrega
        FROM solicitacoes {where_excel}
        ORDER BY id DESC
    """, p_periodo)
    linhas = cursor.fetchall()
    conexao.close()

    label = _label_periodo(periodo_inicio, periodo_fim)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = f"Cestas {label}"[:31]

    # Estilo cabeçalho
    azul_escuro = PatternFill("solid", fgColor="1B2F5E")
    fonte_branca = Font(bold=True, color="FFFFFF")
    cabecalhos = [
        "ID", "Nome", "CPF", "Bairro", "CRAS", "Técnico",
        "Status", "Data Solicitação", "Data Entrega", "Técnico Entrega",
        "Renda Per Capita", "Nº Pessoas", "Exceção Art.64", "Observações"
    ]
    for col, titulo in enumerate(cabecalhos, 1):
        cel = ws.cell(row=1, column=col, value=titulo)
        cel.font   = fonte_branca
        cel.fill   = azul_escuro
        cel.alignment = Alignment(horizontal="center")

    # Dados
    for row_idx, row in enumerate(linhas, 2):
        row = list(row)
        # Descriptografar CPF
        if row[2]:
            row[2] = formatar_cpf(descriptografar_cpf(row[2]))
        # Booleano legível
        row[12] = "Sim" if row[12] else "Não"
        for col_idx, valor in enumerate(row, 1):
            ws.cell(row=row_idx, column=col_idx, value=valor)

    # Ajustar largura das colunas
    for col in ws.columns:
        max_len = max((len(str(cel.value)) for cel in col if cel.value), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 40)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    nome_arquivo = f"cestas_semasf_{mes}.xlsx"
    return send_file(
        buf,
        as_attachment=True,
        download_name=nome_arquivo,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.route("/relatorio/pdf/<tipo>")
@login_required
def relatorio_pdf(tipo):
    if current_user.perfil not in ['admin', 'gestor', 'creas', 'cras_volante', 'cras']:
        return "Acesso negado", 403

    periodo_inicio = request.args.get('periodo_inicio', '').strip()
    periodo_fim    = request.args.get('periodo_fim', '').strip()
    dados = _coletar_dados_relatorio(periodo_inicio, periodo_fim)
    label = _label_periodo(periodo_inicio, periodo_fim)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    w, h = A4

    subtitulo = "RELATÓRIO RESUMIDO DE CESTAS BÁSICAS" if tipo == 'resumido' else "RELATÓRIO DE CESTAS BÁSICAS"
    _desenhar_cabecalho_relatorio(c, w, h, label, subtitulo)

    y = h - 5*cm
    c.setFont("Helvetica-Bold", 11)
    c.setFillColorRGB(0, 0.3, 0)
    c.drawString(2*cm, y, f"RESUMO — {label.upper()}")
    c.setFillColorRGB(0, 0, 0)
    y -= 0.3*cm
    y = _desenhar_totais(c, w, y, dados)

    # No PDF completo, adicionar as tabelas Por CRAS e Por Técnico
    if tipo == 'completo':
        y -= 0.5*cm
        # Tabela Por CRAS
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(0, 0.3, 0)
        c.drawString(2*cm, y, "DISTRIBUIÇÃO POR UNIDADE RESPONSÁVEL")
        c.setFillColorRGB(0, 0, 0)
        y -= 0.6*cm
        c.setFont("Helvetica-Bold", 9)
        c.drawString(2.2*cm, y, "Unidade")
        c.drawString(11*cm, y, "Total")
        c.drawString(13.5*cm, y, "Entregues")
        c.drawString(16.5*cm, y, "Ausentes")
        y -= 0.1*cm
        c.line(2*cm, y, w - 2*cm, y)
        y -= 0.4*cm
        def nova_pagina_relatorio():
            _rodape_relatorio(c, w, mes)
            c.showPage()
            _desenhar_cabecalho_relatorio(c, w, h, mes, subtitulo)
            return h - 5*cm

        c.setFont("Helvetica", 9)
        for cras, tot, ent, aus in dados['por_cras']:
            if y < 4*cm:
                y = nova_pagina_relatorio()
            c.drawString(2.2*cm, y, (cras or 'N/A')[:45])
            c.drawString(11*cm, y, str(tot))
            c.drawString(13.5*cm, y, str(ent or 0))
            c.drawString(16.5*cm, y, str(aus or 0))
            y -= 0.45*cm

        y -= 0.5*cm
        # Tabela Por Técnico
        if y < 6*cm:
            y = nova_pagina_relatorio()
        c.setFont("Helvetica-Bold", 11)
        c.setFillColorRGB(0, 0.3, 0)
        c.drawString(2*cm, y, "DISTRIBUIÇÃO POR TÉCNICO")
        c.setFillColorRGB(0, 0, 0)
        y -= 0.6*cm
        c.setFont("Helvetica-Bold", 9)
        c.drawString(2.2*cm, y, "Técnico")
        c.drawString(11*cm, y, "Total")
        c.drawString(13.5*cm, y, "Entregues")
        c.drawString(16.5*cm, y, "Ausentes")
        y -= 0.1*cm
        c.line(2*cm, y, w - 2*cm, y)
        y -= 0.4*cm
        c.setFont("Helvetica", 9)
        for nome, tot, ent, aus in dados['por_tecnico']:
            if y < 3*cm:
                y = nova_pagina_relatorio()
            c.drawString(2.2*cm, y, (nome or 'N/A')[:45])
            c.drawString(11*cm, y, str(tot))
            c.drawString(13.5*cm, y, str(ent or 0))
            c.drawString(16.5*cm, y, str(aus or 0))
            y -= 0.45*cm

    _rodape_relatorio(c, w, label)
    c.save()
    buffer.seek(0)

    slug = (periodo_inicio or 'tudo') + ('_a_' + periodo_fim if periodo_fim and periodo_fim != periodo_inicio else '')
    nome_arq = f"relatorio_{tipo}_{slug}.pdf"
    logger.info(f"Relatório PDF ({tipo}) período {label} gerado por {current_user.id}")
    return send_file(buffer, as_attachment=True, download_name=nome_arq, mimetype='application/pdf')

# =====================================================
# USUÁRIOS
# =====================================================

@app.route("/usuarios")
@login_required
def listar_usuarios():
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for("dashboard"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT id, usuario, nome, perfil, cras FROM usuarios ORDER BY id")
    usuarios = cursor.fetchall()
    conexao.close()
    lista_cras = get_lista_cras()
    return render_template("usuarios.html", usuarios=usuarios, current_user=current_user,
                           lista_cras=lista_cras)

@app.route("/usuario/novo", methods=["GET", "POST"])
@login_required
def novo_usuario():
    if request.method == "POST":
        senha = request.form.get("senha", "")
        perfil = request.form.get("perfil", "")
        # CRAS só faz sentido para técnico de CRAS; demais perfis ficam NULL
        cras = request.form.get("cras") if perfil == "cras" else None
        if len(senha) < 6:
            flash("Mínimo 6 caracteres!", "danger")
        else:
            hash_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conexao = get_db()
            cursor = conexao.cursor()
            try:
                cursor.execute(
                    "INSERT INTO usuarios (usuario, nome, senha, perfil, cras, primeiro_acesso) VALUES (%s,%s,%s,%s,%s,1)",
                    (request.form.get("usuario"), request.form.get("nome"), hash_senha, perfil, cras)
                )
                conexao.commit()
                flash("✅ Usuário criado!", 'success')
            except Exception as e:
                if 'unique' in str(e).lower() or 'duplicate' in str(e).lower():
                    flash("❌ Usuário já existe!", 'danger')
                else:
                    logger.error(f"Erro ao criar usuário: {e}")
                    flash("❌ Erro ao criar usuário. Tente novamente.", 'danger')
                conexao.rollback()
            finally:
                conexao.close()
    lista_cras = get_lista_cras()
    return render_template("novo_usuario.html", lista_cras=lista_cras)

@app.route("/usuario/excluir/<int:id>")
@login_required
def excluir_usuario(id):
    if current_user.perfil != 'admin':
        return "Acesso negado", 403
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conexao.commit()
    conexao.close()
    return redirect(url_for("listar_usuarios"))

@app.route("/usuario/editar/<int:id>", methods=["POST"])
@login_required
def editar_usuario(id):
    if current_user.perfil != 'admin':
        return "Acesso negado", 403
    nome = request.form.get("nome", "").strip()
    if not nome:
        flash("Nome não pode ser vazio.", "danger")
        return redirect(url_for("listar_usuarios"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET nome = %s WHERE id = %s", (nome, id))
    conexao.commit()
    conexao.close()
    logger.info(f"Nome do usuário ID={id} alterado por {current_user.id}")
    flash("✅ Nome atualizado!", "success")
    return redirect(url_for("listar_usuarios"))

@app.route("/usuario/editar_perfil/<int:id>", methods=["POST"])
@login_required
def editar_perfil_usuario(id):
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403
    perfil_novo = request.form.get("perfil", "")
    perfis_validos = ['cras', 'creas', 'cras_volante', 'gestor', 'admin']
    if perfil_novo not in perfis_validos:
        flash("Perfil inválido.", "danger")
        return redirect(url_for("listar_usuarios"))
    # Gestor não pode promover/rebaixar admins nem criar novos admins
    if current_user.perfil == 'gestor':
        conexao = get_db()
        cursor = conexao.cursor()
        cursor.execute("SELECT perfil FROM usuarios WHERE id = %s", (id,))
        row = cursor.fetchone()
        conexao.close()
        if row and row[0] == 'admin':
            flash("❌ Gestores não podem alterar perfil de administradores.", "danger")
            return redirect(url_for("listar_usuarios"))
        if perfil_novo == 'admin':
            flash("❌ Gestores não podem criar administradores.", "danger")
            return redirect(url_for("listar_usuarios"))
    conexao = get_db()
    cursor = conexao.cursor()
    # Se deixou de ser técnico CRAS, limpa o CRAS vinculado
    if perfil_novo != 'cras':
        cursor.execute("UPDATE usuarios SET perfil = %s, cras = NULL WHERE id = %s", (perfil_novo, id))
    else:
        cursor.execute("UPDATE usuarios SET perfil = %s WHERE id = %s", (perfil_novo, id))
    conexao.commit()
    conexao.close()
    logger.info(f"Perfil do usuário ID={id} alterado para {perfil_novo} por {current_user.id}")
    flash("✅ Perfil atualizado!", "success")
    return redirect(url_for("listar_usuarios"))

@app.route("/usuario/editar_cras/<int:id>", methods=["POST"])
@login_required
def editar_cras_usuario(id):
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403
    cras = request.form.get("cras", "").strip() or None
    # Gestor não pode alterar admins
    if current_user.perfil == 'gestor':
        conexao = get_db()
        cursor = conexao.cursor()
        cursor.execute("SELECT perfil FROM usuarios WHERE id = %s", (id,))
        row = cursor.fetchone()
        conexao.close()
        if row and row[0] == 'admin':
            flash("❌ Gestores não podem alterar dados de administradores.", "danger")
            return redirect(url_for("listar_usuarios"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET cras = %s WHERE id = %s", (cras, id))
    conexao.commit()
    conexao.close()
    logger.info(f"CRAS do usuário ID={id} alterado para {cras} por {current_user.id}")
    flash("✅ CRAS atualizado!", "success")
    return redirect(url_for("listar_usuarios"))

@app.route("/usuario/alterar_senha", methods=["POST"])
@login_required
def alterar_senha_simples():
    atual = request.form.get("senha_atual", "")
    nova = request.form.get("nova_senha", "")
    confirma = request.form.get("confirmar_senha", "")
    # Verificar senha atual
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT senha FROM usuarios WHERE usuario = %s", (current_user.id,))
    row = cursor.fetchone()
    conexao.close()
    if not row or not bcrypt.checkpw(atual.encode('utf-8'), row[0].encode('utf-8')):
        flash("❌ Senha atual incorreta!", "danger")
        return redirect(url_for("solicitacoes"))
    if len(nova) < 6:
        flash("Mínimo 6 caracteres!", "danger")
        return redirect(url_for("solicitacoes"))
    if not any(c.isupper() for c in nova):
        flash("A nova senha precisa ter pelo menos uma letra maiúscula!", "danger")
        return redirect(url_for("solicitacoes"))
    if not any(c.isdigit() for c in nova):
        flash("A nova senha precisa ter pelo menos um número!", "danger")
        return redirect(url_for("solicitacoes"))
    if nova != confirma:
        flash("❌ As senhas não conferem!", "danger")
        return redirect(url_for("solicitacoes"))
    hash_nova = bcrypt.hashpw(nova.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET senha = %s WHERE usuario = %s", (hash_nova, current_user.id))
    conexao.commit()
    conexao.close()
    logger.info(f"Senha alterada por {current_user.id}")
    flash("✅ Senha alterada com sucesso!", 'success')
    return redirect(url_for("solicitacoes"))

# =====================================================
# CONFIGURAÇÕES DO SISTEMA
# =====================================================

def get_salario_minimo():
    """Busca o salário mínimo vigente do banco de dados"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT valor FROM configuracoes WHERE chave = 'salario_minimo'")
        row = cursor.fetchone()
        conn.close()
        return float(row[0]) if row else 1621.00
    except:
        return 1621.00

@app.route("/api/configuracoes")
@login_required
def api_configuracoes():
    """Retorna configurações públicas para uso no frontend"""
    salario = get_salario_minimo()
    return jsonify({
        'salario_minimo': salario,
        'limite_renda_per_capita': round(salario / 4, 2)
    })

@app.route("/configuracoes", methods=["GET", "POST"])
@login_required
def configuracoes():
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for("dashboard"))
    erro = sucesso = None
    conn = get_db()
    cursor = conn.cursor()
    try:
        if request.method == "POST" and current_user.perfil == 'admin':
            novo_salario = request.form.get("salario_minimo", "").strip().replace(",", ".")
            try:
                valor = float(novo_salario)
                if valor <= 0:
                    raise ValueError
                cursor.execute("""
                    INSERT INTO configuracoes (chave, valor, descricao, atualizado_em)
                    VALUES ('salario_minimo', %s, 'Salário mínimo nacional vigente (R$)', %s)
                    ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor, atualizado_em = EXCLUDED.atualizado_em
                """, (str(valor), datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M:%S')))
                conn.commit()
                logger.info(f"Salário mínimo atualizado para R$ {valor} por {current_user.id}")
                sucesso = f"✅ Salário mínimo atualizado para R$ {valor:.2f}! Novo limite de renda per capita: R$ {valor/4:.2f}"
            except ValueError:
                erro = "❌ Valor inválido. Digite um número positivo (ex: 1518.00)"

        # Tudo numa só conexão
        cursor.execute("SELECT chave, valor, descricao, atualizado_em FROM configuracoes ORDER BY chave")
        configs = cursor.fetchall()

        cursor.execute("SELECT valor FROM configuracoes WHERE chave = 'salario_minimo'")
        row = cursor.fetchone()
        salario = float(row[0]) if row else 1621.00

        cursor.execute("SELECT id, cras, bairro FROM cras_bairros ORDER BY cras, bairro")
        bairros_por_cras = {}
        bairros_com_id   = {}
        lista_cras_set   = []
        for bid, bcras, bbairro in cursor.fetchall():
            bairros_por_cras.setdefault(bcras, []).append(bbairro)
            bairros_com_id.setdefault(bcras, []).append((bid, bbairro))
            if bcras not in lista_cras_set:
                lista_cras_set.append(bcras)
    finally:
        conn.close()

    return render_template("configuracoes.html",
        configs=configs,
        salario_minimo=salario,
        limite_rpc=round(salario / 4, 2),
        erro=erro,
        sucesso=sucesso,
        bairros_por_cras=bairros_por_cras,
        bairros_com_id=bairros_com_id,
        lista_cras=lista_cras_set,
        current_user=current_user
    )

@app.route("/configuracoes/bairro/adicionar", methods=["POST"])
@login_required
def bairro_adicionar():
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403
    bairro = request.form.get("bairro", "").strip().upper()
    cras   = request.form.get("cras", "").strip()
    if not bairro or not cras:
        flash("❌ Preencha o nome do bairro e selecione o CRAS.", "danger")
        return redirect(url_for("configuracoes"))
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO cras_bairros (cras, bairro) VALUES (%s, %s)", (cras, bairro))
        conn.commit()
        logger.info(f"Bairro '{bairro}' adicionado ao {cras} por {current_user.id}")
        flash(f"✅ Bairro '{bairro}' adicionado ao {cras}!", "success")
    except Exception:
        conn.rollback()
        flash(f"❌ Bairro '{bairro}' já existe no sistema.", "danger")
    finally:
        conn.close()
    return redirect(url_for("configuracoes"))

@app.route("/configuracoes/bairro/mover", methods=["POST"])
@login_required
def bairro_mover():
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403
    bairro_id = request.form.get("bairro_id", "")
    novo_cras  = request.form.get("novo_cras", "").strip()
    if not bairro_id or not novo_cras:
        flash("❌ Dados inválidos.", "danger")
        return redirect(url_for("configuracoes"))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE cras_bairros SET cras = %s WHERE id = %s", (novo_cras, bairro_id))
    conn.commit()
    conn.close()
    flash(f"✅ Bairro movido para {novo_cras}!", "success")
    return redirect(url_for("configuracoes"))

@app.route("/configuracoes/bairro/remover", methods=["POST"])
@login_required
def bairro_remover():
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403
    bairro_id = request.form.get("bairro_id", "")
    if not bairro_id:
        flash("❌ Bairro não identificado.", "danger")
        return redirect(url_for("configuracoes"))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cras_bairros WHERE id = %s", (bairro_id,))
    conn.commit()
    conn.close()
    flash("✅ Bairro removido.", "success")
    return redirect(url_for("configuracoes"))

# =====================================================
# BACKUP MANUAL (rota admin)
# =====================================================

@app.route("/api/backup")
@login_required
def backup():
    if current_user.perfil != 'admin':
        return "Acesso negado", 403
    try:
        enviar_backup_email()
        return "✅ Backup enviado por e-mail com sucesso!"
    except Exception as e:
        return f"❌ Erro ao enviar backup: {e}", 500

@app.route("/api/backup/automatico")
def backup_automatico():
    """Endpoint para cron externo (cron-job.org). Protegido por token secreto."""
    token_enviado = request.args.get('token', '')
    token_esperado = os.environ.get('BACKUP_TOKEN', '')
    if not token_esperado or token_enviado != token_esperado:
        return "Acesso negado", 403
    try:
        resultado = enviar_backup_email()
        if resultado is False:
            return "Erro: SENDGRID_API_KEY nao configurada", 500
        return "Backup enviado com sucesso", 200
    except Exception as e:
        logger.error(f"Erro no backup automatico via cron externo: {e}")
        return f"Erro: {e}", 500

# =====================================================
# ADMINISTRAÇÃO
# =====================================================

@app.route("/administracao")
@login_required
def administracao():
    if current_user.perfil not in ['admin', 'gestor']:
        return redirect(url_for('dashboard'))

    busca_id   = request.args.get('busca_id', '').strip()
    busca_nome = request.args.get('busca_nome', '').strip()

    solicitacao_encontrada = None
    resultados = []

    conn = get_db()
    cur  = conn.cursor()

    if busca_id:
        try:
            cur.execute("""
                SELECT s.id, s.nome, s.cpf, s.status, s.data_solicitacao,
                       COALESCE(u.nome, s.tecnico) as tecnico_nome, s.bairro, s.cras
                FROM solicitacoes s
                LEFT JOIN usuarios u ON s.tecnico = u.usuario
                WHERE s.id = %s
            """, (int(busca_id),))
            row = cur.fetchone()
            if row:
                row = list(row)
                if row[2]: row[2] = formatar_cpf(descriptografar_cpf(row[2]))
                solicitacao_encontrada = row
        except ValueError:
            pass
    elif busca_nome:
        cur.execute("""
            SELECT s.id, s.nome, s.cpf, s.status, s.data_solicitacao,
                   COALESCE(u.nome, s.tecnico) as tecnico_nome, s.bairro, s.cras
            FROM solicitacoes s
            LEFT JOIN usuarios u ON s.tecnico = u.usuario
            WHERE s.nome ILIKE %s AND s.status = 'Cadastrada'
            ORDER BY s.id DESC LIMIT 20
        """, (f"%{busca_nome}%",))
        for row in cur.fetchall():
            row = list(row)
            if row[2]: row[2] = formatar_cpf(descriptografar_cpf(row[2]))
            resultados.append(row)

    cur.execute("SELECT usuario, nome FROM usuarios ORDER BY nome")
    lista_usuarios = cur.fetchall()

    cur.execute("""
        SELECT s.id, s.nome, s.cancelado_em, COALESCE(u.nome, s.cancelado_por), s.motivo_cancelamento
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.cancelado_por = u.usuario
        WHERE s.status = 'Cancelada'
        ORDER BY s.id DESC LIMIT 15
    """)
    ultimos_cancelamentos = cur.fetchall()

    conn.close()

    return render_template('administracao.html',
        busca_id=busca_id,
        busca_nome=busca_nome,
        solicitacao_encontrada=solicitacao_encontrada,
        resultados=resultados,
        lista_usuarios=lista_usuarios,
        ultimos_cancelamentos=ultimos_cancelamentos,
        current_user=current_user
    )


@app.route("/cancelar_solicitacao", methods=["POST"])
@login_required
def cancelar_solicitacao():
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403

    try:
        id = int(request.form.get('solicitacao_id', 0))
    except ValueError:
        id = 0
    if not id:
        flash("ID de solicitação inválido.", "danger")
        return redirect(url_for('administracao'))

    motivo = request.form.get('motivo', '').strip()
    if not motivo:
        flash("Informe o motivo do cancelamento.", "danger")
        return redirect(url_for('administracao'))

    agora = datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M:%S')
    conn  = get_db()
    cur   = conn.cursor()

    cur.execute("SELECT status, tecnico, nome FROM solicitacoes WHERE id = %s", (id,))
    row = cur.fetchone()
    if not row:
        flash("Solicitação não encontrada.", "danger")
        conn.close()
        return redirect(url_for('administracao'))

    status_atual, tecnico, nome_beneficiario = row
    if status_atual != 'Cadastrada':
        flash(f"Só é possível cancelar solicitações com status 'Cadastrada'. Status atual: {status_atual}", "warning")
        conn.close()
        return redirect(url_for('administracao'))

    cur.execute("""
        UPDATE solicitacoes
        SET status='Cancelada', cancelado_por=%s, cancelado_em=%s, motivo_cancelamento=%s
        WHERE id=%s
    """, (current_user.id, agora, motivo, id))

    cur.execute("""
        INSERT INTO historico_edicoes (solicitacao_id, usuario, campo, valor_antes, valor_depois, data_hora)
        VALUES (%s, %s, 'status', 'Cadastrada', 'Cancelada', %s)
    """, (id, current_user.id, agora))

    # Notifica o técnico que criou a solicitação
    if tecnico:
        msg = (f"Sua solicitação #{id} ({nome_beneficiario}) foi cancelada por "
               f"{current_user.nome or current_user.id}. Motivo: {motivo}")
        cur.execute("""
            INSERT INTO notificacoes (destinatario, remetente, mensagem, tipo, criada_em, solicitacao_id)
            VALUES (%s, %s, %s, 'cancelamento', %s, %s)
        """, (tecnico, current_user.id, msg, agora, id))

    conn.commit()
    conn.close()

    logger.info(f"Solicitação #{id} cancelada por {current_user.id}. Motivo: {motivo}")
    flash(f"Solicitação #{id} cancelada com sucesso.", "success")
    return redirect(url_for('administracao'))


@app.route("/administracao/enviar_notificacao", methods=["POST"])
@login_required
def enviar_notificacao():
    if current_user.perfil not in ['admin', 'gestor']:
        return "Acesso negado", 403

    destinatarios = request.form.getlist('destinatarios')
    mensagem      = request.form.get('mensagem', '').strip()

    if not destinatarios or not mensagem:
        flash("Selecione pelo menos um destinatário e escreva a mensagem.", "danger")
        return redirect(url_for('administracao'))

    agora = datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M:%S')
    conn  = get_db()
    cur   = conn.cursor()

    # "todos" é um atalho para selecionar todos os usuários
    if 'todos' in destinatarios:
        cur.execute("SELECT usuario FROM usuarios")
        destinatarios = [r[0] for r in cur.fetchall()]

    for dest in destinatarios:
        cur.execute("""
            INSERT INTO notificacoes (destinatario, remetente, mensagem, tipo, criada_em)
            VALUES (%s, %s, %s, 'comunicado', %s)
        """, (dest, current_user.id, mensagem, agora))

    conn.commit()
    conn.close()
    flash(f"Notificação enviada para {len(destinatarios)} usuário(s).", "success")
    return redirect(url_for('administracao'))


# =====================================================
# NOTIFICAÇÕES
# =====================================================

@app.route("/notificacoes")
@login_required
def notificacoes():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT n.id, COALESCE(u.nome, n.remetente), n.mensagem, n.tipo, n.lida, n.criada_em, n.solicitacao_id
        FROM notificacoes n
        LEFT JOIN usuarios u ON n.remetente = u.usuario
        WHERE n.destinatario = %s
        ORDER BY n.id DESC LIMIT 50
    """, (current_user.id,))
    lista = cur.fetchall()
    conn.close()
    return render_template('notificacoes.html', lista_notificacoes=lista, current_user=current_user)


@app.route("/notificacoes/marcar_lida/<int:id>", methods=["POST"])
@login_required
def marcar_notificacao_lida(id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE notificacoes SET lida=TRUE WHERE id=%s AND destinatario=%s", (id, current_user.id))
    conn.commit()
    conn.close()
    return redirect(url_for('notificacoes'))


@app.route("/notificacoes/marcar_todas_lidas", methods=["POST"])
@login_required
def marcar_todas_lidas():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE notificacoes SET lida=TRUE WHERE destinatario=%s", (current_user.id,))
    conn.commit()
    conn.close()
    return redirect(url_for('notificacoes'))

# =====================================================
# EXECUÇÃO
# =====================================================

if __name__ == "__main__":
    app.run(debug=True)
