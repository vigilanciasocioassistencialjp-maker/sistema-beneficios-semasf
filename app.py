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
import hashlib
import smtplib
import gzip
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit

# =====================================================
# CONFIGURAÇÃO DO APP
# =====================================================

app = Flask(__name__)

# 🔒 Secret key
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

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

EMAIL_REMETENTE    = os.environ.get('EMAIL_REMETENTE', '')
EMAIL_SENHA_APP    = os.environ.get('EMAIL_SENHA_APP', '')
EMAIL_DESTINATARIO = os.environ.get('EMAIL_DESTINATARIO', '')

def gerar_backup_json():
    conn = get_db_connection()
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
    if not EMAIL_REMETENTE or not EMAIL_SENHA_APP or not EMAIL_DESTINATARIO:
        print("Backup ignorado: variaveis de e-mail nao configuradas no Render.")
        return
    try:
        agora = datetime.now(FUSO_RONDONIA)
        nome_arquivo = f"backup_semasf_{agora.strftime('%Y%m%d_%H%M%S')}.json.gz"

        dados = gerar_backup_json()
        conteudo = json.dumps(dados, ensure_ascii=False, indent=2, default=str).encode('utf-8')
        buffer_gz = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer_gz, mode='wb') as gz:
            gz.write(conteudo)
        buffer_gz.seek(0)
        tamanho_kb = round(buffer_gz.getbuffer().nbytes / 1024, 1)

        msg = MIMEMultipart()
        msg['From']    = f"Sistema SEMASF <{EMAIL_REMETENTE}>"
        msg['To']      = EMAIL_DESTINATARIO
        msg['Subject'] = f"[SEMASF] Backup automatico - {agora.strftime('%d/%m/%Y')}"

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
        msg.attach(MIMEText(corpo, 'plain', 'utf-8'))

        parte = MIMEBase('application', 'octet-stream')
        parte.set_payload(buffer_gz.read())
        encoders.encode_base64(parte)
        parte.add_header('Content-Disposition', f'attachment; filename="{nome_arquivo}"')
        msg.attach(parte)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as servidor:
            servidor.login(EMAIL_REMETENTE, EMAIL_SENHA_APP)
            servidor.sendmail(EMAIL_REMETENTE, EMAIL_DESTINATARIO, msg.as_string())

        print(f"Backup enviado: {nome_arquivo} ({tamanho_kb} KB)")
        logger.info(f"Backup automatico enviado: {nome_arquivo} ({tamanho_kb} KB, {dados['total_solicitacoes']} solicitacoes)")

    except Exception as e:
        print(f"Erro no backup automatico: {e}")
        logger.error(f"Erro no backup automatico: {e}")

scheduler = BackgroundScheduler(timezone='America/Porto_Velho')
scheduler.add_job(
    func=enviar_backup_email,
    trigger=CronTrigger(hour=0, minute=0),
    id='backup_diario',
    name='Backup diario por e-mail',
    replace_existing=True
)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())
print("Agendador de backup iniciado (todo dia a meia-noite, horario de Rondonia)")

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

def get_db():
    return get_db_connection()

# =====================================================
# LOGIN
# =====================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return carregar_usuario(user_id)

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
            login_user(user)
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
                dias = (datetime.now(FUSO_RONDONIA) - data_ultima.replace(tzinfo=None)).days
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
            INSERT INTO solicitacoes (tecnico, cpf, cpf_hash, nome, data_nascimento, telefone, email, endereco, numero, complemento, bairro, cep, referencia, cras, data_escuta, total_pessoas, composicao_familiar, renda_bruta, renda_per_capita, beneficios, vulnerabilidade, servicos_suas, parecer, status, data_solicitacao, excecao_art64)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (tecnico, cpf_cripto, cpf_hash, nome, data_nasc, telefone, email, endereco, numero, complemento, bairro, cep, referencia, cras, data_escuta, total_pessoas, composicao_json, renda_bruta, renda_per_capita, beneficios, vulnerabilidade_text, servicos_text, parecer, 'Cadastrada', data_solic, excecao_art64))
        conexao.commit()
        conexao.close()
        
        logger.info(f"Solicitação cadastrada: {nome}")
        flash('✅ Solicitação cadastrada!', 'success')
        return redirect(url_for("solicitacoes"))
    return render_template("index.html", sucesso=False)

# =====================================================
# LISTAR SOLICITAÇÕES (CPF DESCRIPTOGRAFADO)
# =====================================================

@app.route("/solicitacoes")
@app.route("/solicitacoes/<int:pagina>")
@login_required
def solicitacoes(pagina=1):
    registros_por_pagina = 20
    offset = (pagina - 1) * registros_por_pagina
    conexao = get_db()
    cursor = conexao.cursor()
    if current_user.perfil in ['admin', 'gestor', 'creas']:
        cursor.execute("SELECT COUNT(*) FROM solicitacoes")
        total_registros = cursor.fetchone()[0]
        cursor.execute("SELECT id, tecnico, nome, cpf, bairro, cras, data_solicitacao, status FROM solicitacoes ORDER BY id DESC LIMIT %s OFFSET %s", (registros_por_pagina, offset))
    else:
        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE cras = %s", (current_user.cras,))
        total_registros = cursor.fetchone()[0]
        cursor.execute("SELECT id, tecnico, nome, cpf, bairro, cras, data_solicitacao, status FROM solicitacoes WHERE cras = %s ORDER BY id DESC LIMIT %s OFFSET %s", (current_user.cras, registros_por_pagina, offset))
    total_paginas = (total_registros + registros_por_pagina - 1) // registros_por_pagina
    dados = cursor.fetchall()
    conexao.close()
    dados_formatados = []
    for row in dados:
        row = list(row)
        if row[3]:
            cpf_real = descriptografar_cpf(row[3])
            row[3] = formatar_cpf(cpf_real)
        dados_formatados.append(tuple(row))
    return render_template("solicitacoes.html", solicitacoes=dados_formatados, user_perfil=current_user.perfil, datetime=datetime, pagina_atual=pagina, total_paginas=total_paginas, total_registros=total_registros, current_user=current_user)

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
            u_entrega.nome as tecnico_entrega_nome
        FROM solicitacoes s 
        LEFT JOIN usuarios u_escuta ON s.tecnico = u_escuta.usuario 
        LEFT JOIN usuarios u_entrega ON s.tecnico_entrega = u_entrega.usuario 
        WHERE s.id = %s
    """, (id,))
    s = cursor.fetchone()
    conexao.close()
    if not s: return "Não encontrada", 404
    
    s = list(s)
    # Corrigir CPF
    if s[2]:
        cpf_real = descriptografar_cpf(s[2])
        s[2] = formatar_cpf(cpf_real)
    # Corrigir data de nascimento (índice 3)
    if s[3]:
        try:
            if '-' in str(s[3]):
                partes = str(s[3]).split('-')
                if len(partes) == 3:
                    s[3] = f"{partes[2]}/{partes[1]}/{partes[0]}"
        except:
            pass
    
    return render_template("ver_solicitacao.html", solicitacao=s, json=json, datetime=datetime, current_user=current_user)

# =====================================================
# PDF
# =====================================================

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
            s.excecao_art64             -- ÍNDICE 29
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
            canvas_obj.setFont("Helvetica-Bold", 14)
            canvas_obj.drawString(2*cm, y, "PREFEITURA MUNICIPAL DE JI-PARANÁ")
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica-Bold", 11)
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

            # ── 2. COMPOSIÇÃO FAMILIAR ──────────────────────────────
            y = check_space(8*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "2. COMPOSIÇÃO FAMILIAR")
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

            # ── 3. ENDEREÇO ─────────────────────────────────────────
            y = check_space(7*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "3. ENDEREÇO")
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

            # ── 4. INFORMAÇÕES SOCIOECONÔMICAS ──────────────────────
            y = check_space(6*cm, y)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.setFillColorRGB(0, 0.4, 0)
            canvas_obj.drawString(2*cm, y, "4. INFORMAÇÕES SOCIOECONÔMICAS")
            canvas_obj.setFillColorRGB(0, 0, 0)
            y -= 0.6*cm
            canvas_obj.setFont("Helvetica", 10)
            rb_val = s[RENDA_BRUTA] if s[RENDA_BRUTA] and float(s[RENDA_BRUTA]) > 0 else 0
            rpc_val = s[RENDA_PER_CAPITA] if s[RENDA_PER_CAPITA] and float(s[RENDA_PER_CAPITA]) > 0 else 0
            for label, valor in [
                ("Renda Bruta Familiar:", f"R$ {float(rb_val):.2f}" if rb_val > 0 else 'N/A'),
                ("Renda Per Capita:", f"R$ {float(rpc_val):.2f}" if rpc_val > 0 else 'N/A'),
                ("Benefícios:", (s[BENEFICIOS] if s[BENEFICIOS] else 'Nenhum')[:50]),
                ("Vulnerabilidades:", (s[VULNERABILIDADE] if s[VULNERABILIDADE] else 'Não informado')[:50]),
                ("Serviços SUAS:", (s[SERVICOS_SUAS] if s[SERVICOS_SUAS] else 'Não informado')[:50]),
            ]:
                canvas_obj.drawString(2.5*cm, y, f"{label} {valor}")
                y -= 0.45*cm
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
                canvas_obj.setFillColorRGB(0.7, 0.1, 0.1)
                canvas_obj.setFont("Helvetica-Bold", 9)
                canvas_obj.rect(2*cm, y - 0.5*cm, 17*cm, 0.75*cm, fill=0)
                canvas_obj.drawString(2.3*cm, y - 0.25*cm,
                    "⚠  CONCESSÃO EXCEPCIONAL — Art. 64 da Lei Municipal nº 3.603/2022: situação não contemplada nos critérios ordinários,")
                canvas_obj.drawString(2.3*cm, y - 0.55*cm,
                    "     autorizada mediante parecer técnico social e autorização do gestor da SEMASF.")
                canvas_obj.setFillColorRGB(0, 0, 0)
                y -= 1.1*cm
            parecer_txt = s[PARECER] if s[PARECER] else 'Sem parecer técnico registrado.'
            text_object = canvas_obj.beginText(2.5*cm, y)
            text_object.setFont("Helvetica", 9)
            max_w = w - 5*cm
            linha = ""
            for palavra in parecer_txt.split():
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

            y = check_space(7*cm, y)
            y -= 5 * 0.45*cm + 0.2*cm + 0.6*cm  # endereço

            y = check_space(6*cm, y)
            y -= 5 * 0.45*cm + 0.2*cm + 0.6*cm  # socioeconômico

            y = check_space(4*cm, y)
            y -= 3 * 0.45*cm + 0.2*cm + 0.6*cm  # atendimento

            y = check_space(5*cm, y)
            y -= 0.6*cm
            # simular quebra de página do parecer
            parecer_txt = s[PARECER] if s[PARECER] else 'Sem parecer técnico registrado.'
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
    if not status or not data:
        flash("Preencha todos os campos!", "danger")
        return redirect(url_for("solicitacoes"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE solicitacoes SET status=%s, data_entrega=%s, tecnico_entrega=%s WHERE id=%s", (status, data, current_user.id, id))
    conexao.commit()
    conexao.close()
    logger.info(f"Entrega: ID={id}, Status={status}")
    flash('✅ Registrado!' if status == 'Entregue' else '❌ Ausência registrada.', 'success')
    return redirect(url_for("solicitacoes"))

# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT COUNT(*) FROM solicitacoes")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status='Entregue'")
    entregues = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status='Ausente'")
    ausentes = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status='Cadastrada'")
    pendentes = cursor.fetchone()[0]
    conexao.close()
    return render_template("dashboard.html", total_solicitacoes=total, total_entregues=entregues, total_ausentes=ausentes, total_pendentes=pendentes, datetime=datetime, current_user=current_user)

# =====================================================
# RELATÓRIO
# =====================================================

@app.route("/relatorio")
@login_required
def relatorio():
    # Mês selecionado (padrão: mês atual)
    mes = request.args.get('mes', datetime.now(FUSO_RONDONIA).strftime('%Y-%m'))

    # Lista de meses disponíveis para o seletor (últimos 12 meses)
    nomes_meses = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
                   'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro']
    lista_meses = []
    agora = datetime.now(FUSO_RONDONIA)
    for i in range(12):
        data = agora - timedelta(days=30 * i)
        valor = data.strftime('%Y-%m')
        nome = f"{nomes_meses[data.month - 1]}/{data.year}"
        lista_meses.append({'valor': valor, 'nome': nome})

    # data_solicitacao salva como 'dd/mm/YYYY HH:MM:SS'
    # mes vem como 'YYYY-MM', precisamos converter para '%/MM/YYYY%'
    try:
        ano, num_mes = mes.split('-')
        filtro_like = f"%/{num_mes}/{ano}%"
        filtro_like_entrega = f"{ano}-{num_mes}%"  # data_entrega pode vir em outro formato
    except:
        filtro_like = f"%"
        filtro_like_entrega = f"%"

    conexao = get_db()
    cursor = conexao.cursor()

    # Totais do mês
    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes
        WHERE data_solicitacao LIKE %s OR data_entrega LIKE %s OR data_entrega LIKE %s
    """, (filtro_like, filtro_like, filtro_like_entrega))
    total_solicitacoes = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes
        WHERE status = 'Entregue' AND (data_solicitacao LIKE %s OR data_entrega LIKE %s OR data_entrega LIKE %s)
    """, (filtro_like, filtro_like, filtro_like_entrega))
    total_entregues = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes
        WHERE status = 'Ausente' AND (data_solicitacao LIKE %s OR data_entrega LIKE %s OR data_entrega LIKE %s)
    """, (filtro_like, filtro_like, filtro_like_entrega))
    total_ausentes = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes
        WHERE status = 'Cadastrada' AND data_solicitacao LIKE %s
    """, (filtro_like,))
    total_pendentes = cursor.fetchone()[0]

    # Exceções Art. 64 do período
    cursor.execute("""
        SELECT COUNT(*) FROM solicitacoes
        WHERE excecao_art64 = TRUE AND data_solicitacao LIKE %s
    """, (filtro_like,))
    total_excecoes = cursor.fetchone()[0]

    # Por CRAS
    cursor.execute("""
        SELECT cras,
               COUNT(*) as total,
               SUM(CASE WHEN status = 'Entregue' THEN 1 ELSE 0 END) as entregues,
               SUM(CASE WHEN status = 'Ausente' THEN 1 ELSE 0 END) as ausentes
        FROM solicitacoes
        WHERE data_solicitacao LIKE %s OR data_entrega LIKE %s OR data_entrega LIKE %s
        GROUP BY cras
        ORDER BY total DESC
    """, (filtro_like, filtro_like, filtro_like_entrega))
    por_cras = cursor.fetchall()

    # Por Técnico (quem fez a escuta)
    cursor.execute("""
        SELECT COALESCE(u.nome, s.tecnico) as nome_tecnico,
               COUNT(*) as total,
               SUM(CASE WHEN s.status = 'Entregue' THEN 1 ELSE 0 END) as entregues,
               SUM(CASE WHEN s.status = 'Ausente' THEN 1 ELSE 0 END) as ausentes
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico = u.usuario
        WHERE s.data_solicitacao LIKE %s OR s.data_entrega LIKE %s OR s.data_entrega LIKE %s
        GROUP BY COALESCE(u.nome, s.tecnico)
        ORDER BY total DESC
    """, (filtro_like, filtro_like, filtro_like_entrega))
    por_tecnico = cursor.fetchall()

    # Últimas entregas do mês (máx 20)
    cursor.execute("""
        SELECT s.nome,
               s.cpf,
               s.bairro,
               s.cras,
               s.status,
               s.data_entrega,
               COALESCE(u.nome, s.tecnico_entrega) as tecnico
        FROM solicitacoes s
        LEFT JOIN usuarios u ON s.tecnico_entrega = u.usuario
        WHERE s.status IN ('Entregue', 'Ausente')
          AND (s.data_solicitacao LIKE %s OR s.data_entrega LIKE %s OR s.data_entrega LIKE %s)
        ORDER BY s.id DESC
        LIMIT 20
    """, (filtro_like, filtro_like, filtro_like_entrega))
    raw_entregas = cursor.fetchall()

    # Descriptografar CPFs das últimas entregas
    ultimas_entregas = []
    for row in raw_entregas:
        row = list(row)
        if row[1]:
            row[1] = formatar_cpf(descriptografar_cpf(row[1]))
        ultimas_entregas.append(tuple(row))

    # Recorrência: beneficiários com mais de 1 cesta entregue
    cursor.execute("""
        SELECT cpf_hash,
               MAX(nome) as nome,
               MAX(cpf) as cpf_cripto,
               COUNT(*) as total_recebido,
               MAX(data_entrega) as ultima_entrega
        FROM solicitacoes
        WHERE status = 'Entregue' AND cpf_hash IS NOT NULL
        GROUP BY cpf_hash
        HAVING COUNT(*) > 1
        ORDER BY total_recebido DESC
        LIMIT 30
    """)
    raw_recorrencia = cursor.fetchall()

    conexao.close()

    recorrencia = []
    for row in raw_recorrencia:
        cpf_legivel = formatar_cpf(descriptografar_cpf(row[2])) if row[2] else 'N/A'
        recorrencia.append({
            'cpf': cpf_legivel,
            'nome': row[1] or 'N/A',
            'total_recebido': row[3],
            'ultima_entrega': str(row[4]) if row[4] else 'N/A',
        })

    return render_template(
        "relatorio.html",
        mes=mes,
        lista_meses=lista_meses,
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
# USUÁRIOS
# =====================================================

@app.route("/usuarios")
@login_required
def listar_usuarios():
    if current_user.perfil != 'admin': return redirect(url_for("dashboard"))
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT id, usuario, nome, perfil, cras FROM usuarios ORDER BY id")
    usuarios = cursor.fetchall()
    conexao.close()
    return render_template("usuarios.html", usuarios=usuarios, current_user=current_user)

@app.route("/usuario/novo", methods=["GET", "POST"])
@login_required
def novo_usuario():
    if request.method == "POST":
        senha = request.form.get("senha", "")
        perfil = request.form.get("perfil", "")
        # CRAS só faz sentido para técnico de CRAS; demais perfis ficam NULL
        cras = request.form.get("cras") if perfil == "tecnico" else None
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
            except:
                flash("❌ Usuário já existe!", 'danger')
            finally:
                conexao.close()
    return render_template("novo_usuario.html")

@app.route("/usuario/excluir/<int:id>")
@login_required
def excluir_usuario(id):
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conexao.commit()
    conexao.close()
    return redirect(url_for("listar_usuarios"))

@app.route("/usuario/alterar_senha", methods=["POST"])
@login_required
def alterar_senha_simples():
    nova = request.form.get("nova_senha", "")
    if len(nova) < 6:
        flash("Mínimo 6 caracteres!", "danger")
        return redirect(url_for("listar_usuarios"))
    hash_nova = bcrypt.hashpw(nova.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET senha = %s WHERE usuario = %s", (hash_nova, current_user.id))
    conexao.commit()
    conexao.close()
    flash("✅ Senha alterada!", 'success')
    return redirect(url_for("listar_usuarios"))

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
        return 1518.00

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
    if current_user.perfil != 'admin':
        return redirect(url_for("dashboard"))
    conn = get_db()
    cursor = conn.cursor()
    erro = sucesso = None
    if request.method == "POST":
        novo_salario = request.form.get("salario_minimo", "").strip().replace(",", ".")
        try:
            valor = float(novo_salario)
            if valor <= 0:
                raise ValueError
            from datetime import datetime
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
    cursor.execute("SELECT chave, valor, descricao, atualizado_em FROM configuracoes ORDER BY chave")
    configs = cursor.fetchall()
    conn.close()
    salario = get_salario_minimo()
    return render_template("configuracoes.html",
        configs=configs,
        salario_minimo=salario,
        limite_rpc=round(salario / 4, 2),
        erro=erro,
        sucesso=sucesso,
        current_user=current_user
    )

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

# =====================================================
# EXECUÇÃO
# =====================================================

if __name__ == "__main__":
    app.run(debug=True)
