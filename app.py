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
# HTTPS
# =====================================================

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
        
        # Criptografar CPF e gerar hash
        cpf_cripto = criptografar_cpf(cpf_limpo)
        cpf_hash = hash_cpf(cpf_limpo)
        
        conexao = get_db()
        cursor = conexao.cursor()
        cursor.execute("""
            INSERT INTO solicitacoes (tecnico, cpf, cpf_hash, nome, data_nascimento, telefone, email, endereco, numero, complemento, bairro, cep, referencia, cras, data_escuta, total_pessoas, composicao_familiar, renda_bruta, renda_per_capita, beneficios, vulnerabilidade, servicos_suas, parecer, status, data_solicitacao)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (current_user.id, cpf_cripto, cpf_hash, request.form["nome"], request.form.get("data_nascimento",""), request.form.get("telefone",""), request.form.get("email",""), request.form.get("endereco",""), request.form.get("numero",""), request.form.get("complemento",""), request.form["bairro"], request.form.get("cep",""), request.form.get("referencia",""), request.form["cras"], request.form.get("data_escuta",""), 1, '[]', 0, 0, '', '', '', '', 'Cadastrada', datetime.now(FUSO_RONDONIA).strftime("%d/%m/%Y %H:%M:%S")))
        conexao.commit()
        conexao.close()
        
        logger.info(f"Solicitação cadastrada: {request.form['nome']}")
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
    if current_user.perfil in ['admin', 'gestor']:
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
    if s[2]:
        cpf_real = descriptografar_cpf(s[2])
        s[2] = formatar_cpf(cpf_real)
    
    return render_template("ver_solicitacao.html", solicitacao=s, json=json, datetime=datetime, current_user=current_user)

# =====================================================
# PDF
# =====================================================

@app.route("/gerar_pdf/<int:id>")
@login_required
def gerar_pdf_assinatura(id):
    conexao = get_db()
    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM solicitacoes WHERE id = %s", (id,))
    s = cursor.fetchone()
    conexao.close()
    if not s: return "Não encontrada", 404
    
    cpf_real = formatar_cpf(descriptografar_cpf(s[2])) if s[2] else 'Não informado'
    numero = f"CB-{datetime.now(FUSO_RONDONIA).strftime('%Y%m%d')}-{s[0]:04d}"
    
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2*cm, 28*cm, "PREFEITURA MUNICIPAL DE JI-PARANÁ")
    c.setFont("Helvetica", 10)
    c.drawString(2*cm, 26*cm, f"Nº: {numero} | Data: {datetime.now(FUSO_RONDONIA).strftime('%d/%m/%Y %H:%M')}")
    c.drawString(2*cm, 25*cm, f"Beneficiário: {s[3]}")
    c.drawString(2*cm, 24.5*cm, f"CPF: {cpf_real}")
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"termo_{numero}.pdf", mimetype='application/pdf')

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
    return render_template("relatorio.html", mes=datetime.now(FUSO_RONDONIA).strftime('%Y-%m'), datetime=datetime, current_user=current_user)

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
        if len(senha) < 6:
            flash("Mínimo 6 caracteres!", "danger")
        else:
            hash_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conexao = get_db()
            cursor = conexao.cursor()
            try:
                cursor.execute("INSERT INTO usuarios (usuario, nome, senha, perfil, cras, primeiro_acesso) VALUES (%s,%s,%s,%s,%s,1)", (request.form.get("usuario"), request.form.get("nome"), hash_senha, request.form.get("perfil"), request.form.get("cras")))
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
# BACKUP
# =====================================================

@app.route("/api/backup")
@login_required
def backup():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios")
    usuarios = [dict(zip([d[0] for d in cursor.description], row)) for row in cursor.fetchall()]
    cursor.execute("SELECT * FROM solicitacoes")
    solicitacoes = [dict(zip([d[0] for d in cursor.description], row)) for row in cursor.fetchall()]
    conn.close()
    backup = {'data': datetime.now(FUSO_RONDONIA).isoformat(), 'usuarios': usuarios, 'solicitacoes': solicitacoes}
    backup_dir = '/opt/render/.data/backups'
    os.makedirs(backup_dir, exist_ok=True)
    nome = f"backup_{datetime.now(FUSO_RONDONIA).strftime('%Y%m%d_%H%M%S')}.json"
    with open(os.path.join(backup_dir, nome), 'w') as f:
        json.dump(backup, f, ensure_ascii=False, indent=2)
    return f"✅ Backup: {nome}"

# =====================================================
# EXECUÇÃO
# =====================================================

if __name__ == "__main__":
    app.run(debug=True)
