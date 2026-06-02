from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from usuarios import Usuario, carregar_usuario
from banco import criar_banco, get_db_connection
import os
import json
from datetime import datetime
import bcrypt
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
import io
import qrcode

# =====================================================
# CONFIGURAÇÃO DO APP
# =====================================================

app = Flask(__name__)
app.secret_key = "sistema_cestas"

# 🔧 CRIAR BANCO DE DADOS SE NÃO EXISTIR
criar_banco()

# =====================================================
# CRIAR USUÁRIO ADMIN AUTOMATICAMENTE (Se não houver usuários)
# =====================================================

def criar_admin_automatico():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verificar se existe algum usuário na tabela
        cursor.execute("SELECT COUNT(*) FROM usuarios")
        
        resultado = cursor.fetchone()
        count = resultado[0] if resultado else 0

        if count == 0:
            # Criar admin com senha 'admin123'
            senha_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            
            sql = """
                INSERT INTO usuarios (usuario, nome, senha, perfil, primeiro_acesso)
                VALUES (%s, %s, %s, %s, %s)
            """
            
            cursor.execute(sql, ('admin', 'Administrador', senha_hash.decode('utf-8'), 'admin', 1))
            conn.commit()
                
            print("✅ Usuário admin criado automaticamente no banco!")
            print("Usuário: admin | Senha: admin123")
        else:
            print(f"✅ Banco já possui {count} usuário(s)")

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"⚠️ Erro ao criar admin automático: {e}")

# Executa a função uma única vez após a criação das tabelas
criar_admin_automatico()

# =====================================================
# FUNÇÃO DE CONEXÃO COM BANCO 
# =====================================================

def get_db():
    """Retorna conexão com o banco - usa a função do banco.py"""
    return get_db_connection()

# =====================================================
# LOGIN MANAGER
# =====================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return carregar_usuario(user_id)

# =====================================================
# FILTROS PERSONALIZADOS
# =====================================================

@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value) if value else []
    except:
        return []

@app.template_filter('formatar_data')
def formatar_data(data):
    """Converte data ISO (YYYY-MM-DD) para formato brasileiro (DD/MM/YYYY)"""
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
    
    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = request.form["senha"]

        conexao = get_db()
        cursor = conexao.cursor()

        cursor.execute("""
            SELECT usuario, senha, perfil, primeiro_acesso, cras, nome
            FROM usuarios
            WHERE usuario = %s
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
                    
                    if primeiro_acesso == 1:
                        return redirect(url_for("trocar_senha", primeiro_acesso=True))
                    
                    if perfil_banco in ['admin', 'gestor']:
                        return redirect(url_for("dashboard"))
                    else:
                        return redirect(url_for("solicitacoes"))
                else:
                    erro = "❌ Senha incorreta! Tente novamente."
            except Exception as e:
                print(f"Erro ao verificar senha: {e}")
                erro = "❌ Erro na autenticação. Contate o administrador."
        else:
            erro = "❌ Usuário não encontrado! Verifique seu login."
    
    return render_template("login.html", erro=erro)

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
        elif len(nova_senha) < 4:
            erro = "A nova senha deve ter no mínimo 4 caracteres!"
        elif nova_senha != confirmar_senha:
            erro = "A confirmação da senha não corresponde!"
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
                
                sucesso = "✅ Senha alterada com sucesso!"
                
                if primeiro_acesso:
                    if current_user.perfil in ['admin', 'gestor']:
                        return redirect(url_for("dashboard"))
                    else:
                        return redirect(url_for("solicitacoes"))
    
    return render_template("trocar_senha.html", 
                         erro=erro, 
                         sucesso=sucesso, 
                         primeiro_acesso=primeiro_acesso)

# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# =====================================================
# PÁGINA PRINCIPAL (Nova Solicitação)
# =====================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def inicio():
    if request.method == "POST":
        bairro = request.form["bairro"]
        cras_solicitacao = request.form["cras"]
        
        # Admin e Gestor podem cadastrar para qualquer CRAS
        if current_user.perfil not in ['admin', 'gestor']:
            if current_user.cras != cras_solicitacao:
                return "Você não tem permissão para cadastrar solicitações para este CRAS!", 403
        
        cpf = request.form["cpf"]
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
        data_solicitacao = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
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
            tecnico, cpf, nome, data_nascimento, telefone, email,
            endereco, numero, complemento, bairro, cep, referencia,
            cras, data_escuta, total_pessoas, composicao_json,
            renda_bruta, renda_per_capita, beneficios, vulnerabilidade_text,
            servicos_suas_text, parecer, 'Cadastrada', data_solicitacao
        ))
        
        conexao.commit()
        conexao.close()
        
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
    
    # Admin e Gestor veem todas as solicitações
    if current_user.perfil in ['admin', 'gestor']:
        cursor.execute("SELECT COUNT(*) FROM solicitacoes")
        total_registros = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT 
                id, tecnico, nome, cpf, bairro, cras, data_solicitacao, status
            FROM solicitacoes
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, (registros_por_pagina, offset))
    else:
        # Técnico vê apenas solicitações do seu CRAS
        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE cras = %s", (current_user.cras,))
        total_registros = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT 
                id, tecnico, nome, cpf, bairro, cras, data_solicitacao, status
            FROM solicitacoes
            WHERE cras = %s
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, (current_user.cras, registros_por_pagina, offset))
    
    total_paginas = (total_registros + registros_por_pagina - 1) // registros_por_pagina
    dados = cursor.fetchall()
    conexao.close()
    
    return render_template(
        "solicitacoes.html",
        solicitacoes=dados,
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
    
    return render_template("ver_solicitacao.html", 
                         solicitacao=solicitacao, 
                         json=json, 
                         datetime=datetime,
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
    
    numero_controle = f"CB-{datetime.now().strftime('%Y%m%d')}-{solicitacao[0]:04d}"
    
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
    c.drawString(2*cm, y_position - 1.8*cm, f"Data de Emissão: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    
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
    c.drawString(2*cm, y_position, f"Data Nascimento: {solicitacao[4] if solicitacao[4] else 'Não informado'}")
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
    c.drawString(2*cm, 1*cm, f"Documento gerado em {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}")
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
    data_entrega = request.form.get("data_entrega
