# sync_google_oauth.py - Versão corrigida
import gspread
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
import sqlite3
import os
from datetime import datetime

SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive'
]


def get_db_connection():
    """Conecta ao banco de dados"""
    if os.environ.get('DATABASE_URL'):
        import psycopg2
        return psycopg2.connect(os.environ.get('DATABASE_URL'))
    else:
        return sqlite3.connect('sistema.db')


def autenticar_google():
    """Autentica usando OAuth - versão segura para iniciantes"""
    creds = None

    # IMPORTANTE: Criar pasta segura na sua HOME do computador
    # No Windows: C:\Users\SEU_USUARIO\.credentials_semasc\
    # No Mac/Linux: /home/seu_usuario/.credentials_semasc/

    import os
    from pathlib import Path

    # Detecta automaticamente qual sistema operacional você usa
    home = str(Path.home())
    pasta_segura = os.path.join(home, '.credentials_semasc')

    # Criar a pasta se não existir
    os.makedirs(pasta_segura, exist_ok=True)

    token_path = os.path.join(pasta_segura, 'token.pickle')
    creds_path = os.path.join(pasta_segura, 'credentials_oauth.json')

    print(f"🔐 Pasta segura: {pasta_segura}")

    # Carregar token se existir
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
        print("✅ Token encontrado!")

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            print("🔄 Token renovado")
        else:
            print("\n⚠️ Primeira vez executando ou token expirado!")
            print("🔑 Vamos abrir o navegador para você autorizar o acesso.")
            print("")

            # Verificar se o arquivo de credenciais existe
            if not os.path.exists(creds_path):
                print(f"❌ ERRO: Arquivo de credenciais não encontrado!")
                print(f"📁 Procurei em: {creds_path}")
                print("")
                print("📌 SOLUÇÃO:")
                print("1. Pegue o arquivo credentials_oauth.json que você baixou do Google Cloud")
                print("2. Copie ele para a pasta:")
                print(f"   {pasta_segura}")
                print("3. Execute este script novamente")
                return None

            flow = InstalledAppFlow.from_client_secrets_file(
                creds_path,
                SCOPES
            )

            # Tenta diferentes portas (resolve problemas comuns)
            try:
                creds = flow.run_local_server(port=8080)
            except:
                try:
                    creds = flow.run_local_server(port=5000)
                except:
                    creds = flow.run_local_server(port=0)

        # Salvar token na pasta segura
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)

        print("✅ Autenticado com sucesso!")
        print(f"📁 Token salvo em: {token_path}")

    client = gspread.authorize(creds)
    return client


def sincronizar_para_planilha(sheet_id):
    """Sincroniza dados para uma planilha existente"""

    print(f"\n🔄 Iniciando sincronização - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")

    try:
        # Autenticar
        client = autenticar_google()

        # Abrir planilha
        spreadsheet = client.open_by_key(sheet_id)
        sheet = spreadsheet.sheet1

        # Buscar dados do banco
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verificar se a tabela existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='solicitacoes'")
        if not cursor.fetchone():
            print("⚠️ Tabela 'solicitacoes' não encontrada no banco!")
            conn.close()
            return False

        cursor.execute("""
            SELECT id, nome, cpf, data_nascimento, telefone, bairro, cras,
                   data_solicitacao, status, data_entrega, renda_bruta, parecer
            FROM solicitacoes 
            ORDER BY id DESC
        """)

        dados = cursor.fetchall()
        conn.close()

        if not dados:
            print("⚠️ Nenhum dado encontrado no banco")
            return False

        print(f"📊 Encontrados {len(dados)} registros")

        # Preparar dados para planilha
        planilha_dados = []

        # Cabeçalhos
        planilha_dados.append([
            "ID", "Nome", "CPF", "Data Nascimento", "Telefone",
            "Bairro", "CRAS", "Data Solicitação", "Status",
            "Data Entrega", "Renda Bruta (R$)", "Parecer Técnico",
            "Data Sincronização"
        ])

        # Adicionar linhas
        for row in dados:
            planilha_dados.append([
                row[0],
                row[1] or "",
                row[2] or "",
                row[3] or "",
                row[4] or "",
                row[5] or "",
                row[6] or "",
                row[7] or "",
                row[8] or "",
                row[9] or "",
                f"{float(row[10]):.2f}" if row[10] else "0,00",
                (row[11] or "")[:200],  # Limitar parecer a 200 caracteres
                datetime.now().strftime('%d/%m/%Y %H:%M')
            ])

        # Limpar planilha (limpa todas as células)
        sheet.clear()

        # CORREÇÃO: Usar named parameters para evitar o warning
        sheet.update(range_name='A1', values=planilha_dados, value_input_option='USER_ENTERED')

        # CORREÇÃO: Removido columns_auto_update (não existe mais)
        # Formatar cabeçalho
        sheet.format('A1:M1', {
            'textFormat': {'bold': True},
            'backgroundColor': {'red': 0.2, 'green': 0.4, 'blue': 0.6}
        })

        print(f"✅ Sincronização concluída! {len(dados)} registros enviados")
        return True

    except Exception as e:
        print(f"❌ Erro na sincronização: {e}")
        import traceback
        traceback.print_exc()
        return False


def criar_planilha():
    """Cria uma nova planilha automaticamente"""
    try:
        client = autenticar_google()

        # Criar planilha
        spreadsheet = client.create("Sistema SEMASF - Cestas Básicas")

        # Compartilhar com seu email
        spreadsheet.share('aristeumac@gmail.com', perm_type='user', role='writer')

        print(f"\n✅ Planilha criada com sucesso!")
        print(f"📊 ID da planilha: {spreadsheet.id}")
        print(f"🔗 Link: https://docs.google.com/spreadsheets/d/{spreadsheet.id}")

        # Criar uma segunda aba para estatísticas
        try:
            stats_worksheet = spreadsheet.add_worksheet(title="Estatísticas", rows="100", cols="10")
            print(f"✅ Aba 'Estatísticas' criada")
        except:
            pass

        return spreadsheet.id
    except Exception as e:
        print(f"❌ Erro ao criar planilha: {e}")
        return None


def sincronizar_estatisticas(sheet_id):
    """Sincroniza estatísticas para uma aba separada"""
    try:
        client = autenticar_google()
        spreadsheet = client.open_by_key(sheet_id)

        # Tenta obter ou criar a aba de estatísticas
        try:
            stats_sheet = spreadsheet.worksheet("Estatísticas")
        except:
            stats_sheet = spreadsheet.add_worksheet(title="Estatísticas", rows="100", cols="10")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Coletar estatísticas
        cursor.execute("SELECT COUNT(*) FROM solicitacoes")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Entregue'")
        entregues = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Ausente'")
        ausentes = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Cadastrada'")
        pendentes = cursor.fetchone()[0]

        cursor.execute("""
            SELECT cras, COUNT(*) as total, 
                   SUM(CASE WHEN status = 'Entregue' THEN 1 ELSE 0 END) as entregues
            FROM solicitacoes 
            GROUP BY cras
        """)
        por_cras = cursor.fetchall()

        conn.close()

        # Preparar dados
        dados_stats = [
            ["📊 ESTATÍSTICAS GERAIS", ""],
            ["Data da atualização", datetime.now().strftime('%d/%m/%Y %H:%M:%S')],
            ["Total de Solicitações", total],
            ["Cestas Entregues", entregues],
            ["Famílias Ausentes", ausentes],
            ["Aguardando Entrega", pendentes],
            ["Taxa de Sucesso", f"{(entregues / total * 100):.1f}%" if total > 0 else "0%"],
            ["", ""],
            ["📋 SOLICITAÇÕES POR CRAS", "", "", ""],
            ["CRAS", "Total", "Entregues", "Taxa"]
        ]

        for cras in por_cras:
            taxa = (cras[2] / cras[1] * 100) if cras[1] > 0 else 0
            dados_stats.append([cras[0], cras[1], cras[2], f"{taxa:.1f}%"])

        # Limpar e atualizar
        stats_sheet.clear()
        stats_sheet.update(range_name='A1', values=dados_stats, value_input_option='USER_ENTERED')

        # Formatar cabeçalho
        stats_sheet.format('A1:D1', {
            'textFormat': {'bold': True},
            'backgroundColor': {'red': 0.2, 'green': 0.4, 'blue': 0.6}
        })

        print(f"✅ Estatísticas sincronizadas!")
        return True
    except Exception as e:
        print(f"❌ Erro ao sincronizar estatísticas: {e}")
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("Google Sheets Sync - Sistema SEMASF")
    print("=" * 50)

    # Usar o ID da planilha que você criou
    SHEET_ID = "1qExaH5dNH6UIVPNxUH-bwSSaJ-p6qt8M7otsNbde4gM"

    print("\n1. Sincronizar dados com planilha")
    print("2. Sincronizar estatísticas")
    print("3. Fazer tudo (dados + estatísticas)")
    print("4. Criar nova planilha")

    opcao = input("\nEscolha uma opção (1-4): ")

    if opcao == '1':
        sincronizar_para_planilha(SHEET_ID)
    elif opcao == '2':
        sincronizar_estatisticas(SHEET_ID)
    elif opcao == '3':
        print("\n--- Sincronizando dados ---")
        sincronizar_para_planilha(SHEET_ID)
        print("\n--- Sincronizando estatísticas ---")
        sincronizar_estatisticas(SHEET_ID)
    elif opcao == '4':
        criar_planilha()
    else:
        print("Opção inválida!")