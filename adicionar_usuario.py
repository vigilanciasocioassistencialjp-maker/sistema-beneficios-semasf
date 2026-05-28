import bcrypt
import sqlite3

def hash_senha(senha):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(senha.encode('utf-8'), salt).decode('utf-8')

def adicionar_usuario(usuario, senha, perfil, nome):
    conexao = sqlite3.connect("sistema.db")
    cursor = conexao.cursor()
    
    senha_hash = hash_senha(senha)
    
    try:
        cursor.execute("""
            INSERT INTO usuarios (usuario, nome, senha, perfil, primeiro_acesso)
            VALUES (?, ?, ?, ?, 1)
        """, (usuario, nome, senha_hash, perfil))
        conexao.commit()
        print(f"✅ Usuário {usuario} criado com sucesso!")
        print(f"⚠️ Ele precisará trocar a senha no primeiro acesso.")
    except sqlite3.IntegrityError:
        print(f"❌ Erro: Usuário {usuario} já existe!")
    finally:
        conexao.close()

if __name__ == "__main__":
    print("=== ADICIONAR NOVO USUÁRIO ===")
    usuario = input("Usuário (login): ")
    nome = input("Nome completo: ")
    perfil = input("Perfil (tecnico ou gestor): ")
    senha = input("Senha temporária: ")
    
    adicionar_usuario(usuario, senha, perfil, nome)