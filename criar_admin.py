import sqlite3
import bcrypt


def criar_admin():
    conn = sqlite3.connect('sistema.db')
    cursor = conn.cursor()

    # Verificar se a tabela existe
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
    if not cursor.fetchone():
        print("❌ Tabela 'usuarios' não encontrada!")
        conn.close()
        return

    # Verificar se já existe admin
    cursor.execute("SELECT * FROM usuarios WHERE usuario = 'admin'")
    if cursor.fetchone():
        print("✅ Admin já existe!")
        conn.close()
        return

    # Criar admin (senha: admin123)
    senha_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())

    cursor.execute('''
        INSERT INTO usuarios (usuario, nome, senha, perfil, primeiro_acesso)
        VALUES (?, ?, ?, ?, ?)
    ''', ('admin', 'Administrador', senha_hash.decode('utf-8'), 'admin', 1))

    conn.commit()
    conn.close()
    print("✅ Usuário admin criado com sucesso!")
    print("Usuário: admin")
    print("Senha: admin123")


if __name__ == "__main__":
    criar_admin()