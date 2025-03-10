from flask import Flask, jsonify, request, send_file
from main import app, con
import re
from flask_bcrypt import generate_password_hash, check_password_hash
from fpdf import FPDF
import jwt

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id):
    payload = {'id_usuario': user_id}
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    return token

def remover_bearer(token):
    # Verifica se o token começa com 'Bearer '
    if token.startswith('Bearer '):
        # Se o token começar com 'Bearer ', remove o prefixo 'Bearer ' do token
        # Utiliza a função len('Bearer ') para obter o comprimento do prefixo 'Bearer ' e corta o token a partir desse ponto
        return token[len('Bearer '):]
    else:
        # Se o token não começar com 'Bearer ', retorna o token original sem alterações
        return token

def validar_senha(senha):
    if len(senha) < 8:
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres"}), 400

    if not re.search(r"[!@#$%¨&*(),.?\":<>{}|]", senha):
        return jsonify({"error": "A senha deve conter pelo menos um símbolo especial"}), 400

    if not re.search(r"[A-Z]", senha):
        return jsonify({"error": "A senha deve conter pelo menos uma letra maiúscula"}), 400

    if len(re.findall(r"\d", senha)) < 2:
        return jsonify({"error": "A senha deve conter pelo menos dois números"}), 400

    return True

@app.route('/livro', methods = ['GET'])
def livro():
    cur = con.cursor()
    cur.execute("SELECT id_livro, titulo, autor, ano_publicacao FROM livro")
    livros = cur.fetchall()
    livro_dic = []
    for livro in livros:
        livro_dic.append({
            'id_livro': livro[0],
            'titulo': livro[1],
            'autor': livro[2],
            'ano_publicacao': livro[3]
        })

    return jsonify(mensagem='Lista de livros', livros=livro_dic)
@app.route('/livro', methods=['POST'])
def livro_post():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload.get('id_usuario')
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'mensagem': 'Dados inválidos ou ausentes'}), 400

    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    if not titulo or not autor or not ano_publicacao:
        return jsonify({'mensagem': 'Todos os campos (titulo, autor, ano_publicacao) são obrigatórios'}), 400

    cur = con.cursor()
    cur.execute("SELECT 1 FROM LIVRO WHERE TITULO = ?", (titulo,))

    if cur.fetchone():
        return jsonify({'mensagem': 'Livro já cadastrado'}), 409

    cur.execute(
        "INSERT INTO LIVRO (TITULO, AUTOR, ANO_PUBLICACAO) VALUES (?, ?, ?) RETURNING ID_livro", (titulo, autor, ano_publicacao)
    )
    livro_id = cursor.fetchone()[0]
    con.commit()
    cur.close()

    return jsonify({
        'mensagem': 'Livro cadastrado com sucesso',
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    }), 201


@app.route('/livro/<int:id>', methods=['PUT'])
def livro_put(id):
    cur = con.cursor()
    cur.execute("SELECT id_livro, titulo, autor, ano_publicacao FROM LIVRO WHERE id_livro =?", (id,))
    livro_data = cur.fetchone()

    if not livro_data:
        cur.close()
        return jsonify({"error": "Livro não foi encontrado"}), 404

    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cur.execute("update livro set titulo = ?, autor = ?, ano_publicacao = ? where id_livro = ?",
                (titulo, autor, ano_publicacao, id))

    con.commit()
    cur.close()

    return jsonify({
        'message': "Livro atualizado com sucesso!",
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })

@app.route('/livro/<int:id>', methods=['DELETE'])
def deletar_livro(id):
    cur = con.cursor()

    # Verificar se o livro existe
    cur.execute("SELECT 1 FROM livro WHERE ID_LIVRO = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    # Excluir o livro
    cur.execute("DELETE FROM livro WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Livro excluído com sucesso!",
        'id_livro': id
    })

@app.route('/usuarios', methods = ['GET'])
def usuarios():
    cur = con.cursor()
    cur.execute("SELECT id_usuario, nome, email, senha FROM usuarios")
    usuarios = cur.fetchall()
    usuarios_dic = []

    for usuario in usuarios:
        usuarios_dic.append({
            'id_usuario': usuario[0],
            'nome': usuario[1],
            'email': usuario[2],
            'senha': usuario[3]
        })

    return jsonify(mensagem='Lista de usuarios', usuarios=usuarios_dic)


@app.route('/usuarios', methods=['POST'])
def cadastro_usuario():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()

    cur.execute("SELECT 1 FROM usuarios WHERE NOME = ?", (nome,))

    if cur.fetchone():
        return jsonify({"message": "Usuário já cadastrado!"}), 400

    senha = generate_password_hash(senha).decode('utf-8')

    cur.execute("INSERT INTO USUARIOS(NOME, EMAIL, SENHA) VALUES(?, ?, ?)", (nome, email, senha))

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário cadastrado!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })

@app.route('/usuarios/<int:id>', methods=['PUT'])
def atualizar_usuario(id):
    cur = con.cursor()
    cur.execute("SELECT id_usuario, nome, email, senha FROM USUARIOS WHERE id_usuario =?", (id,))
    usuarios_data = cur.fetchone()

    if not  usuarios_data:
        cur.close()
        return jsonify({"error": "Usuário não foi encontrado"}), 404

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    cur.execute("update usuarios set nome = ?, email = ?, senha = ? where id_usuario = ?",
                (nome, email, senha, id))

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuuário atualizado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })



@app.route('/usuarios/<int:id>', methods=['DELETE'])
def deletar_usuarios(id):
    cur = con.cursor()

    # Verificar se o livro existe
    cur.execute("SELECT 1 FROM usuarios WHERE ID_usuario = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Usuário não encontrado"}), 404

    # Excluir o livro
    cur.execute("DELETE FROM usuarios WHERE ID_USUARIO = ?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário excluído com sucesso!",
        'id_usuario': id
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({"error": "Todos os campos (email, senha) são obrigatórios."}), 400

    cur = con.cursor()
    cur.execute("SELECT SENHA, ID_USUARIO FROM USUARIOS WHERE EMAIL = ?", (email,))
    usuario = cur.fetchone()
    cur.close()

    if not usuario:
        return jsonify({"error": "Usuário ou senha inválidos."}), 401

    senha_armazenada = usuario[0]
    id_usuario = usuario[1]

    if check_password_hash(senha_armazenada, senha):
        token = generate_token(id_usuario)
        return jsonify({'mesagem': 'Login com sucesso!', 'token': token}), 200

    if check_password_hash(senha_armazenada, senha):
        return jsonify({"message": "Login realizado com sucesso!"})

    return jsonify({"error": "Senha incorreta."})

@app.route('/livros/relatorio', methods=['GET'])
def criar_pdf():
    cursor = con.cursor()
    cursor.execute("SELECT id_livro, titulo, autor, ano_publicacao FROM livro ")
    livros = cursor.fetchall()
    cursor.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", style='B', size=16)
    pdf.cell(200, 10, "Relatorio de Livros", ln=True, align='C')

    pdf.ln(5)  # Espaço entre o título e a linha
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())  # Linha abaixo do título
    pdf.ln(5)  # Espaço após a linha

    pdf.set_font("Arial", size=12)
    for livro in livros:
        pdf.cell(200, 10, f"ID: {livro[0]} - {livro[1]} - {livro[2]} - {livro[3]}", ln=True)
    contador_livros = len(livros)

    pdf.ln(10)  # Espaço antes do contador
    pdf.set_font("Arial", style='B', size=12)
    pdf.cell(200, 10, f"Total de livros cadastrados: {contador_livros}", ln=True, align='C')
    pdf_path = "relatorio_livros.pdf"
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')