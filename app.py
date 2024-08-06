from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import uuid

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///Escola.sqlite3"
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Prof(db.Model, UserMixin):
    __tablename__ = 'prof'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(86), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    turmas = db.relationship('Turma', backref='creator', lazy=True)

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(200), nullable=True)
    codigo = db.Column(db.String(36), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('prof.id'), nullable=False)
    atividades = db.relationship('Atividade', backref='turma', lazy=True)

class Atividade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(200))
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)

class TurmaAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    prof_id = db.Column(db.Integer, db.ForeignKey('prof.id'), nullable=False)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    turma = db.relationship('Turma', backref='accesses')
    prof = db.relationship('Prof', backref='accesses')

    __table_args__ = (db.UniqueConstraint('prof_id', 'turma_id', name='_prof_turma_uc'),)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return Prof.query.get(int(user_id))

@app.route('/', methods=['GET'])
def home():
    return render_template("home.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado.', 'success')
    return redirect(url_for('home'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    try:
        if request.method == 'POST':
            email = request.form['email']
            senha = request.form['senha']
            existing_user = Prof.query.filter_by(username=email).first()
            if existing_user:
                flash('O email já está em uso.', 'danger')
                return redirect(url_for('registro'))
            pro = Prof(username=email, password=senha)
            db.session.add(pro)
            db.session.commit()
            flash('Registro realizado com sucesso!', 'success')
            return redirect(url_for('login'))
        return render_template("registra.html")
    except Exception as e:
        flash(f'Houve um erro: {str(e)}', 'danger')
        return redirect(url_for('registro'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            email = request.form['email']
            senha = request.form['senha']
            pro = Prof.query.filter_by(username=email).first()
            if pro is None or not pro.verify_password(senha):
                flash('Credenciais inválidas. Por favor, tente novamente.', 'danger')
                return redirect(url_for('login'))

            login_user(pro)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        return render_template("login.html")
    except Exception as e:
        flash(f'Houve um erro: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/gerencia')
@login_required
def index():
    try:
        turmas = Turma.query.filter_by(creator_id=current_user.id).all()
        return render_template('index.html', turmas=turmas)
    except Exception as e:
        return str(e), 500
    

@app.route('/base')
@login_required
def base():
    prof = Prof.query.all()
    return render_template('base.html', prof=prof)


@app.route('/join_turma', methods=['POST'])
@login_required
def join_turma():
    try:
        codigo = request.form.get('codigo')
        turma = Turma.query.filter_by(codigo=codigo).first()
        if turma is None:
            flash('Código de turma inválido.', 'danger')
            return redirect(url_for('turmas'))

        existing_access = TurmaAccess.query.filter_by(prof_id=current_user.id, turma_id=turma.id).first()
        if existing_access:
            flash('Você já tem acesso a esta turma.', 'warning')
            return redirect(url_for('turmas'))

        access = TurmaAccess(prof_id=current_user.id, turma_id=turma.id)
        db.session.add(access)
        db.session.commit()
        flash('Você agora tem acesso à turma.', 'success')
        return redirect(url_for('turmas'))
    except Exception as e:
        return str(e), 500

@app.route('/turmas')
@login_required
def turmas():
    try:
        turmas = Turma.query.all()
        turmas_access = TurmaAccess.query.filter_by(prof_id=current_user.id).all()
        accessible_turmas = [access.turma for access in turmas_access]
        return render_template('turmas.html', turmas=turmas, accessible_turmas=accessible_turmas)
    except Exception as e:
        return f'Houve um erro: {str(e)}', 500


@app.route('/add_turma', methods=['POST'])
@login_required
def add_turma():
    try:
        nome = request.form.get('nome')
        descricao = request.form.get('descricao')
        codigo = str(uuid.uuid4())  # Gera um código único
        nova_turma = Turma(nome=nome, descricao=descricao, codigo=codigo, creator_id=current_user.id)
        db.session.add(nova_turma)
        db.session.commit()
        return redirect(url_for('turmas'))
    except Exception as e:
        return str(e), 500

@app.route('/edit_turma/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_turma(id):
    try:
        turma = Turma.query.get_or_404(id)
        if turma.creator_id != current_user.id:
            flash('Você não tem permissão para editar esta turma.', 'danger')
            return redirect(url_for('turmas'))
        if request.method == 'POST':
            turma.nome = request.form.get('nome')
            turma.descricao = request.form.get('descricao')
            db.session.commit()
            return redirect(url_for('turmas'))
        return render_template('edit_turma.html', turma=turma)
    except Exception as e:
        return str(e), 500

@app.route('/delete_turma/<int:id>')
@login_required
def delete_turma(id):
    try:
        turma = Turma.query.get_or_404(id)
        
        if turma.creator_id != current_user.id:
            flash('Você não tem permissão para excluir esta turma.', 'danger')
            return redirect(url_for('turmas'))
        if turma.atividades: # obiservaçao  
            flash('Você não pode excluir a turma com atividades.', 'danger')
            return redirect(url_for('turmas'))
        TurmaAccess.query.filter_by(turma_id=turma.id).delete()
        db.session.delete(turma)
        db.session.commit()
        return redirect(url_for('turmas'))
    except Exception as e:
        return str(e), 500

@app.route('/turma/<int:turma_id>')
@login_required
def turma(turma_id):
    try:
        turma = Turma.query.get_or_404(turma_id)
        return render_template('turma.html', turma=turma)
    except Exception as e:
        return str(e), 500

@app.route('/turma/<int:turma_id>/add_atividade', methods=['POST'])
@login_required
def add_atividade(turma_id):
    try:
        turma = Turma.query.get_or_404(turma_id)
        nome = request.form.get('nome')
        descricao = request.form.get('descricao')
        nova_atividade = Atividade(nome=nome, descricao=descricao, turma_id=turma_id)
        db.session.add(nova_atividade)
        db.session.commit()
        return redirect(url_for('turma', turma_id=turma_id))
    except Exception as e:
        return str(e), 500

@app.route('/edit_atividade/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_atividade(id):
    try:
        atividade = Atividade.query.get_or_404(id)
        if request.method == 'POST':
            atividade.nome = request.form.get('nome')
            atividade.descricao = request.form.get('descricao')
            db.session.commit()
            return redirect(url_for('turma', turma_id=atividade.turma_id))
        return render_template('edit_atividade.html', atividade=atividade)
    except Exception as e:
        return str(e), 500

@app.route('/delete_atividade/<int:id>')
@login_required
def delete_atividade(id):
    try:
        atividade = Atividade.query.get_or_404(id)
        turma_id = atividade.turma_id
        db.session.delete(atividade)
        db.session.commit()
        return redirect(url_for('turma', turma_id=turma_id))
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True)

