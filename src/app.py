from flask import Flask, redirect, render_template, request, url_for, flash, session
from config import *
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

con_bd = EstablecerConexion()
app.secret_key = 'admin'
#----------------------------------------CREACION DE TABLAS EN POSTGRES-------------------------

#---------------TABLA USUARIOS--------------------------------------
def createTableUsers():
    cursor = con_bd.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS users(
                       idUser serial NOT NULL,
                       name character varying(50),
                       email character varying(50),
                       usuario character varying(50),
                       password character varying,
                       role character varying,
                       skills character varying,
                       CONSTRAINT pk_users_id PRIMARY KEY (idUser));
                   """)
    con_bd.commit()
#--------------TABLA PROYECTOS----------------------------------------------
def createTableProjects():
    cursor = con_bd.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS projects(
                       idProject serial NOT NULL,
                       name character varying(50),
                       description text,
                       CONSTRAINT pk_project_id PRIMARY KEY (idProject));
                   """)
    con_bd.commit()

#--------------TABLA MIEMBROS DEL PROYECTO------------------------------------

def createTableMembersProjects():
    cursor = con_bd.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS members_project(
                       idMembers serial NOT NULL,
                       project_id INTEGER REFERENCES projects(idProject),
                       user_id INTEGER REFERENCES users(idUser),
                       CONSTRAINT pk_membersProject_id PRIMARY KEY (idMembers));
                   """)
    con_bd.commit()

#--------------TABLA EQUIPOS---------------------------------------
def createTableTeams():
    cursor = con_bd.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS teams(
                       idTeam serial NOT NULL,
                       name character varying(50),
                       CONSTRAINT pk_team_id PRIMARY KEY (idTeam));
                   """)
    con_bd.commit()
    
#--------------TABLA USUARIOS POR EQUIPO---------------------------------

def createTableMembersTeam():
    cursor = con_bd.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS members_team(
                       idMembers serial NOT NULL,
                       team_id INTEGER REFERENCES teams(idTeam),
                       user_id INTEGER REFERENCES users(idUser),
                       CONSTRAINT pk_membersTeam_id PRIMARY KEY (idMembers));
                   """)
    con_bd.commit()
#----------------TABLA DE TAREAS------------------------------------------------------------
def createTableTasks():
    cursor = con_bd.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS tasks(
                       idTask serial NOT NULL,
                       name character varying(50),
                       description text,
                       initDate date,
                       finishDate date,
                       user_id INTEGER REFERENCES users(idUser),
                       CONSTRAINT pk_task_id PRIMARY KEY (idTask));
                   """)
    con_bd.commit()
    
#-------------TABLA DE CHATS----------------------------------------------------
def createTableChats():
    cursor=con_bd.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS chats(
                        idChat SERIAL NOT NULL,
                        sender_id INTEGER REFERENCES users(idUser),
                        receiver_id INTEGER REFERENCES users(idUser),
                        message_text TEXT,
                        timestamp TIMESTAMP DEFAULT now(),
                        CONSTRAINT pk_chats_id PRIMARY KEY (idChat));
                        """)
#Inicio 
@app.route('/')  # decorator to register a route with the app
def index():
    
    cursor = con_bd.cursor()
    sql = "SELECT*FROM users"
    cursor.execute(sql)
    UsuariosRegistrados = cursor.fetchall()
    return render_template('index.html', usuarios = UsuariosRegistrados)

#login
@app.route('/login_session', methods=['GET', 'POST'])
def login_session():
    cursor = con_bd.cursor()
    sql = "SELECT*FROM users"
    cursor.execute(sql)
    UsersRegister = cursor.fetchall()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in UsersRegister:
            if(user[3]==username) and check_password_hash(user[4],password):
                session['user_id'] = user[0]
                
                return redirect(url_for('start'))
            else:
                flash('Credenciales incorrectas. Intentalo de nuevo', 'danger')
    return render_template('index.html')

#autenticación de usuario para paginas protegidas
def login_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if 'user_id' not in session:
            flash("No hay una sesión activa.")
            return redirect(url_for('login_session'))
        return f(*args, **kwargs)
    return decorated_function

#pagina de inicio para los usuarios
@app.route('/start')
@login_required
def start():
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    sql = """SELECT * FROM users where idUser=%s"""
    cursor.execute(sql,(user_id,))
    User = cursor.fetchone()
    return render_template('start.html', user=User) 

#----------------------------------VISTA DE INICIO PARA EQUIPOS-----------------------------------------------
@app.route('/start/teams')
@login_required
def teams():
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    sql = """SELECT team_id FROM members_team where user_id=%s"""
    cursor.execute(sql,(user_id,))
    team_ids = cursor.fetchall()
    dataTeam = {
        'role':'Administrativo',
        'user':[],
    }
    # Consulta los detalles del equipo a partir de los ID del proyecto obtenidos
    team_details = []
    user_details = ''
    for team_id in team_ids:
        team_id = team_id[0]  # Extrae el ID del proyecto de la tupla
        sql = """SELECT idTeam, name FROM teams WHERE idTeam=%s"""
        cursor.execute(sql, (team_id,))
        team_detail = cursor.fetchone()
        if team_detail:
            team_details.append(team_detail)
        sql= """SELECT role FROM users WHERE idUser=%s"""
        cursor.execute(sql, (user_id,))
        user_detail = cursor.fetchone()
        if user_detail:
            user_details = user_detail[0]
        sql = """SELECT users.idUser, users.name, users.email, users.role, users.skills
                 FROM members_team
                 INNER JOIN users ON members_team.user_id = users.idUser
                 WHERE members_team.team_id = %s"""
        cursor.execute(sql, (team_id,))
        user_detail = cursor.fetchall()
        

        dataTeam ={
            'team':team_details,
            'role': user_details,
            'user': user_detail,
        }
    
    return render_template('teams.html', dataTeams=dataTeam)

#---------------------------------VISTA DE INICIO PARA PROYECTOS---------------------------------------
@app.route('/start/projects')
@login_required
def projects():
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    sql = """SELECT project_id FROM members_project where user_id=%s"""
    cursor.execute(sql,(user_id,))
    project_ids = cursor.fetchall()
    dataProject = {
        'role':'Administrativo',
        'user':[],
    }
    # Consulta los detalles de los proyectos a partir de los ID de proyecto obtenidos
    project_details = []
    for project_id in project_ids:
        project_id = project_id[0]  # Extrae el ID del proyecto de la tupla
        sql = """SELECT idProject, name, description FROM projects WHERE idProject=%s"""
        cursor.execute(sql, (project_id,))
        project_detail = cursor.fetchone()
        if project_detail:
            project_details.append(project_detail)
        #nivel de acceso segun el rol del usuario
        sql= """SELECT role FROM users WHERE idUser=%s"""
        cursor.execute(sql, (user_id,))
        user_detail = cursor.fetchone()
        if user_detail:
            user_details = user_detail[0]
        sql = """SELECT users.name, users.email, users.role, users.skills
                 FROM members_project
                 INNER JOIN users ON members_project.user_id = users.idUser
                 WHERE members_project.project_id = %s"""
        cursor.execute(sql, (project_id,))
        user_detail = cursor.fetchall()

        dataProject ={
            'projects':project_details,
            'role': user_details,
            'user': user_detail,
        }
    
    return render_template('projects.html', dataProjects=dataProject)


#-----------------------------pagina de inicio para las tareas-----------------------------------
@app.route('/tasks')
@login_required
def tasks():
    task_details = []
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    dataTasks = {
        'role':'Administrativo'
    }
    sql = """SELECT idTask, name, description, initDate, finishDate FROM tasks WHERE user_id=%s"""
    cursor.execute(sql, (user_id,))
    tasks_detail = cursor.fetchone()
    if tasks_detail:
        task_details.append(tasks_detail)
    #nivel de acceso segun el rol del usuario
    sql = """SELECT role FROM users WHERE idUser=%s"""
    cursor.execute(sql, (user_id,))
    user_detail = cursor.fetchone()
    if user_detail:
        user_details = user_detail[0]
    dataTasks ={
        'tasks':task_details,
        'role': user_details
    }
    return render_template('tasks.html',dataTask=dataTasks)

#----------------------------------pagina para cerrar sesion-----------------------------------------------------
@app.route('/logout')
@login_required
def logout():
    # Elimina la variable de sesión 'user_id' para cerrar la sesión
    session.pop('user_id', None)
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login_session')) 
 

#---------------------------------------INICIO CHAT----------------------------------------------------------------------

@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def chat(receiver_id):
    cursor = con_bd.cursor()
    user_id = session['user_id']
    if receiver_id:
        session['receiver_id'] = receiver_id
    # Consulta la información del usuario actual
    sql_get_user = "SELECT idUser, name FROM users WHERE idUser = %s"
    cursor.execute(sql_get_user, (user_id,))
    user_data = cursor.fetchone()
    
    # Consulta la información del miembro del equipo con receiver_id
    sql_get_receiver = "SELECT idUser, name FROM users WHERE idUser = %s"
    cursor.execute(sql_get_receiver, (receiver_id,))
    receiver_data = cursor.fetchone()
    
    if user_data and receiver_data:
        user_id = user_data[0]
        receiver_id = receiver_data[0]
        
        # Consulta el historial de chat entre el usuario actual y el miembro del equipo
        sql_get_chat_history = """
            SELECT c.idChat, c.sender_id, c.receiver_id, c.message_text, c.timestamp, u.name AS sender_name
            FROM chats c
            INNER JOIN users u ON c.sender_id = u.idUser
            WHERE (c.sender_id = %s AND c.receiver_id = %s) OR (c.sender_id = %s AND c.receiver_id = %s)
            ORDER BY c.timestamp ASC
        """
        cursor.execute(sql_get_chat_history, (user_id, receiver_id, receiver_id, user_id))
        chat_history = cursor.fetchall()

        
        # Marca los mensajes como leídos (opcional)
        # Puedes agregar lógica para marcar mensajes como leídos en tu aplicación si lo deseas.
        
        return render_template('chat_history.html', user_data=user_data, receiver_data=receiver_data, chat_history=chat_history)
    else:
        flash("Usuario o miembro del equipo no encontrado.", "danger")
        return redirect(url_for('teams'))

    

#---------------------------------------GUARDAR USUARIOS-----------------------------------------
@app.route('/save_users', methods = ['POST'])
def addUser():
    
    cursor = con_bd.cursor()
    name = request.form['name']
    email = request.form['email']
    user = request.form['username']
    password = request.form['password']
    role = request.form['role']
    skills = request.form['skills']
    hashed_password = generate_password_hash(password)
    
    if name and email and user and password and role and skills:
        sql = """INSERT INTO users(name, email, usuario, password, role, skills) VALUES (%s, %s, %s, %s, %s, %s)"""
    
        cursor.execute(sql,(name, email, user, hashed_password, role, skills))
        
        con_bd.commit()
        flash("Registro guardado correctamente", "info")
        return redirect(url_for('index'))
    else:
        return "Error en la consulta"
    
#------------------------------GUARDAR PROYECTOS----------------------------------------------------------------

@app.route('/save_project', methods = ['POST'])
@login_required
def addProject():
    
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    name = request.form['nameProject']
    description = request.form['description']
    
    if name and description:
        insert_project_sql = """INSERT INTO projects(name, description) VALUES (%s, %s) RETURNING idProject"""
        cursor.execute(insert_project_sql,(name, description))
        project_id = cursor.fetchone()[0]
        flash("Registro guardado correctamente", "info")
        insert_members_sql = """INSERT INTO members_project(project_id,user_id) values(%s,%s)"""
        cursor.execute(insert_members_sql,(project_id,user_id))
        con_bd.commit()
    return redirect(url_for('projects'))
   
#---------------------------GUARDAR MIEMBROS EN EL PROYECTO-------------------------- 
@app.route('/add_user_to_project', methods=['POST'])
@login_required
def add_user_to_project():
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    
    # Obtén los datos del formulario
    project_id = request.form['project_id']
    username = request.form['username']
    
    # Verifica si el usuario ingresado existe en la tabla 'users'
    sql_check_user = "SELECT idUser FROM users WHERE usuario = %s"
    cursor.execute(sql_check_user, (username,))
    user_data = cursor.fetchone()
    
    if user_data:
        user_id_to_add = user_data[0]
        
        # Verifica si el usuario ya es miembro del proyecto
        sql_check_membership = "SELECT idMembers FROM members_project WHERE project_id = %s AND user_id = %s"
        cursor.execute(sql_check_membership, (project_id, user_id_to_add))
        existing_membership = cursor.fetchone()
        
        if existing_membership:
            flash("El usuario ya es miembro de este proyecto.", "warning")
        else:
            # Agrega al usuario como miembro del proyecto
            sql_insert_membership = "INSERT INTO members_project (project_id, user_id) VALUES (%s, %s)"
            cursor.execute(sql_insert_membership, (project_id, user_id_to_add))
            con_bd.commit()
            flash("Usuario agregado al proyecto correctamente.", "info")
    else:
        flash("El usuario ingresado no existe.", "danger")
    
    return redirect(url_for('projects'))

#------------------GUARDAR EQUIPOS----------------------------------------------------------

@app.route('/save_teams', methods = ['POST'])
@login_required
def addTeam():
    
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    name = request.form['nameTeam']
    
    if name:
        insert_team_sql = """INSERT INTO teams(name) VALUES (%s) RETURNING idTeam"""
        cursor.execute(insert_team_sql,(name,))
        team_id = cursor.fetchone()[0]
        flash("Registro guardado correctamente", "info")
        insert_members_sql = """INSERT INTO members_team(team_id,user_id) values(%s,%s)"""
        cursor.execute(insert_members_sql,(team_id,user_id))
        con_bd.commit()
    return redirect(url_for('teams'))
   
#---------------------------GUARDAR MIEMBROS EN EL equipo-------------------------- 
@app.route('/add_user_to_team', methods=['POST'])
@login_required
def add_user_to_team():
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    
    # Obtén los datos del formulario
    team_id = request.form['team_id']
    username = request.form['username']
    
    # Verifica si el usuario ingresado existe en la tabla 'users'
    sql_check_user = "SELECT idUser FROM users WHERE usuario = %s"
    cursor.execute(sql_check_user, (username,))
    user_data = cursor.fetchone()
    
    if user_data:
        user_id_to_add = user_data[0]
        
        # Verifica si el usuario ya es miembro del equipo
        sql_check_membership = "SELECT idMembers FROM members_team WHERE team_id = %s AND user_id = %s"
        cursor.execute(sql_check_membership, (team_id, user_id_to_add))
        existing_membership = cursor.fetchone()
        
        if existing_membership:
            flash("El usuario ya es miembro de este equipo.", "warning")
        else:
            # Agrega al usuario como miembro del equipo
            sql_insert_membership = "INSERT INTO members_team (team_id, user_id) VALUES (%s, %s)"
            cursor.execute(sql_insert_membership, (team_id, user_id_to_add))
            con_bd.commit()
            flash("Usuario agregado al equipo correctamente.", "info")
    else:
        flash("El usuario ingresado no existe.", "danger")
    
    return redirect(url_for('teams'))

#-----------------------------------GUARDAR TAREAS-------------------------------------------------------

@app.route('/save_tasks', methods = ['POST'])
@login_required
def addTask():
    
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    name = request.form['nameTask']
    description = request.form['description']
    initDate = request.form['initDate']
    finishDate = request.form['finishDate']
    username = request.form['username']
    
    # Verifica si el usuario ingresado existe en la tabla 'users'
    sql_check_user = "SELECT idUser FROM users WHERE usuario = %s"
    cursor.execute(sql_check_user, (username,))
    user_data = cursor.fetchone()
    
    if user_data:
        user_id_to_add = user_data[0]
        if name and description and initDate and finishDate and username:
            insert_team_sql = """INSERT INTO tasks(name, description, initDate, finishDate, user_id) VALUES (%s,%s,%s,%s,%s)"""
            cursor.execute(insert_team_sql,(name,description,initDate,finishDate,user_id_to_add))
            con_bd.commit()
    else:
        flash("El usuario ingresado no existe.", "danger") 

    return redirect(url_for('tasks'))

#-------------------------GUARDAR MENSAJES------------------------------------

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    cursor = con_bd.cursor()
    user_id = session.get('user_id')
    receiver_id = session.get('receiver_id')
    message_text = request.form['message_text']
    
    # Inserta el mensaje en la base de datos
    insert_message_sql = """
        INSERT INTO chats (sender_id, receiver_id, message_text)
        VALUES (%s, %s, %s)
    """
    cursor.execute(insert_message_sql, (user_id, receiver_id, message_text))
    con_bd.commit()
    
    flash("Mensaje enviado correctamente.", "info")
    return redirect(url_for('chat', receiver_id=receiver_id))

def error_404(error):
    return render_template('error_404.html'), 404

if __name__ == "__main__":
    app.register_error_handler(404, error_404)
    createTableUsers()
    createTableProjects()
    createTableMembersProjects()
    createTableTeams()
    createTableMembersTeam()
    createTableTasks()
    createTableChats()
    app.run(port=9999,debug=True)