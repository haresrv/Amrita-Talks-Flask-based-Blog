from flask import Flask, render_template ,redirect, url_for,request,session,flash
from functools import wraps
import re
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
current_user = ""
current_user_id = 0

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


# posts = [
#     {
#         'author':'Sree Ramji',
#         'title':'Blog Post 1',
#         'content':'w0rk 5h0uld b3 m1nd 1nv0lv3d 7h1n6',
#         'date_posted':'Jan 2, 2020'
#     },

#     {
#         'author': 'Hare SRV',
#         'title': 'Blog Post 2',
#         'content': '7h053 v10l3n7 d3l16h75 h4v3 v10l3n7 3nd5',
#         'date_posted': 'Jan 5, 2020'
#     }
# ]

posts = []

# users = {"Chosen_One":"DrewMcintyre123","Architect":"SethRollins123","Rated_R_Superstar":"Edge123","Phenomenal_One":"AJStyles123"}

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first.','danger')
            return redirect(url_for('login'))
    return wrap


def validate(password):
        if len(password) < 6:
            return 1
        elif re.search('[0-9]',password) is None:
            return 2
        elif re.search('[A-Za-z]',password) is None:
            return 3
        else:
            return None


def isInvalid(username):
        user=User.query.filter_by(username=username).first()
        if user:
            return 1
        else:
            return 0


def isInvalidMail(email):
    user = User.query.filter_by(email=email).first()
    if user:
        return 1
    else:
        return 0

def row2dict(row):
    d = {}
    for column in row.__table__.columns:
        if(column.name=='user_id'):
            # print(int(str(getattr(row, column.name))))
            d["author"] =   str(db.session.query(User).filter_by(id=int(str(getattr(row, column.name)))).first().username)
        else:
            d[column.name] = str(getattr(row, column.name))
    return d



def update():
    posts.clear()
    for i in db.session.query(Post).all():
        posts.append(row2dict(i))  
    # print(posts)
@app.route("/")
@app.route("/home")
@login_required
def home():
    update()
    # print(posts)
    return render_template("home.html",posts=posts)

@app.route("/about")
def about():
    return render_template("about.html",title='About')


@login_required
@app.route("/create",methods = ['GET','POST'])
def create():
    if request.method == 'POST':
        if request.form["title"] == "" or request.form["content"] == "":
            flash('Enter all fields','danger')

        else:
            # print(type(current_user_id))
            db.session.add(Post(title = request.form["title"],content = request.form["content"],user_id = current_user_id ))
            # print(dict(db.session.query(Post).filter_by(title=request.form["title"]).__dict__))
            db.session.commit()
            update()
            return redirect(url_for("home"))
    
    return render_template("new_post.html",title='NEW POST')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # bcrypt.hashpw(request.form['password'].encode('utf-8').encode('utf-8'), hashed_password) == hashed_password
        user = User.query.filter_by(username=request.form['username']).first()
        hashed_password = User.query.filter_by(username=request.form['username']).first().password
        if not (user and (bcrypt.hashpw(request.form['password'].encode('utf-8'), hashed_password) == hashed_password)):
                # error = 'Invalid Credentials. Please try again.'
                flash('Invalid Credentials. Please try again.','danger')
                # print(users)
        else:
            current_user=request.form['username']
            current_user_id = User.query.filter_by(username=request.form['username']).first().id
            current_user_id = int(current_user_id)
            session['logged_in'] = True
            # print("CUR1",current_user)
            flash('You were logged in.','success')
            update()
            
            return redirect(url_for('home'))

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        if request.form['fname']=="" or request.form['lname']=="" or request.form['mobile']=="" or request.form['email']=="" or request.form['username']=="" or request.form['password']=="" or request.form['cpassword']=="":
            flash('Fill all Credentials and Try again.',"danger")
        else:
            if not(request.form['password']==request.form['cpassword']):
                flash('Passwords mismatch',"danger")
            else:
                x = validate(request.form['password'])
                if x is not None:
                    if x==1:
                        flash("Make sure your password is atlaest 6 letters","danger")
                    elif x==2:
                        flash("Make sure your password has a number in it","danger")
                    else:
                        flash("Make sure your password has a letter in it","danger")
                elif isInvalid(request.form['username']):
                    flash("Username already exists!!", "danger")
                elif isInvalidMail(request.form['email']):
                    flash("Email already exists!!", "danger")
                else:
                    hashed_password = bcrypt.hashpw(request.form['password'].encode('utf-8'),bcrypt.gensalt())
                        # .decode('utf-8')
                    user = User(username=request.form['username'],email=request.form['email'],password=hashed_password)
                    db.session.add(user)
                    db.session.commit()
                    flash("Registration Success!! Your Details have been added." ,"warning")
                    # print(hashed_password)
                    # print(users)
                    return redirect(url_for('home'))

    return render_template('register.html', error=error)



@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    current_user=""
    current_user_id=""
    flash('You were logged out.')
    # print("CUR2",current_user)
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    # flash('Non Existent Page',"error")
    return render_template('error.html'), 404

if __name__ == "__main__":
    app.run(debug=True)
