from flask import Flask, abort, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from flask_gravatar import Gravatar
from functools import wraps
import smtplib,requests,os
from dotenv import load_dotenv
from datetime import date

load_dotenv()

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] =os.environ.get('secret')
ckeditor = CKEditor(app)
Bootstrap(app)



##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get("database_uri")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager=LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONFIGURE TABLES

class User(UserMixin,db.Model):
    __tablename__ = "users"
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(250),unique=True,nullable=False)
    password=db.Column(db.String(250),nullable=False)
    name=db.Column(db.String(250),nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments=relationship("Comment",back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer,primary_key=True)
    author_id=db.Column(db.Integer,db.ForeignKey("users.id"))

    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(), nullable=False)
    comments=relationship('Comment',back_populates='blog_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id=db.Column(db.Integer,db.ForeignKey('users.id'))
    text = db.Column(db.Text, nullable=False)
    comment_author=relationship("User",back_populates='comments')

    post_id=db.Column(db.Integer,db.ForeignKey('blog_posts.id'))
    blog_post=relationship("BlogPost",back_populates='comments')
##USER TABLE


db.create_all()

def admin_only(f):

    def decorated_function(post_id):
        blog=BlogPost.query.get(post_id)
     
        if current_user.id != blog.author_id:
            return abort(403)
        else:
            return f(post_id)
    return decorated_function


@login_manager.user_loader
def login_user_callback(user_id):
    user=User.query.get(user_id)
    return user


@app.route('/')
# @login_required
def get_all_posts():
    posts = BlogPost.query.all()
    print(current_user)
    return render_template("index.html",all_posts=posts,isAdmin=current_user)
    

@app.route('/register',methods=['POST','GET'])
def register():
    user=RegisterForm()
    if user.validate_on_submit():

        if User.query.filter_by(email=user.email.data).first():
            flash('Email already registered.Log in instead')
            return redirect(url_for('login'))
        print(user.password.data)
        print(user.confirm_password.data)

        if user.password.data == user.confirm_password.data:
            encrypt_password=generate_password_hash(user.password.data,method="pbkdf2:sha256",salt_length=8)
            new_user=User(email=user.email.data,
                      password=encrypt_password,
                      name=user.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        
        flash('Password must be matched same as confirm password')
            
    return render_template("register.html",form=user,isAdmin=current_user)


@app.route('/login',methods=['POST','GET'])
def login():
    login=LoginForm()

    if login.validate_on_submit():

        isLogin=User.query.filter_by(email=login.email.data).first()
        if isLogin:
            if check_password_hash(isLogin.password,login.password.data):  
                login_user(isLogin)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Invalid password')
        else:
            flash("Invalid email")

    return render_template("login.html",form=login,isAdmin=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login',logged=current_user))


@app.route("/post/<int:post_id>",methods=['POST',"GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment=CommentForm()
    
    if comment.validate_on_submit():

        if not current_user.is_authenticated:
            flash("You need login or register to commit")
            return redirect(url_for('login'))
        
        new_comment=Comment(
        text=comment.comment.data,
        post_id=post_id,
        author_id=current_user.id,
        )

        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html",form=comment,post=requested_post,isAdmin=current_user)
  


@app.route("/about")
def about():
    return render_template("about.html",isAdmin=current_user)



@app.route('/contact',methods=["POST","GET"])
def contact():
    if request.method=='POST':
        if not current_user.is_authenticated:
            flash("You need login or register to send your message")
            return redirect(url_for('login'))
        
        my_gmail=os.environ.get('my_gmail')
        password=os.environ.get('password')
   
        with smtplib.SMTP('smtp.gmail.com') as connection:
            connection.starttls()
            connection.login(user=my_gmail,password=password)
            connection.sendmail(from_addr=request.form['email'],to_addrs=my_gmail,msg=f'Subject:{request.form["subject"]}\n\n{request.form["message"]}.\n\nName: {request.form["name"]}\nPhone Number: {request.form["phone"]}\nGmail: {request.form["email"]}')
        return render_template('contact.html',check=True,isAdmin=current_user)

    return render_template("contact.html",check=False,isAdmin=current_user)


@app.route("/new-post",methods=["POST","GET"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html",is_edit=False, form=form,isAdmin=current_user)


@app.route("/edit-post/<int:post_id>", endpoint='edit_post' ,methods=['POST','GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html",is_edit=True, form=edit_form,isAdmin=current_user)


@app.route("/delete/<int:post_id>",endpoint='delete_post')
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)
