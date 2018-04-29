from . import admin
from flask import render_template, redirect, url_for, flash, request, session, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, OpLog, AdminLog, Userlog, Auth, Role
from functools import wraps
from app import db, app
from werkzeug.utils import secure_filename  # secure_filename(),转换安全名称
import os, uuid, datetime


# 上下文处理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


# 访问限制
def admin_login_req(fn):
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        # 如果没有这个键
        if 'admin' not in session:
            return redirect(url_for("admin.login", next=request.url))
        return fn(*args, **kwargs)  # 装饰器被调用后由函数去继承,fn()

    return decorated_function  # 返回装饰器


# 访问限制
def admin_auth(fn):
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session["admin_id"]
        ).first()
        auths = admin.role.auths  # 获取后台已登录管理员账户所对应角色的权限
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for values in auths if values == v.id]
        rule = request.url_rule
        print(urls)
        print(rule)
        if str(rule) not in urls:
            abort(404)
        return fn(*args, **kwargs)  # 装饰器被调用后由函数去继承,fn()

    return decorated_function  # 返回装饰器


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)  # 将文件名分割出前后缀
    # -1 表示取出文件的后缀
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


# 后台首页
@admin.route("/")
@admin_login_req
def index():
    return render_template("admin/index.html")


# 登录
@admin.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    # 提交表单时的验证
    if form.validate_on_submit():
        data = form.data  # .data 可获取表单提交时的所有信息
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash('⚠️密码错误', 'error')
            return redirect(url_for("admin.login"))
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        adminLog = AdminLog(
            admin_id=admin.id,
            ip=request.remote_addr,
        )
        db.session.add(adminLog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)


# 登出
@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin", None)  # 清除session的值
    session.pop("admin_id", None)
    return redirect(url_for("admin.login"))


# 修改密码
@admin.route('/pwd/', methods=["GET", "POST"])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功,请重新登录", "successfully")
        return redirect(url_for("admin.logout"))
    return render_template("admin/pwd.html", form=form)


# 标签添加
@admin.route('/tag/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data["name"]).count()
        if tag == 1:
            flash("该标签已存在！", "error")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(
            name=data["name"]
        )
        db.session.add(tag)
        db.session.commit()
        flash("提交成功", "successfully")
        oplog = OpLog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason=f"添加标签{data['name']}"
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.tag_add"))
    return render_template("admin/tag_add.html", form=form)


# 标签列表
@admin.route('/tag/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def tag_list(page=None):
    if page is None:  # 如果没有传入页码，则默认为 1 。
        page = 1
    page_data = Tag.query.order_by(
        Tag.addTime.desc()  # 按照时间排序。
    ).paginate(page=page, per_page=5)  # (第几页，分几条)
    return render_template("admin/tag_list.html", page_data=page_data)


# 标签删除
@admin.route('/tag/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()  # 通过主键查询数据库
    db.session.delete(tag)
    db.session.commit()
    flash("标签删除成功", "successfully_deleted")
    return redirect(url_for("admin.tag_list", page=1))


# 标签编辑
@admin.route('/tag/edit/<int:id>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)  # 通过主键查询数据库 获取旧名称
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data["name"]).count()
        if tag.name == data["name"] or tag_count == 1:
            flash("该标签已存在！", "error")
            return redirect(url_for("admin.tag_edit", id=id))
        tag.name = data["name"]
        db.session.add(tag)
        db.session.commit()
        flash("标签编辑成功", "successfully_edited")
        return redirect(url_for("admin.tag_edit", id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


# 电影添加
@admin.route('/movie/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        if Movie.query.filter_by(title=data["title"]).count() == 1:
            flash("该片名已经存在！", "error")
            return redirect(url_for("admin.movie_add"))

        file_url = secure_filename(form.url.data.filename)  # 获取并转化为安全的电影文件名
        file_logo = secure_filename(form.logo.data.filename)

        if not os.path.exists(app.config['UP_DIR']):  # 存放目录不存在则创建
            os.makedirs(app.config['UP_DIR'])  # 创建多级目录
            os.chmod(app.config['UP_DIR'], "rw")  # 授权

        url = change_filename(file_url)  # 调用函数生成新的文件名
        logo = change_filename(file_logo)

        form.url.data.save(app.config['UP_DIR'] + url)  # 保存上传的数据
        form.logo.data.save(app.config['UP_DIR'] + logo)

        movie = Movie(
            title=data["title"],
            url=url,
            info=data["info"],
            logo=logo,
            star=int(data["star"]),
            playNum=0,
            commentNum=0,
            tag_id=int(data["tag_id"]),
            area=data["area"],
            release_time=data["release_time"],
            length=data["length"],
        )
        db.session.add(movie)
        db.session.commit()
        flash("电影添加成功", "successfully")
        return redirect(url_for("admin.movie_add"))
    return render_template("admin/movie_add.html", form=form)


# 电影列表
@admin.route('/movie/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    # join(Tag) 关联到 Tag ，并以 filter 进行多表查询
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/movie_list.html", page_data=page_data)


# 电影删除
@admin.route('/movie/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def movie_del(id=None):
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash("电影删除成功", "successfully_deleted")
    return redirect(url_for("admin.movie_list", page=1))


# 电影编辑
@admin.route('/movie/edit/<int:id>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_edit(id=None):
    form = MovieForm()

    form.url.validators = []
    form.logo.validators = []

    movie = Movie.query.get_or_404(int(id))
    if request.method == "GET":
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star

    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        if movie_count == 1 or movie.title == data["title"]:
            flash("电影名称已存在", "error")
            return redirect(url_for("admin.movie_edit", id=id))

        if not os.path.exists(app.config['UP_DIR']):  # 存放目录不存在则创建
            os.makedirs(app.config['UP_DIR'])  # 创建多级目录
            os.chmod(app.config['UP_DIR'], "rw")  # 授权

        if form.url.data.filename != "":
            file_url = secure_filename(form.url.data.filename)  # 获取并转化为安全的电影文件名
            movie.url = change_filename(file_url)  # 调用函数生成新的文件名
            form.url.data.save(app.config['UP_DIR'] + movie.url)  # 保存上传的数据

        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)

        movie.star = data["star"]
        movie.tag_id = data["tag_id"]
        movie.info = data["info"]
        movie.title = data["title"]
        movie.area = data["area"]
        movie.length = data["length"]
        movie.release_time = data["release_time"]

        db.session.add(movie)
        db.session.commit()

        flash("电影修改成功", "successfully")
        return redirect(url_for("admin.movie_edit", id=id))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


# 电影预告添加
@admin.route('/preview/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data

        file_logo = secure_filename(form.logo.data.filename)  # 获取并转化为安全的电影文件名
        if not os.path.exists(app.config['UP_DIR']):  # 存放目录不存在则创建
            os.makedirs(app.config['UP_DIR'])  # 创建多级目录
            os.chmod(app.config['UP_DIR'], "rw")  # 授权
        logo = change_filename(file_logo)  # 调用函数生成新的文件名
        form.logo.data.save(app.config['UP_DIR'] + logo)  # 保存上传的数据

        preview = Preview(
            title=data["title"],
            logo=logo
        )

        db.session.add(preview)
        db.session.commit()
        flash("电影预告添加成功", "successfully")

        return redirect(url_for("admin.preview_add"))
    return render_template("admin/preview_add.html", form=form)


# 电影预告列表
@admin.route('/preview/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/preview_list.html", page_data=page_data)


# 电影预告列表-删除
@admin.route('/preview/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def preview_del(id=None):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash("电影删除成功", "successfully_deleted")
    return redirect(url_for("admin.preview_list", page=1))

# 电影预告列表-编辑
@admin.route('/preview/edit/<int:id>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_edit(id):
    form = PreviewForm()
    form.logo.validators = []
    preview = Preview.query.get_or_404(int(id))
    if request.method == "GET":
        form.title.data = preview.title

    if form.validate_on_submit():
        data = form.data
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + preview.logo)

        preview.title = data["title"]
        db.session.add(preview)
        db.session.commit()
        flash("电影预告编辑成功", "successfully")

        return redirect(url_for("admin.preview_edit", id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


# 会员列表
@admin.route('/user/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


# 查看会员
@admin.route('/user/view/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template("admin/user_view.html", user=user)


# 会员删除
@admin.route('/user/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    print(user)
    db.session.delete(user)
    db.session.commit()
    flash("会员删除成功", "successfully_deleted")
    return redirect(url_for("admin.user_list", page=1))


# 评论列表
@admin.route('/comment/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def comment_list(page):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/comment_list.html", page_data=page_data)


# 评论删除
@admin.route('/comment/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("会员删除成功", "successfully_deleted")
    return redirect(url_for("admin.comment_list", page=1))


# 电影收藏列表
@admin.route('/moviecol/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def moviecol_list(page):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Moviecol.movie_id,
        User.id == Moviecol.user_id
    ).order_by(
        Moviecol.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


# 电影收藏列表-删除
@admin.route('/moviecol/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功", "successfully_deleted")
    return redirect(url_for("admin.moviecol_list", page=1))


# 操作日志列表
@admin.route('/opLog/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def opLog_list(page=None):
    if page is None:
        page = 1
    page_data = OpLog.query.join(
        Admin
    ).filter(
        Admin.id == OpLog.admin_id,
    ).order_by(
        OpLog.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/opLog_list.html", page_data=page_data)


# 管理员登陆日志列表
@admin.route('/adminLoginLog/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def adminLoginLog_list(page=None):
    if page is None:
        page = 1
    page_data = AdminLog.query.join(
        Admin
    ).filter(
        Admin.id == AdminLog.admin_id,
    ).order_by(
        AdminLog.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/adminLoginLog_list.html", page_data=page_data)


# 会员登录日志列表
@admin.route('/userLoginLog/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def userLoginLog_list(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.join(
        User
    ).filter(
        User.id == Userlog.user_id,
    ).order_by(
        Userlog.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/userLoginLog_list.html", page_data=page_data)


# 权限添加
@admin.route('/auth/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data["name"],
            url=data["url"]
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功", "successfully")
    return render_template("admin/auth_add.html", form=form)


# 权限列表
@admin.route('/auth/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def auth_list(page=None):
    if page is None:  # 如果没有传入页码，则默认为 1 。
        page = 1
    page_data = Auth.query.order_by(
        Auth.addTime.desc()  # 按照时间排序。
    ).paginate(page=page, per_page=5)  # (第几页，分几条)
    return render_template("admin/auth_list.html", page_data=page_data)


# 权限删除
@admin.route('/auth/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def auth_del(id=None):
    auth = Auth.query.filter_by(id=id).first_or_404()  # 通过主键查询数据库
    db.session.delete(auth)
    db.session.commit()
    flash("标签删除成功", "successfully_deleted")
    return redirect(url_for("admin.auth_list", page=1))


# 权限编辑
@admin.route('/auth/edit/<int:id>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)  # 通过主键查询数据库 获取旧名称
    if form.validate_on_submit():
        data = form.data
        auth.url = data["url"]
        auth.name = data["name"]
        db.session.add(auth)
        db.session.commit()
        flash("权限编辑成功", "successfully_edited")
        return redirect(url_for("admin.auth_edit", id=id))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


# 角色添加
@admin.route('/role/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data["name"],
            # 数组[1,2,3] -> 字符串'1,2,3'
            auths=",".join(map(lambda v: str(v), data["auths"]))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功", "successfully")
    return render_template("admin/role_add.html", form=form)


# 角色编辑
@admin.route('/role/edit/<int:id>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)  # 通过主键查询数据库 获取旧名称
    if request.method == "GET":
        auths = role.auths
        # 字符串转化为整形数组 "1,2,3" -> [1, 2, 3] 渲染到html页面
        form.auths.data = list(map(lambda v: int(v), auths.split(',')))
    if form.validate_on_submit():
        data = form.data
        role.name = data["name"]
        # 数组[1,2,3] -> 字符串'1,2,3'  存储到数据库
        role.auths = ",".join(map(lambda v: str(v), data["auths"]))
        db.session.add(role)
        db.session.commit()
        flash("权限编辑成功", "successfully_edited")
        return redirect(url_for("admin.role_edit", id=id))
    return render_template("admin/role_edit.html", form=form, role=role)


# 角色列表
@admin.route('/role/list/<int:page>/', methods={"GET", "POST"})
@admin_login_req
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addTime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html", page_data=page_data)


# 角色删除
@admin.route('/role/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def role_del(id=None):
    role = Role.query.filter_by(id=id).first_or_404()  # 通过主键查询数据库
    db.session.delete(role)
    db.session.commit()
    flash("标签删除成功", "successfully_deleted")
    return redirect(url_for("admin.role_list", page=1))


# 管理员添加
@admin.route('/admin/add/', methods={"GET", "POST"})
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    from werkzeug.security import generate_password_hash
    if form.validate_on_submit():
        data = form.data
        admin = Admin(
            name=data["name"],
            pwd=generate_password_hash(data["pwd"]),
            role_id=data["role_id"],
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功", "successfully")
    return render_template("admin/admin_add.html", form=form)


# 管理员列表
@admin.route('/admin/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:  # 如果没有传入页码，则默认为 1 。
        page = 1
    page_data = Admin.query.join(
        Role
    ).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addTime.desc()  # 按照时间排序。
    ).paginate(page=page, per_page=5)  # (第几页，分几条)
    return render_template("admin/admin_list.html", page_data=page_data)
