from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, EqualTo
from app.models import Admin, Tag, Auth, Role  # 导入管理员数据表模型

tags = Tag.query.all()  # 查询所有标签
auth_list = Auth.query.all()
role_list = Role.query.all()


# 登录表单
class LoginForm(FlaskForm):
    """管理员表单验证"""
    account = StringField(  # 定义账号"account",前端渲染为id,name='account'
        label="账号",  # 定义标签
        validators=[  # validators 验证器
            DataRequired("请输入账号：")  # from wtforms.validators
        ],  # import DataRequired
        description="账号",  # 定义描述字段
        render_kw={  # 定义附加选项
            "class": "form-control",  # 可从模板中复制粘贴
            "placeholder": "请输入账号！",  # 等同于设置 HTML 标签属性
            #  "required": "required"         # 自动加载到前端，表示此项必填
        }
    )
    pwd = PasswordField(  # 注释同上
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
            #  "required": "required"
        }
    )
    submit = SubmitField(
        label="登录",
        render_kw={
            "class": "btn btn-primary btn-block btn-flat",
        }
    )

    # 自定义登录验证器 validate跟上字段名称account
    def validate_account(self, field):
        account = field.data
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError("该用户不存在！")


# 添加标签的表单
class TagForm(FlaskForm):
    name = StringField(  # name="name",id="input_name"
        label="名称",
        validators=[
            DataRequired("请输入标签!")
        ],
        description="标签",
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "placeholder": "请输入标签名称!"
        }
    )
    submit = SubmitField(
        "编辑",  # value=”编辑”
        render_kw={
            "class": "btn btn-primary",
        }
    )


# 上传电影的表单
class MovieForm(FlaskForm):
    title = StringField(
        label="片名",
        validators=[
            DataRequired("片名未输入! ")
        ],
        description="片名",
        render_kw={
            "class": "form-control",
            "id": "input_title",
            "placeholder": "请输入片名!"
        }
    )
    url = FileField(
        label="文件",
        validators=[
            DataRequired("请上传文件！")
        ],
        description="文件",
    )
    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired("请输入简介！")
        ],
        description="简介",
        render_kw={
            "class": "form-control",
            "row": "10"
        }
    )
    logo = FileField(
        label="封面",
        validators=[
            DataRequired("请上传封面！")
        ],
        description="封面",
    )
    star = SelectField(
        label="星级",
        validators=[
            DataRequired("请选择星级！")
        ],
        coerce=int,  # 类型
        choices=[(1, "1星"), (2, "2星"), (3, "3星"), (4, "4星"), (5, "5星")],  # 下拉选项
        description="星级",
        render_kw={
            "class": "form-control"
        }
    )
    tag_id = SelectField(
        label="标签",
        validators=[
            DataRequired("请选择标签！")
        ],
        coerce=int,  # 类型
        choices=[(v.id, v.name) for v in tags],  # tags = Tag.query.all()  # 查询所有标签
        description="标签",
        render_kw={
            "class": "form-control"
        }
    )
    area = StringField(
        label="地区",
        validators=[
            DataRequired("请输入地区！")
        ],
        description="地区",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入地区!"
        }
    )
    length = StringField(
        label="片长",
        validators=[
            DataRequired("请输入片长！")
        ],
        description="片长",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入片长!"
        }
    )
    release_time = StringField(
        label="上映时间",
        validators=[
            DataRequired("请选择上映时间！")
        ],
        description="上映时间",
        render_kw={
            "class": "form-control",
            "id": "input_release_time",
            "placeholder": "请选择上映时间!"
        }
    )
    submit = SubmitField(
        "编辑",  # value=”编辑”
        render_kw={
            "class": "btn btn-primary",
        }
    )


# 上传预告的表单
class PreviewForm(FlaskForm):
    title = StringField(
        label="预告标题",
        validators=[
            DataRequired("预告标题未输入! ")
        ],
        description="预告标题",
        render_kw={
            "class": "form-control",
            "id": "input_title",
            "placeholder": "请输入预告标题!"
        }
    )
    logo = FileField(
        label="预告封面",
        validators=[
            DataRequired("请上传预告封面！")
        ],
        description="文件",
    )
    submit = SubmitField(
        "编辑",  # value=”编辑”
        render_kw={
            "class": "btn btn-primary",
        }
    )


# 修改密码的表单
class PwdForm(FlaskForm):
    old_pwd = PasswordField(  # 注释同上
        label="旧密码",
        validators=[
            DataRequired("请输入旧密码！")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码！",
            #  "required": "required"
        }
    )
    new_pwd = PasswordField(  # 注释同上
        label="新密码",
        validators=[
            DataRequired("请输入新密码！")
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码！",
            #  "required": "required"
        }
    )
    submit = SubmitField(
        "编辑",  # value=”编辑”
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_old_pwd(self, field):
        from flask import session
        name = session["admin"]  # 通过session["admin"]获取账户名
        pwd = field.data  # 通过field字段获取密码
        admin = Admin.query.filter_by(  # 在数据库中查看登陆的账户是否存在
            name=name
        ).first()
        if not admin.check_pwd(pwd):  # 调用函数检查密码
            raise ValidationError("旧密码错误")


# 管理员权限的表单
class AuthForm(FlaskForm):
    name = StringField(
        label="权限名称",
        validators=[
            DataRequired("请输入权限名称！")
        ],
        description="权限名称",
        render_kw={
            "class": "form-control",
            "id": "input_name",
            "autofocus": "",
            "placeholder": "请输入权限名称！"
        }
    )
    url = StringField(
        label="权限地址",
        validators=[
            DataRequired("请输入权限地址！")
        ],
        description="权限地址",
        render_kw={
            "class": "form-control",
            "id": "input_url",
            "placeholder": "请输入权限地址！"
        }
    )
    submit = SubmitField(
        '提交',
        render_kw={
            "class": "btn btn-primary"
        }
    )


# 角色表单
class RoleForm(FlaskForm):
    name = StringField(
        label="角色名称",
        validators=[
            DataRequired("请输入角色名称！")
        ],
        description="角色名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入角色名称！"
        }
    )
    auths = SelectMultipleField(
        label="权限列表",
        validators=[
            DataRequired("请选择权限列表！")
        ],
        coerce=int,
        choices=[(v.id, v.name) for v in auth_list],
        description="权限列表",
        render_kw={
            "class": "form-control"
        }
    )
    submit = SubmitField(
        '提交',
        render_kw={
            "class": "btn btn-primary"
        }
    )


class AdminForm(FlaskForm):
    name = StringField(
        label="管理员名称",
        validators=[
            DataRequired("请输入管理员名称！")
        ],
        description="管理员名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入管理员名称！",
        }
    )
    pwd = PasswordField(
        label="管理员密码",
        validators=[
            DataRequired("请输入管理员密码！")
        ],
        description="管理员密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入管理员密码！",
        }
    )
    repwd = PasswordField(
        label="管理员重复密码",
        validators=[
            DataRequired("请重复输入管理员密码！"),
            EqualTo("pwd", message="两次密码不一致")
        ],
        description="管理员重复密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请重复输入管理员密码！",
        }
    )
    role_id = SelectField(
        label="所属角色",
        coerce=int,
        choices=[(v.id, v.name) for v in role_list],
        render_kw={
            "class": "form-control",
        }
    )
    submit = SubmitField(
        label="添加",
        render_kw={
            "class": "btn btn-primary btn-block btn-flat",
        }
    )
