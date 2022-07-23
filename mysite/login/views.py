import emoji
import hashlib
import datetime

from django.shortcuts import render
from django.shortcuts import redirect
from django.conf import settings

from . import models
from . import forms

# Create your views here.


def hash_code(s, salt='mysite'):  # encode
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())  
    return h.hexdigest()


def index(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    return render(request, 'login/index.html')


def login(request):
    if request.session.get('is_login', None):  # Do not allow repeat login
        return redirect('/index/')

    if request.method == "POST":
        login_form = forms.UserForm(request.POST)
        message = "😦Oops! Wrong vertification code!"
        if login_form.is_valid():          # Make sure that neither username nor password is none 
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')       
            try:
                user = models.User.objects.get(name=username)
            except :
                message = "😦Oops! Username doesn't exisit."
                return render(request, 'login/login.html', locals())

            if not user.has_confirmed:
                message = '😦Oops! This user has not been confirmed by email!'
                return render(request, 'login/login.html', locals())    

            if user.password == hash_code(password):
                request.session['is_login'] = True
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                return redirect('/index/')
                
            else:
                message = '😦Oops! Wrong password.'
                return render(request, 'login/login.html', locals())
        else:
            return render(request, 'login/login.html', locals())

    login_form = forms.UserForm()
    return render(request, 'login/login.html', locals())


def register(request):
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        register_form = forms.RegisterForm(request.POST)
        message = "😦Oops! Wrong vertification code!"
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            sex = register_form.cleaned_data.get('sex')

            if password1 != password2:
                message = '😦Oops! Different password inputs.'
                return render(request, 'login/register.html', locals())
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:
                    message = '😦Oops! Username already exisits.'
                    return render(request, 'login/register.html', locals())
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:
                    message = '😦Oops! This E-mail address is already been registered!'
                    return render(request, 'login/register.html', locals())

                new_user = models.User()
                new_user.name = username
                new_user.password = hash_code(password1)
                new_user.email = email
                new_user.sex = sex
                new_user.save()

                code = make_confirm_string(new_user)
                send_email(email, code)

                message = 'Please check verification code from your e-mail box.'
                return render(request, 'login/confirm.html', locals())
        else:
            return render(request, 'login/register.html', locals())
    register_form = forms.RegisterForm()
    return render(request, 'login/register.html', locals())


def logout(request):
    if not request.session.get('is_login', None):  # didn't log in
        return redirect("/login/")
    request.session.flush()

    # can also use these functions:
    # del request.session['is_login']
    # del request.session['user_id']
    # del request.session['user_name']

    return redirect("/login/")


def make_confirm_string(user):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code = hash_code(user.name, now)
    models.ConfirmString.objects.create(code=code, user=user,)
    return code


def send_email(email, code):

    from django.core.mail import EmailMultiAlternatives

    subject = 'Registration confirmation email'

    text_content = '''Thank you for using our website.\
                    If you see this message, it means that your email server does not provide HTML link function, please contact the administrator!'''

    html_content = '''
                    <p>Thank you for register<a href="http://{}/confirm/?code={}" target=blank>www.liujiangblog.com</a>,\
                    Our website focusing on providing detailed stock information everyday.</p>
                    <p>Please click the site link to complete the registration confirmation!</p>
                    <p>This link is valid for{}days.</p>
                    '''.format('127.0.0.1:8000', code, settings.CONFIRM_DAYS)

    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def user_confirm(request):
    code = request.GET.get('code', None)
    message = ''
    try:
        confirm = models.ConfirmString.objects.get(code=code)
    except:
        message = 'Invalid confirmation request!'
        return render(request, 'login/confirm.html', locals())

    c_time = confirm.c_time
    now = datetime.datetime.now()
    if now > c_time + datetime.timedelta(settings.CONFIRM_DAYS):
        confirm.user.delete()
        message = 'Your email has expired! Please register again!'
        return render(request, 'login/confirm.html', locals())
    else:
        confirm.user.has_confirmed = True
        confirm.user.save()
        confirm.delete()
        message = 'Thank you for your confirmation, please log in with your account!'
        return render(request, 'login/confirm.html', locals())


