from datetime import timedelta

from django import forms
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.db.models import Q
from django.forms import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate

from django.utils.safestring import mark_safe
from django.core.mail import send_mail

class UserCacheMixin:
    user_cache = None


class SignIn(UserCacheMixin, forms.Form):
    password = forms.CharField(
        label=_("Password"), strip=False, widget=forms.PasswordInput
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if settings.USE_REMEMBER_ME:
            self.fields["remember_me"] = forms.BooleanField(
                label=_("Remember me"), required=False
            )

    def clean_password(self):
        password = self.cleaned_data["password"]

        if not self.user_cache:
            return password

        if not self.user_cache.check_password(password):
            raise ValidationError(_("You entered an invalid password."))

        return password


class SignInViaUsernameForm(SignIn):
    username = forms.CharField(label=_("Username"))

    @property
    def field_order(self):
        if settings.USE_REMEMBER_ME:
            return ["username", "password", "remember_me"]
        return ["username", "password"]

    def clean_username(self):
        username = self.cleaned_data["username"]

        user = User.objects.filter(username=username).first()
        if not user:
            raise ValidationError(_("You entered an invalid username."))

        if not user.is_active:
            raise ValidationError(_("This account is not active."))

        self.user_cache = user

        return username


class EmailForm(UserCacheMixin, forms.Form):
    email = forms.EmailField(label=_("Email"))

    def clean_email(self):
        email = self.cleaned_data["email"]

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            raise ValidationError(_("You entered an invalid email address."))

        if not user.is_active:
            raise ValidationError(_("This account is not active."))

        self.user_cache = user

        return email


class SignInViaEmailForm(SignIn, EmailForm):
    @property
    def field_order(self):
        if settings.USE_REMEMBER_ME:
            return ["email", "password", "remember_me"]
        return ["email", "password"]


class EmailOrUsernameForm(UserCacheMixin, forms.Form):
    email_or_username = forms.CharField(label=_("Email or Username"))

    def clean_email_or_username(self):
        email_or_username = self.cleaned_data["email_or_username"]

        user = User.objects.filter(
            Q(username=email_or_username) | Q(email__iexact=email_or_username)
        ).first()
        if not user:
            raise ValidationError(
                _("You entered an invalid email address or username.")
            )

        if not user.is_active:
            raise ValidationError(_("This account is not active."))

        self.user_cache = user

        return email_or_username


class SignInViaEmailOrUsernameForm(SignIn, EmailOrUsernameForm):
    @property
    def field_order(self):
        if settings.USE_REMEMBER_ME:
            return ["email_or_username", "password", "remember_me"]
        return ["email_or_username", "password"]


class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = settings.SIGN_UP_FIELDS

    email = forms.EmailField(
        label=_("Email"), help_text=_("Required. Enter an existing email address.")
    )
    agree_to_terms = forms.BooleanField(
        required=True,
        label=mark_safe('I agree to the <a href="/accounts/terms/" target="_blank">terms and conditions</a>'),
        error_messages={'required': "You must agree to the terms and conditions to proceed."}
    )    
    def save(self, commit=True):
        user = super(SignUpForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
    
    def clean_email(self):
        email = self.cleaned_data["email"]

        user = User.objects.filter(email__iexact=email).exists()
        if user:
            raise ValidationError(_("You can not use this email address."))

        return email

    def send_welcome_email(self, user):
        subject = "Welcome to Our Site"
        message = "Thank you for registering at our site."
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list)


class ResendActivationCodeForm(UserCacheMixin, forms.Form):
    email_or_username = forms.CharField(label=_("Email or Username"))

    def clean_email_or_username(self):
        email_or_username = self.cleaned_data["email_or_username"]

        user = User.objects.filter(
            Q(username=email_or_username) | Q(email__iexact=email_or_username)
        ).first()
        if not user:
            raise ValidationError(
                _("You entered an invalid email address or username.")
            )

        if user.is_active:
            raise ValidationError(_("This account has already been activated."))

        activation = user.activation_set.first()
        if not activation:
            raise ValidationError(_("Activation code not found."))

        now_with_shift = timezone.now() - timedelta(hours=24)
        if activation.created_at > now_with_shift:
            raise ValidationError(
                _(
                    "Activation code has already been sent. You can request a new code in 24 hours."
                )
            )

        self.user_cache = user

        return email_or_username


class ResendActivationCodeViaEmailForm(UserCacheMixin, forms.Form):
    email = forms.EmailField(label=_("Email"))

    def clean_email(self):
        email = self.cleaned_data["email"]

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            raise ValidationError(_("You entered an invalid email address."))

        if user.is_active:
            raise ValidationError(_("This account has already been activated."))

        activation = user.activation_set.first()
        if not activation:
            raise ValidationError(_("Activation code not found."))

        now_with_shift = timezone.now() - timedelta(hours=24)
        if activation.created_at > now_with_shift:
            raise ValidationError(
                _(
                    "Activation code has already been sent. You can request a new code in 24 hours."
                )
            )

        self.user_cache = user

        return email


class RestorePasswordForm(EmailForm):
    pass


class RestorePasswordViaEmailOrUsernameForm(EmailOrUsernameForm):
    pass


class ChangeProfileForm(forms.Form):
    first_name = forms.CharField(label=_("First name"), max_length=30, required=False)
    last_name = forms.CharField(label=_("Last name"), max_length=150, required=False)


class ChangeEmailForm(forms.Form):
    email = forms.EmailField(label=_("Email"))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data["email"]

        if email == self.user.email:
            raise ValidationError(_("Please enter another email."))

        user = User.objects.filter(
            Q(email__iexact=email) & ~Q(id=self.user.id)
        ).exists()
        if user:
            raise ValidationError(_("You can not use this mail."))

        return email


class RemindUsernameForm(EmailForm):
    pass


def sign_up(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get("username")
            raw_password = form.cleaned_data.get("password1")
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect("index")
    else:
        form = SignUpForm()
    return render(request, "accounts/sign_up.html", {"form": form})
