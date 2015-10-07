"""Django views for the Chirper app.

Note that every save call either passes or raises an Exception.
This is because we want to print the messages provided by Stormpath.

"""
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.conf import settings

from django_stormpath.models import APPLICATION
from django_stormpath.forms import StormpathUserCreationForm

from sample.forms import SampleUserCustomInfoForm

from stormpath.error import Error as StormpathError
from stormpath.nonce import Nonce
from stormpath.id_site import IdSiteCallbackResult


def handle_id_site_callback(self, url_response):
    try:
        from urlparse import urlparse
    except ImportError:
        from urllib.parse import urlparse

    import jwt
    try:
        jwt_response = urlparse(url_response).query.split('=')[1]
    except Exception:  # because we wan't to catch everything
        return None

    api_key_secret = self._client.auth.secret

    # validate signature
    try:
        decoded_data = jwt.decode(
            jwt_response, api_key_secret, audience=self._client.auth.id,
            algorithms=['HS256'])
    except (jwt.DecodeError, jwt.ExpiredSignature):
        return None

    if 'err' in decoded_data:
        raise StormpathError(decoded_data.get('err'))

    nonce = Nonce(decoded_data['irt'])

    # check if nonce is in cache already
    # if it is throw an Exception
    if self._store._cache_get(nonce.href):
        raise ValueError('JWT has already been used.')

    # store nonce in cache store
    self._store._cache_put(href=nonce.href, data={'value': nonce.value})

    # issuer = decoded_data['iss']
    account_href = decoded_data['sub']
    is_new_account = decoded_data['isNewSub']
    state = decoded_data.get('state')
    status = decoded_data.get('status')

    if account_href:
        account = self.accounts.get(account_href)
        if self.has_account(account):
            # We modify the internal parameter sp_http_status which indicates if an account
            # is new (ie. just created). This is so we can take advantage of the account.is_new_account
            # property
            account.sp_http_status  # NOTE: this forces account retrieval and building of the actual Account object
            account.__dict__['sp_http_status'] = 201 if is_new_account else 200
        else:
            account = None
    else:
        account = None
    return IdSiteCallbackResult(account=account, state=state, status=status)


def stormpath_id_site_callback(request):
    from django_stormpath.id_site import handle_id_site_callback
    ret = handle_id_site_callback(APPLICATION,
            request.build_absolute_uri())
    return handle_id_site_callback(request, ret)


def stormpath_login(request):
    """Verify user login.
    It uses django_stormpath to check if user credentials are valid.
    """
    if settings.USE_ID_SITE:
        return redirect('sample:stormpath_id_site_login')

    if request.user.is_authenticated():
        return redirect('sample:home')

    form = AuthenticationForm(data=(request.POST or None))

    if form.is_valid():
        user = form.get_user()
        login(request, user)
        return redirect('sample:home')

    return render(
        request, 'login.html', {"form": form, 'id_site': settings.USE_ID_SITE})


@login_required
def stormpath_logout(request):
    """Simple logout view.
    """
    if settings.USE_ID_SITE:
        return redirect('sample:stormpath_id_site_logout')

    logout(request)
    return redirect('sample:home')


def register(request):
    """User creation view.
    """
    if settings.USE_ID_SITE:
        return redirect('sample:stormpath_id_site_register')

    form = StormpathUserCreationForm(request.POST or None)

    if form.is_valid():
        try:
            form.save()
            user = authenticate(
                username=request.POST['username'],
                password=request.POST['password1'])
            login(request, user)
            return redirect('sample:dashboard')
        except Exception as e:
            messages.add_message(request, messages.ERROR, str(e))
    return render(request, 'register.html', {"form": form})


@login_required
def dashboard(request):
    """This view renders a simple dashboard page for logged in users.

    Users can see their personal information on this page, as well as store
    additional data to their account (if they so choose).
    """
    form_data = request.POST.copy()
    form_data['user'] = request.user
    a = APPLICATION.accounts.get(request.user.href)
    if request.method == 'GET':
        form_data['birthday'] = a.custom_data.get('birthday')
        form_data['color'] = a.custom_data.get('color')

    form = SampleUserCustomInfoForm(form_data)

    if form.is_valid():
        form.save()

    return render(
        request, 'dashboard.html',
        {
            'birthday': a.custom_data.get('birthday'),
            'color': a.custom_data.get('color'),
            'form': form
        })
