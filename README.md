stormpath-django-sample
=======================

Example application demonstrating how to use the Django plugin for Stormpath

# Chirper

Chirper is a sample Twitter-like application.

The sample application uses the
[stormpath-django](https://github.com/stormpath/stormpath-django) plugin for
providing Django authentication backend, User models and views integrated
with the Stormpath authentication service.

You should have the `stormpath-django` Python module installed before trying
to start Chirper sample application.

## Setup

To use Chirper, aside from the settings required for stormpath-django (please
see the stormpath-django documentation), you need to change the following in
your settings.py file to the correct values:

    STORMPATH_ADMINISTRATORS = "https://api.stormpath.com/v1/groups/GROUP_ID"
    STORMPATH_PREMIUMS = "https://api.stormpath.com/v1/groups/GROUP_ID"

Chirper uses these two groups to determine the type of the user.
These groups aren't in any way special. They're just ordinary Stormpath
groups used to keep track of application Administrators etc.

You need to make sure database and other standard Django settings are correct.
E.g. Chirper has to be specified in INSTALLED_APPS of the project.

## Running it

Running Chirper is the same as running any other Django application.

```sh
$ python manage.py syncdb
$ python manage.py runserver
```