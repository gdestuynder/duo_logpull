duo_logpull
===========

Python lib to pull Duo Security logs into `MozDef <https://github.com/jeffbryner/MozDef/>`_.


Usage
~~~~~

You need a valid admin integration at Duo Security for this to work. Insert the Duo settings in the configuration file.
Test with debug mode first (on by default).
Run every x minutes via a cronjob (for example).

All log info will be in MozDef's details field. Timestamps are automatically converted.

Python dependencies
~~~~~~~~~~~~~~~~~~~

* pytz
* mozdef_lib (https://github.com/gdestuynder/mozdef_lib)
* duo_client (https://github.com/duosecurity/duo_client_python/)
