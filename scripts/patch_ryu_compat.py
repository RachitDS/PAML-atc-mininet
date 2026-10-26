"""Apply the compatibility workaround to the Ryu environment running this script."""
from importlib.util import find_spec
from pathlib import Path

spec=find_spec('ryu.app.wsgi')
if not spec or not spec.origin:
    raise SystemExit('Install Ryu in this environment first.')
path=Path(spec.origin)
original='    from eventlet.wsgi import ALREADY_HANDLED\n    _ALREADY_HANDLED = ALREADY_HANDLED'
replacement='    import eventlet.wsgi\n    _ALREADY_HANDLED = getattr(eventlet.wsgi, "ALREADY_HANDLED", None)'
contents=path.read_text()
if original in contents:
    path.with_suffix('.py.original').write_text(contents)
    path.write_text(contents.replace(original,replacement))
    print('Applied compatibility patch; original file saved alongside it.')
elif replacement in contents:
    print('Compatibility patch already applied.')
else:
    raise SystemExit('Unrecognized Ryu WSGI source; inspect this version before patching.')
