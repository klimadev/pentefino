"""Platform registry — auto-discovers platforms in this package."""

import importlib, pkgutil, logging

_log = logging.getLogger(__name__)

_registry: dict[str, dict] = {}

def discover():
    """Import all platform modules and register those with PLATFORM dict."""
    _registry.clear()
    for mod_info in pkgutil.iter_modules(__path__, f'{__package__}.'):
        mod = importlib.import_module(mod_info.name)
        plat = getattr(mod, 'PLATFORM', None)
        if plat and 'name' in plat and 'scan' in plat:
            plat['module'] = mod_info.name
            _registry[plat['name']] = plat
            _log.debug("registered platform: %s", plat['name'])
    return _registry

def get(name: str) -> dict | None:
    if not _registry:
        discover()
    return _registry.get(name)

def list_platforms() -> list[dict]:
    if not _registry:
        discover()
    return list(_registry.values())

def resolve(target: str, explicit: str | None = None) -> tuple[dict, str]:
    """Resolve platform from explicit flag or auto-detect target."""
    if not _registry:
        discover()
    if explicit:
        p = get(explicit)
        if p:
            return p, target
        raise ValueError(f"Platform '{explicit}' not found. Available: {[n for n in _registry]}")

    # auto-detect
    # pass original target to detect (may start with @ for instagram etc.)
    t = target.lower()
    for name, plat in _registry.items():
        hint = plat.get('detect')
        if hint and hint(t):
            return plat, t.lstrip('@')

    # fallback: site generico
    fallback = get('site')
    if fallback:
        return fallback, t
    raise ValueError("No platform found and no 'site' fallback registered.")
