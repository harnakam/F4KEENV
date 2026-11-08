"""Extract declared transport auth, preserving requirements and unresolved refs."""
import re

from .store import identity

METHODS = {'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'}


def canonical(domain, product):
    # Do not guess registrable domains: public suffix and corporate ownership differ.
    domain = domain.strip().lower().rstrip('.')
    if domain.startswith('www.'):
        domain = domain[4:]
    product = re.sub(r'\s+', ' ', product.strip().casefold()) or 'default'
    return identity('svc', domain, product), domain, product


def resolve_local(spec, value):
    seen = set()
    while isinstance(value, dict) and '$ref' in value:
        ref = value['$ref']
        if not ref.startswith('#/') or ref in seen:
            return None, ref
        seen.add(ref)
        node = spec
        try:
            for part in ref[2:].split('/'):
                node = node[part.replace('~1', '/').replace('~0', '~')]
        except (KeyError, TypeError):
            return None, ref
        value = node
    return value, None


def extract(spec, provider_id, evidence_id):
    if not isinstance(spec, dict):
        raise ValueError('OpenAPI document must be an object')
    version = spec.get('openapi', spec.get('swagger', ''))
    if not (str(version).startswith('3.') or version == '2.0'):
        raise ValueError('Only OpenAPI 3.x and Swagger 2.0 JSON are supported')
    if not isinstance(spec.get('info', {}), dict) or not isinstance(spec.get('components', {}), dict):
        raise ValueError('OpenAPI info and components must be objects')
    definitions = spec.get('components', {}).get('securitySchemes', {}) if str(version).startswith('3.') else spec.get('securityDefinitions', {})
    if not isinstance(definitions, dict) or not isinstance(spec.get('paths', {}), dict):
        raise ValueError('Security schemes and paths must be objects')
    usages = {name: [] for name in definitions}
    issues = []
    root_security = spec.get('security', [])
    if not isinstance(root_security, list) or any(not isinstance(r, dict) for r in root_security):
        raise ValueError('Root security must be an array of requirement objects')
    operations = []
    for path, path_item in spec.get('paths', {}).items():
        item, unresolved = resolve_local(spec, path_item)
        if unresolved:
            issues.append({'path': path, 'unresolved_ref': unresolved})
            continue
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method not in METHODS or not isinstance(operation, dict):
                continue
            requirements = operation.get('security', root_security)
            if not isinstance(requirements, list) or any(not isinstance(r, dict) for r in requirements):
                raise ValueError(f'Invalid security requirements: {method} {path}')
            usage = {'method': method.upper(), 'path': path, 'requirements': requirements,
                     'allows_anonymous': not requirements or {} in requirements}
            operations.append(usage)
            for requirement in requirements:
                for name, scopes in requirement.items():
                    if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes):
                        raise ValueError(f'Invalid scopes: {method} {path}/{name}')
                    if name in usages:
                        usages[name].append({'method': method.upper(), 'path': path})
                    else:
                        issues.append({'path': path, 'undefined_scheme': name})
    credentials = []
    for name, definition in definitions.items():
        scheme, unresolved = resolve_local(spec, definition)
        if unresolved or not isinstance(scheme, dict):
            issues.append({'scheme': name, 'unresolved_ref': unresolved or 'invalid scheme'})
            continue
        auth = scheme.get('type', 'unknown')
        if auth not in {'apiKey', 'http', 'oauth2', 'openIdConnect', 'mutualTLS', 'basic'}:
            issues.append({'scheme': name, 'unsupported_type': auth})
            continue
        location = scheme.get('in') if auth == 'apiKey' else ('tls' if auth == 'mutualTLS' else 'header' if auth in {'http', 'basic'} else 'unknown')
        if auth == 'apiKey' and (location not in {'header', 'query', 'cookie'} or not scheme.get('name')):
            raise ValueError(f'Invalid apiKey scheme: {name}')
        credentials.append({
            'id': identity('cred', provider_id, 'openapi', name, str(version)),
            'provider_id': provider_id, 'credential_type': 'api_key' if auth == 'apiKey' else 'unknown',
            'variant': str(spec.get('info', {}).get('version') or 'unknown'),
            'auth': {'scheme_name': name, 'type': auth, 'http_scheme': scheme.get('scheme'),
                     'location': location, 'parameter_name': scheme.get('name'),
                     'bearer_format_hint': scheme.get('bearerFormat'),
                     'flows': scheme.get('flows', {}), 'swagger_flow': scheme.get('flow'),
                     'authorization_url': scheme.get('authorizationUrl'), 'token_url': scheme.get('tokenUrl'),
                     'scopes': scheme.get('scopes', {}), 'openid_connect_url': scheme.get('openIdConnectUrl')},
            'serialization': {'status': 'unknown', 'template': None},
            'issuance': {'method': 'unknown', 'algorithm': 'unknown'},
            'confidence': 0.7, 'evidence_kind': 'aggregated_openapi', 'evidence_ids': [evidence_id],
            'synthetic_capability': 'unknown', 'detector_refs': [], 'operations': usages[name],
        })
    return credentials, {'openapi_version': str(version), 'root_security': root_security,
                         'operations': operations, 'issues': issues}
