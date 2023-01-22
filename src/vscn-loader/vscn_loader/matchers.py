import json
from vscn_loader.const import BIN_DIR, TMP_DIR
from vscn_loader.runner import run
from vscn_loader.repository import Repository


def load_matchers(year, nvd_path, sha256, postgresql_db: str):
    final_matchers_path = f'{TMP_DIR}/matchers-{year}.json'
    output = run([f'{BIN_DIR}/extract-matchers.sh', nvd_path, final_matchers_path])

    print(f'Extracted matchers. Output: {output}')

    matchers = None

    with open(final_matchers_path) as f:
        matchers = json.load(f)

    transformed_matchers = _transform(matchers, year, sha256)

    print(f'Matchers for insertion: {len(transformed_matchers)}')

    with Repository(postgresql_db) as repo:
        inserted_rows = repo.insert_matchers(transformed_matchers)
        print(f'inserted {len(transformed_matchers)} data: {inserted_rows}')
        deleted_rows = repo.clean_up_matchers(year, sha256)
        print(f'Deleted {deleted_rows} matchers')


def _transform(matchers, year, sha256):
    for matcher in matchers:
        nodes = matcher['config'].get('nodes') if matcher.get('config') else None
        products = set()
        vendors = set()

        for node in nodes:
            _traverse_node(node, products, vendors)

        matcher['year'] = year
        matcher['sha256'] = sha256
        matcher['products'] = list(products)
        matcher['vendors'] = list(vendors)
    return matchers


def _traverse_node(node, products: set, vendors: set):
    if not node:
        return

    cpe_match = node['cpe_match']
    children = node['children']

    if children:
        for child in children:
            _traverse_node(child, products, vendors)

    _traverse_cpe_match(cpe_match, products, vendors)

    return _traverse_node


def _traverse_cpe_match(cpe_match: list, products: set, vendors: set):
    for cpe in cpe_match:
        cpe23uri: str = cpe['cpe23Uri']
        items = cpe23uri.split(':')
        type = items[2]
        vendor = items[3]
        product = items[4]
        exact_version = items[5]
        update = items[6]

        target = items[9]

        cpe['type'] = type
        cpe['vendor'] = vendor
        cpe['product'] = product
        cpe['exactVersion'] = exact_version
        cpe['update'] = update
        cpe['target'] = target

        products.add(product)
        vendors.add(vendor)


def _normalize_cpe_value(value):
    if value == '*' or value == '-':
        return None
    return value
