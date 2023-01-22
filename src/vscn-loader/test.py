import psycopg


with psycopg.connect('postgresql://postgresql:postgresql@localhost:5432/vscn') as conn:
    with conn.cursor() as curr:
        curr.execute('select * from matchers where products ? %(product)s', { 'product': 'p1'})
        res = curr.fetchall()
        for r in res:
            print(f"Row: {r}")