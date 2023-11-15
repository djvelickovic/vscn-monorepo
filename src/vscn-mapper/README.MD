# Run mapper

```bash
    python vscn_mapper/main.py
```

## Query 

```sql
    -- list raw
    select * from analytics.potential_matches limit 10;

    -- list with transformation
    select
        dependency_name,
        potential_match ->> 'product' product,
        potential_match ->> 'ratio' ratio,
        potential_match ->> 'partial_ratio' partial_ratio

    from analytics.potential_matches,
    lateral jsonb_array_elements(potential_matches) as inline_products(potential_match)
    order by 3 desc, 4 desc;

```