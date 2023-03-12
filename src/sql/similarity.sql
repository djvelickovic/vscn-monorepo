with

expanded_matches as (
	SELECT
		unknown_product_mappings.unknown_product_name,
		arr.potential_match->>'product' as known_product_name,
		cast(arr.potential_match->>'ratio' as decimal) as ratio,
		cast(arr.potential_match->>'partial_ratio' as decimal) as partial_ratio
	FROM unknown_product_mappings,
	jsonb_array_elements(potential_matches) with ordinality arr(potential_match, position)
),

filtered_matches as (
	select
		* 
	from expanded_matches
	where
		ratio >= 90 
		or partial_ratio >= 90
		or (ratio + partial_ratio) / 2 > 70
)

select * from filtered_matches 