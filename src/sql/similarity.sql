with

expanded_matches as (
	select
		unknown_product_mappings.unknown_product_name,
		arr.potential_match->>'product' as known_product_name,
		cast(arr.potential_match->>'ratio' as decimal) as ratio,
		cast(arr.potential_match->>'partial_ratio' as decimal) as partial_ratio
	from unknown_product_mappings,
	jsonb_array_elements(potential_matches) with ordinality arr(potential_match, position)
),

matched_products as (
	select distinct product_name from product_mappings
),

excluded_matches as (
	select
		expanded_matches.*
	from expanded_matches
	left join matched_products on
		matched_products.product_name = expanded_matches.unknown_product_name
	where
		matched_products.product_name is null
),

filtered_matches as (
	select
		* 
	from excluded_matches
	where
		ratio >= 90 
		or partial_ratio >= 90
		or (ratio + partial_ratio) / 2 > 70
)

select * from filtered_matches
where
	unknown_product_name not in (
		'accessors-smart',
		'antlr',
		'apiguardian-api',
		'asm',
		'aspectjweawer',
		'assertj-core',
		'bcprov-jdk15on',
		'byte-buddy-agent',
		'checker-qual',
		'classmate',
		'hamcrest',
		'HikariCP',
		'istack-commons-runtime',
		'jakarta.activation',
		'javassist',
		'javax.activation-api',
		'jaxb-api',
		'jaxb-runtime',
		'jboss-logging',
		'jsonassert',
		'json-path',
		'lombok',
		'nio-multipart-parser',
		'nio-stream-storage',
		'objenesis',
		'opentest4j',
		'reactive-streams',
		'reactor-core',
		'xmlunit-core'
	)
order by 
	unknown_product_name asc, 
	ratio desc, 
	partial_ratio desc;