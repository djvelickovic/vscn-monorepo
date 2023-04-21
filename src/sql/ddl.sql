create table cves_raw (
      id varchar(256) primary key,
      source_identifier varchar(256),
      published_at timestamp,
      last_modified_at timestamp,
      vulnerability_status varchar(256),
      descriptions jsonb,
      metrics jsonb,
      weaknesses jsonb,
      configurations jsonb,
      refs jsonb,
      inserted_at timestamptz default now()
);


create index idx__cves_raw__id on cves_raw (id);
create index idx__cves_raw__published_at on cves_raw (published_at);
create index idx__cves_raw__last_modified_at on cves_raw (last_modified_at);


create table cves (
      id varchar(256) primary key,
      source_identifier varchar(256),
      published_at timestamp,
      last_modified_at timestamp,
      vulnerability_status varchar(256),
      
      -- cvss_v30_vector_string varchar(64),
      -- cvss_v30_base_score numeric(10, 2),
      -- cvss_v30_base_severity varchar(16),
      
      -- cvss_v2_vector_string varchar(64),
      -- cvss_v2_vector_string varchar(64),
      -- cvss_v2_vector_string varchar(64),

      description varchar(8192),
      weaknesses jsonb, -- compa separated varchar? ids only
      configurations jsonb, -- ?separate table
      refs jsonb, -- urls only
      
      products jsonb,
      vendors jsonb,
      types jsonb
)

create index idx__cves__id on cves (id);
create index idx__cves__published_at on cves (published_at);
create index idx__cves__last_modified_at on cves (last_modified_at);
create index idx__cves__products on cves using gin((products) jsonb_path_ops);
create index idx__cves__vendors on cves using gin((vendors) jsonb_path_ops);


create table matchers (
      cve_id varchar(256),
      year numeric(38,0),
      hash varchar(256),
      products jsonb,
      vendors jsonb,
      config jsonb,
      created_at timestamptz default now()
);

create index idx__matchers__cve_id on matchers (cve_id);
create index idx__matchers__year on matchers (year);
create index idx__matchers__hash on matchers (hash);
create index idx__matchers__products on matchers using gin((products) jsonb_path_ops);
create index idx__matchers__vendors on matchers using gin((vendors) jsonb_path_ops);

create table cves (
      cve_id varchar(256),
      hash varchar(256),
      year numeric(38,0),
      refs jsonb,
      description varchar(8096),
      severity varchar(16),
      published_at timestamptz,
      last_modified timestamptz,
      created_at timestamptz default now()
);

create index idx__cves__cve_id on cves (cve_id);


create table snapshots (
    year numeric(38,0) primary key,
    hash varchar(256),
    updated_at timestamptz
);

create table unknown_products (
      id serial primary key,
      product_name varchar(256),
      version varchar(256),
      is_relevant boolean default true,
      created_at timestamptz default now()
);

create index idx__unknown_products__product_name on unknown_products (product_name);
create index idx__unknown_products__created_at on unknown_products (created_at);

create table product_mappings (
    product_name varchar(256),
    cve_product_name varchar(256)
);

create index idx__product_mappings__product_name on product_mappings (product_name);
create index idx__product_mappings__cve_product_name on product_mappings (cve_product_name);

create table unknown_product_mappings (
      unknown_product_name varchar(256),
      potential_matches jsonb
);

create index idx__unknown_product_mappings__product_name on unknown_product_mappings (unknown_product_name);
