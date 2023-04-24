--drop table snapshots;
--drop table unknown_product_mappings;
--drop table unknown_products;
--drop table matchers;


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
      weaknesses jsonb,
      configurations jsonb,
      refs jsonb,
      products jsonb,
      vendors jsonb,
      types jsonb
); 

create index idx__cves__id on cves (id);
create index idx__cves__published_at on cves (published_at);
create index idx__cves__last_modified_at on cves (last_modified_at);
create index idx__cves__products on cves using gin((products) jsonb_path_ops);
create index idx__cves__vendors on cves using gin((vendors) jsonb_path_ops);

create table unmatched_dependencies (
      id serial primary key,
      dependency_name varchar(128),
      version varchar(32),
      language varchar(32),
      package_manager varchar(32),
      reported_at timestamptz default now()
);

create index idx__unmatched_dependencies__dependency_name on unmatched_dependencies (dependency_name);
create index idx__unmatched_dependencies__language on unmatched_dependencies (language);
create index idx__unmatched_dependencies__created_at on unmatched_dependencies (reported_at);

create table dependency_product_mappings (
      id serial primary key,
      dependency_name varchar(256),
      product_name varchar(256),
      language varchar(32)
);

create index idx__product_mappings__dependency_name on dependency_product_mappings (dependency_name);
create index idx__product_mappings__product_name on dependency_product_mappings (product_name);
create index idx__product_mappings__language on dependency_product_mappings (language);


create schema analytics;
create table analytics.potential_matches (
      dependency_name varchar(256),
      language varchar(32),
      potential_matches jsonb
);

create index idx__unknown_dependencies__dependency_name on analytics.potential_matches (dependency_name);