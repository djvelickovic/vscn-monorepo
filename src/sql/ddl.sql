create or replace table matchers (
      cve_id varchar(256),
      year numeric(38,0),
      hash varchar(256),
      products jsonb,
      vendors jsonb,
      config jsonb,
      created_at timestamptz default now()
);

create or replace index idx__matchers__cve_id on matchers (cve_id);
create or replace index idx__matchers__year on matchers (year);
create or replace index idx__matchers__hash on matchers (hash);
create or replace index idx__matchers__products on matchers using gin((products) jsonb_path_ops);
create or replace index idx__matchers__vendors on matchers using gin((vendors) jsonb_path_ops);

create or replace table cves (
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

create or replace index idx__cves__cve_id on cves (cve_id);


create or replace table snapshots (
    year numeric(38,0) primary key,
    hash varchar(256),
    updated_at timestamptz
);