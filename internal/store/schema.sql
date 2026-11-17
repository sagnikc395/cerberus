-- cerberus owns its own schema in the same database anchora uses, so one
-- Postgres is the whole dependency list.
create schema if not exists cerberus;

create table if not exists cerberus.evaluations (
    event_id    text primary key,
    agent       text        not null,
    session_id  text,
    kind        text        not null,
    received_at timestamptz not null,
    decided_at  timestamptz not null,
    action      text        not null,
    severity    text,
    flagged     boolean     not null,
    masked      integer     not null default 0,
    latency_ms  double precision not null,
    workflow_id text,
    event       jsonb       not null,
    results     jsonb       not null,
    decision    jsonb       not null
);

create index if not exists evaluations_agent_time on cerberus.evaluations (agent, received_at desc);
create index if not exists evaluations_flagged_time on cerberus.evaluations (received_at desc) where flagged;

create table if not exists cerberus.reviews (
    id         text primary key,
    event_id   text        not null,
    agent      text        not null,
    action     text        not null,
    severity   text        not null,
    state      text        not null,
    created_at timestamptz not null,
    decided_at timestamptz,
    reviewer   text,
    notes      text,
    violations jsonb       not null default '[]'::jsonb,
    labels     jsonb       not null default '[]'::jsonb,
    event      jsonb       not null
);

create index if not exists reviews_state on cerberus.reviews (state, created_at);
create index if not exists reviews_agent on cerberus.reviews (agent, created_at desc);

create table if not exists cerberus.sessions (
    agent        text        not null,
    session_id   text        not null,
    started_at   timestamptz not null,
    turn_count   integer     not null default 0,
    tokens_spent bigint      not null default 0,
    cost_usd     double precision not null default 0,
    recent_calls jsonb       not null default '[]'::jsonb,
    updated_at   timestamptz not null default now(),
    primary key (agent, session_id)
);
