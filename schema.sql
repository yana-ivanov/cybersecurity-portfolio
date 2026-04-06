-- ============================================================
-- ArgusX Database Schema
-- Run this in Supabase SQL Editor
-- ============================================================

-- USERS (populated from GitHub OAuth)
create table if not exists users (
  id            uuid primary key default gen_random_uuid(),
  github_id     text unique not null,
  github_handle text unique not null,
  avatar_url    text,
  verified      boolean default false,
  created_at    timestamp with time zone default now()
);

-- POSTS (Intel and Defense)
create table if not exists posts (
  id            uuid primary key default gen_random_uuid(),
  author_id     uuid references users(id) on delete set null,
  category      text not null check (category in ('intel','defense')),
  type          text not null,
  tlp           text not null check (tlp in ('WHITE','GREEN','AMBER','RED')),
  title         text not null,
  body          text not null,
  plain_english text not null,
  impact        text,
  ioc_code      text,
  source_url    text not null,
  source_label  text,
  mitre_tags    text[] default '{}',
  campaign_tags text[] default '{}',
  source_feed   text,
  auto_ingested boolean default false,
  upvote_count  integer default 0,
  created_at    timestamp with time zone default now()
);

-- POST LINKS (Intel <-> Defense relationships)
create table if not exists post_links (
  id              uuid primary key default gen_random_uuid(),
  from_post_id    uuid references posts(id) on delete cascade,
  to_post_id      uuid references posts(id) on delete cascade,
  link_type       text not null check (link_type in (
    'responds_to',      -- defense responds to intel
    'related',          -- manually linked related threat
    'shared_ioc',       -- auto: same IP/domain/hash
    'shared_ttp',       -- auto: same MITRE technique
    'same_campaign',    -- auto: same campaign tag
    'same_infrastructure' -- auto: same C2 domain
  )),
  auto_detected   boolean default false,
  confidence      integer default 100 check (confidence between 0 and 100),
  created_at      timestamp with time zone default now(),
  unique (from_post_id, to_post_id, link_type)
);

-- UPVOTES (one per user per post)
create table if not exists upvotes (
  user_id  uuid references users(id) on delete cascade,
  post_id  uuid references posts(id) on delete cascade,
  created_at timestamp with time zone default now(),
  primary key (user_id, post_id)
);

-- COMMENTS
create table if not exists comments (
  id         uuid primary key default gen_random_uuid(),
  post_id    uuid references posts(id) on delete cascade,
  author_id  uuid references users(id) on delete set null,
  body       text not null,
  ioc_code   text,
  created_at timestamp with time zone default now()
);

-- FLAGS (moderation)
create table if not exists flags (
  id         uuid primary key default gen_random_uuid(),
  post_id    uuid references posts(id) on delete cascade,
  flagged_by uuid references users(id) on delete set null,
  reason     text,
  resolved   boolean default false,
  created_at timestamp with time zone default now()
);

-- ============================================================
-- INDEXES for performance
-- ============================================================
create index if not exists idx_posts_category    on posts(category);
create index if not exists idx_posts_type        on posts(type);
create index if not exists idx_posts_tlp         on posts(tlp);
create index if not exists idx_posts_created_at  on posts(created_at desc);
create index if not exists idx_post_links_from   on post_links(from_post_id);
create index if not exists idx_post_links_to     on post_links(to_post_id);
create index if not exists idx_comments_post     on comments(post_id);
create index if not exists idx_upvotes_post      on upvotes(post_id);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================
alter table users    enable row level security;
alter table posts    enable row level security;
alter table post_links enable row level security;
alter table upvotes  enable row level security;
alter table comments enable row level security;
alter table flags    enable row level security;

-- Users: anyone can read, only the user can update their own row
create policy "users_read_all"   on users for select using (true);
create policy "users_insert_own" on users for insert with check (auth.uid()::text = github_id);
create policy "users_update_own" on users for update using (auth.uid()::text = github_id);

-- Posts: TLP:WHITE and GREEN are public, AMBER/RED require auth
-- TLP:RED is only visible to the author
create policy "posts_read_public" on posts for select using (
  tlp in ('WHITE','GREEN')
  or (tlp = 'AMBER' and auth.uid() is not null)
  or (tlp = 'RED'   and auth.uid()::text = (select github_id from users where id = author_id))
);
create policy "posts_insert_auth" on posts for insert with check (auth.uid() is not null);
create policy "posts_update_own"  on posts for update using (
  auth.uid()::text = (select github_id from users where id = author_id)
);

-- Post links: readable by anyone who can see both posts
create policy "links_read_all"   on post_links for select using (true);
create policy "links_insert_auth" on post_links for insert with check (auth.uid() is not null);

-- Upvotes: readable by all, insert/delete own only
create policy "upvotes_read_all"   on upvotes for select using (true);
create policy "upvotes_insert_own" on upvotes for insert with check (
  auth.uid()::text = (select github_id from users where id = user_id)
);
create policy "upvotes_delete_own" on upvotes for delete using (
  auth.uid()::text = (select github_id from users where id = user_id)
);

-- Comments: readable by all auth users
create policy "comments_read_all"    on comments for select using (true);
create policy "comments_insert_auth" on comments for insert with check (auth.uid() is not null);
create policy "comments_delete_own"  on comments for delete using (
  auth.uid()::text = (select github_id from users where id = author_id)
);

-- Flags: auth users can flag
create policy "flags_insert_auth" on flags for insert with check (auth.uid() is not null);

-- ============================================================
-- FUNCTION: update upvote count on posts table
-- ============================================================
create or replace function update_upvote_count()
returns trigger language plpgsql as $$
begin
  if TG_OP = 'INSERT' then
    update posts set upvote_count = upvote_count + 1 where id = NEW.post_id;
  elsif TG_OP = 'DELETE' then
    update posts set upvote_count = upvote_count - 1 where id = OLD.post_id;
  end if;
  return null;
end;
$$;

create trigger trg_upvote_count
after insert or delete on upvotes
for each row execute function update_upvote_count();

-- ============================================================
-- FUNCTION: auto-detect relationships between posts
-- Runs when a new post is inserted
-- ============================================================
create or replace function auto_detect_relationships()
returns trigger language plpgsql as $$
declare
  other_post record;
begin
  -- 1. Same campaign tag -> same_campaign link
  for other_post in
    select id from posts
    where id != NEW.id
    and campaign_tags && NEW.campaign_tags
    and array_length(campaign_tags, 1) > 0
  loop
    insert into post_links (from_post_id, to_post_id, link_type, auto_detected, confidence)
    values (NEW.id, other_post.id, 'same_campaign', true, 80)
    on conflict do nothing;
  end loop;

  -- 2. Same MITRE tag -> shared_ttp link
  for other_post in
    select id from posts
    where id != NEW.id
    and mitre_tags && NEW.mitre_tags
    and array_length(mitre_tags, 1) > 0
  loop
    insert into post_links (from_post_id, to_post_id, link_type, auto_detected, confidence)
    values (NEW.id, other_post.id, 'shared_ttp', true, 60)
    on conflict do nothing;
  end loop;

  return NEW;
end;
$$;

create trigger trg_auto_relationships
after insert on posts
for each row execute function auto_detect_relationships();
