-- FGO × Supabase 資料表草稿（尚未在實際專案上執行過；貼進 SQL Editor 前請先看過一遍）
-- 對應目前 server.js 的資料：users.json → profiles，saves/*.json → saves（存檔 blob 改用 jsonb）。
-- 帳號密碼交給 Supabase Auth；GM 帳號請先在 Auth 後台建立，再執行最後一行把它設成 role='gm'。

create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  username    text unique not null check (char_length(username) between 2 and 16),
  role        text not null default 'player' check (role in ('player','gm')),
  rating      int  not null default 1000,
  w int not null default 0, l int not null default 0, d int not null default 0,
  created_at  timestamptz not null default now()
);

create table public.saves (
  user_id     uuid primary key references public.profiles(id) on delete cascade,
  rev         int  not null default 0,
  updated_at  timestamptz not null default now(),
  blob        jsonb not null            -- 就是遊戲的存檔 JSON（owned、wallet、tut …）
);

alter table public.profiles enable row level security;
alter table public.saves    enable row level security;

-- profiles：大家都能讀（排行榜）；不開放 insert/update，玩家無法自己改 role、積分
create policy profiles_read on public.profiles for select using (true);
-- saves：只能讀寫自己的
create policy saves_select on public.saves for select using (auth.uid() = user_id);
create policy saves_insert on public.saves for insert with check (auth.uid() = user_id);
create policy saves_update on public.saves for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 註冊後自動建立 profile（username 取自註冊時的 user_metadata.username，沒有就取 email 前半）
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 貨幣上限 999999：寫入存檔時把 wallet 每個欄位夾在 0～999999（對應 server.js 的 CURRENCY_CAP）
create or replace function public.clamp_wallet() returns trigger language plpgsql as $$
declare k text; v numeric; w jsonb;
begin
  if new.blob ? 'wallet' and jsonb_typeof(new.blob->'wallet') = 'object' then
    w := new.blob->'wallet';
    for k, v in select key, case when jsonb_typeof(value) = 'number' then (value #>> '{}')::numeric else 0 end
                from jsonb_each(w) loop
      w := jsonb_set(w, array[k], to_jsonb(least(999999, greatest(0, floor(v)))));
    end loop;
    new.blob := jsonb_set(new.blob, '{wallet}', w);
  end if;
  return new;
end $$;
create trigger saves_clamp_wallet before insert or update on public.saves
  for each row execute function public.clamp_wallet();

-- GM 帳號（先在 Auth 後台建立帳號，username 填 GM）：
-- update public.profiles set role = 'gm' where username = 'GM';
