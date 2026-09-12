<img src="icon.svg" width="48" height="48" alt="" align="left">

# Moderator

Keeps a group civil, and can put somebody out.

<br clear="all">

## Commands

```
/warn <who>             one strike; three and they are removed
    /kick <who>             remove now
    /strikes                who has how many
    /badwords a,b,c         words that earn a strike on their own
```

## What it sees

**Every message**, because a word list means reading everything. Say so to the group.

## What it needs

Removing somebody is a commit every member sees. To let it confirm additions too, tick it under **Who can let people in**.

## Run it

```sh
rotelyx-cli --identity moderator.key invite --hours 24 --through https://amber.telyx.me
python3 bot-examples/moderator/bot.py --identity moderator.key --relay https://amber.telyx.me
```

The first line prints an invitation code. Hand it to whoever should add the
bot to a conversation, and remember that letting anybody in takes two members
agreeing. `ROTELYX_PASSPHRASE` in the environment lets it start unattended;
the client says why that is worse than the prompt.

The bot is a member of the conversation. The people in it can see it is there
and throw it out. See [`docs/BOTS.md`](../../docs/BOTS.md).
