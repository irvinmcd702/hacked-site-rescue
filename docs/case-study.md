# Case study: the casino nobody at the clinic could see

*Fictional client, real techniques. Everything below is reproduced by
`./demo.sh` on a lab site.*

## The situation

Brightline Dental runs a small WordPress site: four pages, a blog, an old
gallery plugin. Patients started mentioning odd search results, but whenever
the office manager opened the site it looked perfect. Two earlier "cleanups"
had deleted a suspicious file; the problem came back both times.

## Why the owner saw nothing

The first thing worth doing on a site like this is to stop looking at it as
the owner. The same home page, fetched five ways:

| Who is looking | Spam links |
|---|---|
| The owner, logged in | none |
| A visitor from the US | none |
| A visitor from Turkey | 3 casino links |
| A visitor from Germany | none |
| Google's crawler | 3 casino links |

The injector checks three things before printing anything: that nobody is
logged in, and that the visitor is either from one country (read from the
header Cloudflare adds) or a search engine. Search rankings suffer, foreign
visitors see spam, and the person paying for the site never does.

## Why deleting the file didn't help

The injector lives in a must-use plugin named like a cache helper. Deleting it
works — for about an hour. The demo shows it:

    after deleting the file:   visitor from Turkey sees 0 spam links
    an hour later (cron ran):  visitor from Turkey sees 6 spam words again

A snippet appended to the theme registers a scheduled task with an innocent
name. When it runs, it checks whether the injector exists and, if not, writes
it back from a base64 copy stored in the database. That is the second layer.
There were five more.

## What the scan found

25 findings, 15 of them critical, covering seven techniques:

1. The cloaked injector (must-use plugin, country + bot + logged-in checks).
2. Invisible casino links inside two blog posts.
3. An administrator account hidden from the Users screen by a query filter —
   the screen still said "Administrators (2)" while listing one.
4. A "backdoor" in the uploads folder, written to dodge text searches.
5. The reinfection task and the two database settings holding its payloads.
6. One line appended to a WordPress core file to load the backdoor on every
   request — caught by comparing every core file with wordpress.org checksums.
7. In the access log: plugin version probing, user enumeration, password
   guessing, a file sent through the gallery plugin's unauthenticated
   endpoint, the backdoor being called, then a dashboard login and a theme
   edit — all from one address within seventeen minutes.

On a freshly built clean copy of the same site the scanner reports nothing,
which matters as much as what it finds: a scanner that cries wolf on every
plugin is not a tool, it's noise.

## The cleanup

The plan is generated from the evidence and runs in this order:

1. Back up files and database — also preserves the evidence.
2. Delete what the attacker added (backdoor, injector).
3. Restore WordPress core from the same release.
4. Reinstall the theme from wordpress.org.
5. Delete the settings holding the payloads.
6. Unschedule the reinfection task.
7. Delete the hidden administrator; anything it published goes to the owner.
8. Strip the invisible blocks from the two posts, leaving the visible text.
9. Remove the gallery plugin — the way in — until a fixed version exists.
10. Shuffle salts (signs everyone out, attacker included), turn off file
    editing in the dashboard, block PHP in uploads.
11. *Manual, for the owner:* new passwords for WordPress, hosting, database
    and email.

Steps the evidence cannot justify are never automated: an unknown must-use
plugin or scheduled task with no link to malicious code becomes a question,
not a deletion.

## Proof it held

| | Findings | Spam for Turkey / Google |
|---|---|---|
| Before | 25 (15 critical) | yes / yes |
| Right after cleanup | 0 | no / no |
| After every scheduled task ran | 0 | no / no |

The owner gets a one-page report in plain language — what visitors saw, how
the attacker got in, what was found and done, and what is left for them — with
the technical evidence folded under each item:
[sample-owner-report.html](sample-owner-report.html).

## What carries over to a real site

- Look at the site as other people: logged out, from other countries, as
  Googlebot. Cloaking is the norm, not the exception.
- Compare core with official checksums instead of reading code.
- Count administrators in the database, not on the Users screen.
- Read the scheduled tasks and the settings table before declaring victory;
  that is where infections keep their spare copies.
- Find the way in from the access log and close it, or the next cleanup is a
  matter of time.
- Check again after the scheduled tasks have run. "Clean right now" is not the
  same as "clean".
