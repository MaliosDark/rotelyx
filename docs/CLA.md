# Contributor License Agreement

> **This is a draft and has not been reviewed by a lawyer.**
>
> It is the document that decides whether Rotelyx can ever be dual licensed,
> sold, or acquired, so it is the one thing in this repository that should not
> go live on an engineer's judgement alone. Have counsel read it first.

## Why this exists

Rotelyx is under the AGPL, and a commercial license can be granted alongside it
(see [LICENSING.md](../LICENSING.md)). Both of those depend on the copyright
being held in one place.

Today it is: every line of `crates/rotelyx-*` has one author. The moment a
second person contributes without an agreement, that stops being true, and from
then on relicensing anything would require tracking down and getting permission
from every contributor who ever touched it. In practice that is not recoverable.

So this is not paperwork for its own sake. It is what keeps the project able to
change its own terms later.

## The agreement

By submitting a contribution to Rotelyx, You agree to the following.

**1. Definitions.** "You" is the copyright owner making the contribution, or the
legal entity authorised by that owner. "Contribution" is any work of authorship
submitted to this project by You, in any form, including code, documentation and
configuration.

**2. Copyright license.** You grant Andryu Schittone a perpetual, worldwide,
non-exclusive, royalty-free, irrevocable copyright license to reproduce,
prepare derivative works of, publicly display, publicly perform, sublicense and
distribute Your Contribution and such derivative works, **under any license
terms, including licenses that are not the AGPL.**

That last clause is the operative one. It is what allows a commercial license to
be granted, and it is what an acquirer would need.

**3. Patent license.** You grant Andryu Schittone a perpetual, worldwide,
non-exclusive, royalty-free, irrevocable patent license to make, have made, use,
offer to sell, sell, import and otherwise transfer Your Contribution, covering
only those patent claims licensable by You that are necessarily infringed by
Your Contribution alone or by its combination with the project.

If You institute patent litigation alleging that the project or a Contribution
infringes a patent, the licenses granted to You under this agreement terminate.

**4. You keep your copyright.** This is a license, not an assignment. You remain
the owner of Your Contribution and are free to use it however You wish
elsewhere.

**5. You have the right to grant this.** You represent that each Contribution is
Your original creation, or that You have the necessary rights to submit it. If
Your employer has rights to work You create, You represent that You have
permission to make the Contribution, or that Your employer has waived those
rights.

**6. Third-party material.** If a Contribution includes work You did not author,
You must identify it and state the license and any restrictions it carries.

**7. No warranty.** Contributions are provided as-is, without warranty of any
kind, express or implied.

**8. Notification.** You agree to notify the project if any of the
representations above becomes inaccurate.

## How to sign

Not yet decided. The two ordinary options:

- A bot on pull requests that records agreement against a GitHub account. Least
  friction, widely used, adequate for most projects.
- A signed document by email. Stronger evidence, more friction.

Whichever is chosen, keep the record. An agreement nobody can produce later is
worth about as much as no agreement.

## What this does not cover

Contributions to `crates/net/`. That code is a derived work of other projects
under their own licenses, and this agreement cannot change their terms. See
[LICENSING.md](../LICENSING.md).
