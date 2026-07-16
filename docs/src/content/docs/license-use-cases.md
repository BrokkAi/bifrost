---
title: License and Use Cases
description: Practical guidance for using Bifrost under the LGPL in research, products, services, and forks.
---

Bifrost is available under the [GNU Lesser General Public License version 3 or
later](https://github.com/BrokkAi/bifrost/blob/master/LICENSE.md)
(`LGPL-3.0-or-later`). You may use it for research, internal work, and commercial
products. The obligations depend mainly on whether you only run Bifrost, combine
it with another program, modify it, or give someone else a copy.

This page is a practical orientation, not legal advice. The license text controls,
and the boundary between separate and combined programs can depend on the facts.
It covers the Bifrost code and artifacts in this repository, not the separate
Brokk product, Brokk services, trademarks, or third-party components with their
own licenses.

## Start With The Integration Boundary

| How you use Bifrost | May the rest of your product use your own license? | What changes when you distribute it? |
| --- | --- | --- |
| Run an installed Bifrost executable as a separate CLI, MCP, or LSP subprocess | Normally yes. Pipes, sockets, RPC, and command-line interfaces normally connect separate programs, although unusually intimate communication can change the analysis. | If users install Bifrost themselves, you are not distributing their copy. If you bundle a Bifrost executable, you must satisfy the LGPL/GPL obligations for that executable even when your adjacent program remains under its own terms. |
| Call a Bifrost service that you operate | Normally yes. LGPLv3 is not the AGPL, so network use alone does not require you to publish a private Bifrost fork. | If customers only receive responses, rather than a copy of Bifrost, that service use is normally not distribution. A downloadable client, on-premise image, appliance, or customer container can be distribution. |
| Dynamically load Bifrost as a library or native module | Yes. LGPLv3 permits a combined application to use terms of your choice if users retain the license's rights in the Bifrost portion. | Give the required notices and license copies, and allow an interface-compatible modified Bifrost to be substituted. If you ship the Bifrost library too, provide its corresponding source in an allowed way. |
| Statically link Bifrost into an executable | Yes, but compliance is more involved than a replaceable shared library. | Users must be able to modify Bifrost and relink the application. This commonly means providing relinkable application object code or another compliant mechanism, as well as the Bifrost source and notices. |
| Modify or fork Bifrost | You may keep a private or internal fork private. Separate programs around it may keep their own licenses. | Recipients of a distributed fork or binary must receive the LGPL freedoms and access to the complete corresponding source for the Bifrost version they received, including your changes. |
| Copy Bifrost implementation code into your own component | Do not assume the new file is independent merely because it has a different name or lives in another repository. | Code copied from or derived from Bifrost remains covered. Treat that component as a modified Bifrost work and get legal review before distributing it under incompatible terms. |

The subprocess row is not a special exemption. It reflects the ordinary
separate-program analysis in the [GNU license
FAQ](https://www.gnu.org/licenses/gpl-faq.html#MereAggregation): both the
communication mechanism and what the programs exchange matter. Containers and
packaging do not turn a combined program into separate programs, or separate
programs into a combined one.

## Common Use Cases

### Researcher evaluating or extending Bifrost

You may run Bifrost on open or private repositories, benchmark it, inspect its
behavior, and make a private experimental fork. The LGPL does not require you to
publish private changes merely because you ran them, and Bifrost's query or scan
output is not generally covered by the license on Bifrost itself. Copyright and
confidentiality in the analyzed source and generated results remain separate
questions.

You may publish papers, benchmark results, and ordinary RQL or JSON query output.
Citation is good research practice—see [Cite Bifrost](/cite-bifrost/)—but it is
not a substitute for license compliance when you distribute Bifrost code or
binaries. If you give collaborators a modified executable or fork, give those
recipients the corresponding source and LGPL rights as well.

### Startup building an MCP server

A service that launches an unmodified Bifrost artifact as a subprocess and uses
its documented CLI, MCP, or LSP protocol will normally remain a separate program.
Your orchestration, authentication, billing, and domain-specific tools can use
your own license.

The cleanest distribution boundary is to let users install Bifrost separately.
If your installer, desktop application, container, or on-premise package includes
the Bifrost executable, you are also a distributor of Bifrost. Include the
required notices and license texts, make the exact corresponding source
available, and do not place extra restrictions on the recipient's Bifrost copy.
If you add tools or behavior by modifying Bifrost itself, those modifications are
part of the covered Bifrost work when distributed.

### Startup building a code agent

An agent may invoke Bifrost as a separate process without adopting the LGPL for
the agent. This is usually the simplest boundary for a proprietary agent.

Embedding the Rust crate, bundling a native extension into the agent, or otherwise
linking Bifrost produces a combined-work question. LGPLv3 can still permit the
agent under your own terms, but distribution must preserve a user's ability to
replace or modify the Bifrost portion and debug that modification. A blanket
EULA ban on reverse engineering needs an explicit exception for that purpose.
Static linking and single-file application bundlers deserve legal review because
the relinking requirement is easy to miss.

### Company building an RQL and code-scanning dashboard

You may run Bifrost behind a hosted dashboard, store RQL queries, scan repositories,
and show results without licensing the dashboard under the LGPL. Operating a
modified Bifrost only on your own servers does not, by itself, require publication
of the server-side changes.

The answer changes when the product is delivered to the customer. An on-premise
dashboard, VM, container image, desktop application, or appliance that contains
Bifrost conveys a copy and brings the distribution obligations into scope. A
browser frontend delivered to users is also distributed software, but it is not
automatically a derivative of the server-side Bifrost process merely because it
displays Bifrost results.

## When You Give Someone A Copy

If you distribute a Bifrost executable, library, native module, container layer,
or modified fork, plan for all of the following:

1. Identify the exact Bifrost version and clearly mark your modifications.
2. Give prominent notice that Bifrost is used and is covered by
   `LGPL-3.0-or-later`.
3. Accompany the distribution with copies of the GNU GPLv3 and LGPLv3 license
   texts and preserve copyright and license notices.
4. Provide the complete corresponding source for the exact Bifrost binary you
   distribute, including your modifications and the scripts needed to control
   compilation and installation. A link to a different upstream revision is not
   corresponding source.
5. For a linked application, preserve the user's ability to run the application
   with a modified, interface-compatible Bifrost. Follow LGPLv3 section 4's
   relinking or suitable shared-library route.
6. Do not forbid modification of the Bifrost portion or reverse engineering done
   to debug those modifications.
7. Review the licenses and notices for dependencies and other bundled components;
   the Bifrost license does not replace their terms. Bifrost's official artifact
   scopes and generated reports are described in [Third-Party
   Notices](/third-party-notices/).

Source generally needs to be offered to the people who receive the binary; the
LGPL does not require every private fork to be published to the whole world.
Recipients keep the right to redistribute their covered copy and modifications
under the applicable GNU license terms.

## Limits And When To Get Advice

- **Separate process is a factual boundary.** A wrapper executable or container
  does not guarantee separation. Review designs that exchange private internal
  data structures or behave as two inseparable halves of one program.
- **Internal use has edges.** Copies used within one organization are generally
  internal. Transfers to another company or to off-site contractors can be
  distribution.
- **Hosted use is not on-premise distribution.** LGPLv3 has no AGPL network-use
  clause, but sending customers an executable, wheel, container, VM, or appliance
  is different from operating it yourself.
- **The license does not govern customer data.** Repository access, privacy,
  security, model-provider terms, and rights in scanned code and results are
  separate from the Bifrost copyright license. See [Data Boundaries](/data-boundaries/).
- **The license is not a trademark grant.** Do not imply that a fork or product is
  made, sponsored, or supported by Brokk without permission.

Ask qualified counsel to review a release if you embed Bifrost into one binary,
ship a native extension or appliance, restrict reverse engineering in your EULA,
transfer copies across company boundaries, or rely on a subprocess boundary with
an unusually coupled protocol.

For the controlling terms and the GNU project's explanations, read the
[Bifrost license](https://github.com/BrokkAi/bifrost/blob/master/LICENSE.md), the
[official LGPLv3 text](https://www.gnu.org/licenses/lgpl-3.0.html), and the GNU
FAQ entries on [separate programs](https://www.gnu.org/licenses/gpl-faq.html#MereAggregation),
[static and dynamic linking](https://www.gnu.org/licenses/gpl-faq.html#LGPLStaticVsDynamic),
[private and hosted modifications](https://www.gnu.org/licenses/gpl-faq.html#UnreleasedMods),
and [program output](https://www.gnu.org/licenses/gpl-faq.html#WhatCaseIsOutputGPL).
