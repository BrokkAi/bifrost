---
title: License and Use Cases
description: Practical guidance for using Bifrost under Apache-2.0 in research, products, services, and forks.
---

Bifrost's public source is available under the [Apache License, Version
2.0](https://github.com/BrokkAi/bifrost/blob/master/LICENSE.md)
(`Apache-2.0`). You may use, modify, and distribute it in research, internal
tools, hosted services, and commercial products.

This page is a practical orientation, not legal advice. The license text
controls. It covers the Bifrost code and artifacts in the public repository,
not separate Brokk products, Brokk services, trademarks, or third-party
components with their own licenses.

## Common Integration Choices

| How you use Bifrost | May the rest of your product use your own license? | What to preserve when you distribute Bifrost |
| --- | --- | --- |
| Run the Bifrost CLI, MCP server, or LSP server as a separate process | Yes. | Include the Apache-2.0 license and preserve applicable copyright, attribution, and notice material. |
| Call a Bifrost service that you or another provider operates | Yes. | Network use alone does not distribute Bifrost. Apply the distribution requirements to any Bifrost code or binaries you do provide. |
| Embed Bifrost crates or the Python package in an application | Yes. Apache-2.0 does not require the surrounding application to use Apache-2.0. | Preserve required notices and identify material modifications to Apache-licensed files when you distribute the combined product. |
| Ship Bifrost in a container, installer, VM, appliance, or on-premise product | Yes. | Include the license and required notices for Bifrost and separately satisfy the licenses of bundled third-party components. |
| Modify or fork Bifrost | Yes, including in a proprietary product. | Retain the Apache license and notices in covered source, mark modified files as changed, and do not use Brokk trademarks to imply endorsement. |

Apache-2.0 does not require you to publish your modifications or the source of
your surrounding product. It also does not require dynamic linking, relinkable
object files, or a subprocess boundary. Those were considerations under older
Bifrost releases licensed under the LGPL, not under the public open-core release.

## Example Use Cases

### Research and education

You may inspect Bifrost, benchmark it, run it against public or private
repositories, publish results, and build experimental forks. Cite Bifrost when
appropriate for research provenance; see [Cite Bifrost](/cite-bifrost/).
Citation is good scholarly practice, while license and notice preservation are
the distribution requirements.

### Proprietary agents, IDEs, and developer tools

A proprietary product may invoke Bifrost over CLI, MCP, or LSP, or embed its
public libraries directly. Your application may remain under your own license.
If you distribute Bifrost with it, include Bifrost's Apache license and notices
in the distribution and identify material changes you made to Bifrost files.

### Hosted scanning and on-premise delivery

You may operate Bifrost in a private hosted service without publishing your
service or private modifications. If you later deliver an on-premise image,
container, appliance, or binary bundle, include the applicable license and
notice material in that customer distribution.

### Commercial extensions and semantic packs

You may build proprietary policies, semantic packs, integrations, and workflow
features against the public Bifrost interfaces. The Apache license on Bifrost
does not automatically apply to independently authored extensions. Content
copied from Bifrost or from a third-party pack retains its applicable license.

## Distribution Checklist

When you distribute Bifrost source or binaries:

1. Include a copy of the Apache-2.0 license.
2. Preserve applicable copyright, attribution, and `NOTICE` material.
3. State when you have materially modified Apache-licensed files.
4. Review the notices for dependencies, generated semantic data, and other
   bundled components; Apache-2.0 does not replace their licenses.
5. Do not use Brokk names or trademarks to imply sponsorship or endorsement.

Official Bifrost artifacts may contain components or generated data under
additional licenses. See [Third-Party Notices](/third-party-notices/) for the
artifact boundaries and provenance that apply alongside Apache-2.0.
