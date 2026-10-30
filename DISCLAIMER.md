# Disclaimer

## Provided as is

HypDMZ is provided **as is, without warranty of any kind**, under the
[Apache License 2.0](https://github.com/voodoomods/hypdmz/blob/main/LICENSE). Sections 7 and 8 of that licence
(Disclaimer of Warranty, Limitation of Liability) apply to the launcher, the container images, the documentation and
the website.

## It reduces what an agent can reach

It does not make running untrusted code safe. HypDMZ puts layers between a swarm and the network: an egress floor
keyed on who sends, an allowlisting proxy, vaulted credentials, hourly caps and an audit trail. Each layer can be
misconfigured, and each can have a flaw nobody has found yet. A container shares the host's kernel, so a kernel or
runtime vulnerability can cross it.

## A passing egress check shows that its probes were blocked, not that no bypass exists

`hypdmz egress-check` runs a fixed set of escape attempts from the swarm's own seat. A route it does not try is a
route it does not test.

## Tested where it says, unverified elsewhere

The protections described on [hypdmz.com](https://hypdmz.com) were checked on the configurations named there, and the
page lists its own limits. Other hosts, versions and policies are unverified. HypDMZ is alpha software and has not had
an independent security audit.

## You remain responsible

That covers your keys, your firewall policy and what it allows, what your agents do with the access you give them,
and your compliance with your model provider's terms and your own obligations. Keep a spending cap with your model
provider: the hourly caps count calls and bytes, not dollars.

## No affiliation

HypDMZ runs on Podman and connects to OpenAI-compatible APIs. It is not affiliated with or endorsed by the Podman
project, Red Hat, OpenAI or any model provider.

HypDMZ is made by VoodooMods LLC. Questions and security reports: open an issue at
https://github.com/voodoomods/hypdmz/issues.
