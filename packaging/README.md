# Server distribution plan

Status: planning only. Source-installer code exists at `../install.sh`, but an end-to-end release installation is unverified; no distribution channel is claimed as supported. No package artifact or systemd unit has been built or tested.

## Shared build and ownership model

`Cargo.toml` supplies the product version. A release build produces the Rust executable plus Angular browser assets under the installer's marked build cache. Each future package recipe consumes that same staged payload rather than maintaining a second build implementation.

`product.toml` records the product's package formats, paths and ownership policy without duplicating the version. It is planning metadata, not a package recipe.

| Channel | Planned payload / ownership | Configuration and data | Service |
|---|---|---|---|
| Source | `bin/baradwatchu-server`, `share/baradwatchu-server/web`; `install.sh` hash manifest owns only these files | Preserve `/etc/baradwatchu/server` and `/var/lib/baradwatchu/server`; source installer creates neither | None yet; manual foreground launch only |
| Arch `pacman` | `/usr/bin/baradwatchu-server`, `/usr/share/baradwatchu-server/web`; PKGBUILD/pacman owns files | `/etc/baradwatchu/server`, `/var/lib/baradwatchu/server`; preserve data on upgrade/removal | Future `baradwatchu-server.service`; no automatic start/restart in this checkpoint |
| Debian/Ubuntu `.deb` | `/usr/bin`, `/usr/share/baradwatchu-server`; dpkg owns files | `/etc` conffiles and `/var/lib`; remove/purge policy must preserve audit data absent explicit operator action | Future systemd unit; maintainer scripts must not start/restart unexpectedly |
| Fedora `.rpm` | `/usr/bin`, `/usr/share/baradwatchu-server`; rpm owns files | `/etc` and `/var/lib`; preserve data on update/erase | Future systemd unit; scriptlets limited to daemon-reload and explicit package policy |

Package-manager installs must refuse source-installer overwrite/uninstall. Package upgrades/removals must be performed by their owning manager. Data and configuration are not package payload files.

## Deferred release work

Add conventional `PKGBUILD`, Debian packaging metadata, RPM spec, service unit and distro integration tests only after service lifecycle and Linux deployment behavior are reviewed. Validate clean install, upgrade, ownership conflicts, uninstall, retained configuration/data, and service state in disposable Arch, Debian/Ubuntu and Fedora environments. Do not label a format supported before those artifacts pass those tests.
