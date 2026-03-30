Changelog

[1.0.1]

- Added device description column in the main table for protocol-specific metadata (for example Profinet type of station).
- Added RFC 5227 style ARP conflict detection based on packet evidence (same IP seen with multiple MAC addresses).
- Added row highlighting rules:
	- red for duplicate/conflicting IPs,
	- light green for devices in the same subnet as the selected adapter,
	- light yellow for devices outside the adapter subnet.
- Added producer fallback from MAC OUI using the bundled IEEE vendor database (Scapy manuf data).
- Extended Profinet DCP parsing to extract additional optional metadata including device family and firmware where available.
- Fixed subnet coloring stability on Windows by hardening ipconfig parsing and adding caching.

[1.0.0]

- Vendor-agnostic branding and documentation
- Unified device list: one row per physical device (except EtherCAT)
- Dynamic protocol switching in-place (ARP/Profinet/EtherNet-IP/Modbus)
- Protocol identity probing for EtherNet/IP and Modbus TCP
- LLDP enrichment for firmware and supplemental metadata
- Improved Profinet DCP parsing and field mapping
- Improved logging controls with module-scoped debug

[0.3.0]

- Added EtherCAT scan support

[0.2.0]

- Improved scan stability and adapter handling
- Improved Profinet DCP discovery in all-adapter mode
- Added GUI quality-of-life improvements

[0.1.0]

- Initial release