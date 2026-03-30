Changelog

[1.2.0]

- Added IP status dot column with color legend (blue = own NIC, green = same subnet, yellow = other subnet, red = conflict).
- Double-click on green IP opens device web panel in browser.
- Selecting a different adapter clears the results table.
- Added GUI action for Balluff BNI XG: switch EtherCAT → EtherNet/IP via CoE SDO sequence.
- Fixed CoE switch sequence reliability (8-bit writes, target validation, mailbox serialization).

[1.1.0]

- Added Profinet DCP device configuration from GUI (gear action per Profinet row): set IP address and station name.
- Added post-save verification flow (Identify) to confirm whether IP/name persisted on device.
- Fixed DCP Set frame format compatibility (FrameID 0xFEFD) to match standard tooling behavior.
- Fixed DCP raw send source MAC handling on Windows/Npcap (use real adapter MAC instead of 00:00:00:00:00:00).
- Improved DCP response handling for VLAN-tagged PN-DCP frames.
- Improved verification messaging to avoid false "controller overwrite" conclusions when not confirmed.
- Moved Profinet gear column to first table column and adjusted column sizing priorities to fit window width without horizontal scrolling.
- Removed screenshot.png from repository.

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