# Limitations

HomeAdmin intentionally reports conservative findings and includes known blind spots:

- **Sleeping devices**: offline/low-power devices may appear missing during a scan window.
- **IP churn**: DHCP reassignment can create apparent drift without a true device change.
- **Incomplete network visibility**: segmented VLANs, AP/client isolation, and routing boundaries reduce visibility.
- **Scan sensitivity**: safer/slower scan profiles may miss transient ports or services.
- **Identity ambiguity**: hostname/MAC spoofing, randomization, and missing metadata can reduce identity confidence.
