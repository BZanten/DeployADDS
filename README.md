# DeployADDS

A PowerShell scripting framework to deploy Active Directory Services on Windows Server 2012 R2 or higher.

- Configuration fully by using the hierarchy of an XML file
- XML Hierarchy follows Active Directory hierarchy:
  - Forest
  - Forest properties
  - sites
  - subnets
  - DNS
    - Forest domain
    - domain properties
      - optional subdomain(s)
      - domain properties
      - Domain controllers
      - DNS
      - OU structure
        - Users, groups etc
- Install Domain Controller, autodetect first DC in Forest, or domain or additional DC in existing domain
- use XML element tags to convert to Powershell Parameter splatting, reducing the required code, giving ultimate flexibility in XML
