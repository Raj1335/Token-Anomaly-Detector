
# Case Study: Salesloft Drift Incident 

### Incident Timeline

- **Mid March 2025** : Actor (*UNC6395*) gained access to Salesloft's Github account [[bleepingcomputer]](https://www.bleepingcomputer.com/news/security/salesloft-march-github-repo-breach-led-to-salesforce-data-theft-attacks/)
- **March-June** : Actor gained envrionment, workflow & private repos information [[thehackernews]](https://thehackernews.com/2025/09/github-account-compromise-led-to.html)
    - Attacker pivots to Drift's AWS environment, obtains OAuth tokens for Drift customer technology integrations (not limited to Salesforce) 
- **8-18 August 2025** : Actor uses stolen Drift OAuth tokens to directly access Salesforce customer instances [[GTIG]](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)
    - Queried standard Salesforce objects (Accounts, Opportunities, Cases, Users) and searched exported data for credential patterns (AKIA, Snowflake, password, secret, key) 
- **20 August 2025** : Salesloft/Salesforce revoke all Drift OAuth tokens; Drift removed from AppExchange [[cybernews]](https://cybernews.com/security/salesforce-instances-targeted-using-stolen-access-tokens/)
- **28 August 2025** : Google discloses extension to Google Workspace — Drift Email OAuth tokens used to access some Workspace mailboxes; Google revokes affected tokens [[salesforce]](https://help.salesforce.com/s/articleView?id=005134951&language=en_US&type=1)
- **5 September 2025**: End of documented intrusion


### Why this evaded standard detection

- Traffic came from a legitimate third-party integration context, not a user login — no new accounts, no failed logins, MFA never in play 
- No single query looked malicious alone — anomaly only visible in aggregate: volume + tenant-breadth + tight time window
- Actor deleted SOQL query job entries post-export, but underlying Salesforce audit logs remained intact 


( **Note** :- How the GitHub account was initially compromised is undisclosed by Salesloft/Mandiant )
